use std::collections::{HashMap, HashSet};
use std::path::Path;

use cultcache_rs::{CultCache, DatabaseEntry, OwnedRedbMessagePackBackingStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::contract::{
    ContractError, FailureKind, RECEIPT_SCHEMA_ID, RESULT_SCHEMA_ID, Refusal, TransportDisposition,
    TransportInvocation, TransportKey, TransportOutcome, TransportReceipt, TransportResult,
    canonical_invocation_bytes, require_id,
};
use crate::envelope::{
    EnvelopeKind, MAX_IDENTITY_BYTES, ServiceError, TransportEnvelope, decrypt_invocation,
    encrypt_result, validate_envelope,
};

pub struct CallerAdmission {
    caller_runtime_id: String,
    connection_key_epoch: u32,
    security: TransportKey,
    allowed_models: HashSet<String>,
    max_concurrent_requests: usize,
    max_payload_bytes: usize,
    max_output_tokens: u32,
}

impl CallerAdmission {
    pub fn new(
        caller_runtime_id: impl Into<String>,
        connection_key: impl Into<String>,
        connection_key_epoch: u32,
        allowed_models: impl IntoIterator<Item = String>,
        max_concurrent_requests: usize,
        max_payload_bytes: usize,
        max_output_tokens: u32,
    ) -> Result<Self, ServiceError> {
        let caller_runtime_id = caller_runtime_id.into();
        require_id(&caller_runtime_id, "caller_runtime_id")?;
        let allowed_models = allowed_models.into_iter().collect::<HashSet<_>>();
        if connection_key_epoch == 0
            || allowed_models.is_empty()
            || caller_runtime_id.len() > MAX_IDENTITY_BYTES
            || allowed_models.iter().any(|model| {
                require_id(model, "allowed_model").is_err() || model.len() > MAX_IDENTITY_BYTES
            })
            || max_concurrent_requests == 0
            || max_payload_bytes == 0
            || max_output_tokens == 0
        {
            return Err(ServiceError::InvalidAdmission);
        }
        let connection_key = Zeroizing::new(connection_key.into());
        let security = TransportKey::from_connection_secret(connection_key.as_str())?;
        Ok(Self {
            caller_runtime_id,
            connection_key_epoch,
            security,
            allowed_models,
            max_concurrent_requests,
            max_payload_bytes,
            max_output_tokens,
        })
    }

    pub fn caller_runtime_id(&self) -> &str {
        &self.caller_runtime_id
    }

    pub(crate) fn max_concurrent_requests(&self) -> usize {
        self.max_concurrent_requests
    }

    pub(crate) fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestIdentity {
    caller_runtime_id: String,
    request_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum ReplayState {
    Active,
    Completed { response: TransportEnvelope },
}

#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "gamecult.codex.replay_record.v1")]
struct ReplayRecord {
    #[cultcache(key = 0)]
    caller_runtime_id: String,
    #[cultcache(key = 1)]
    request_id: String,
    #[cultcache(key = 2)]
    connection_key_epoch: u32,
    #[cultcache(key = 3)]
    invocation_sha256: [u8; 32],
    #[cultcache(key = 4)]
    expires_at_unix_ms: u64,
    #[cultcache(key = 5)]
    state: ReplayState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaim {
    invocation: TransportInvocation,
    invocation_sha256: [u8; 32],
}

impl ExecutionClaim {
    pub fn invocation(&self) -> &TransportInvocation {
        &self.invocation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportAdmission {
    Execute(Box<ExecutionClaim>),
    Reply(TransportEnvelope),
}

pub struct TransportService {
    callers: HashMap<String, CallerAdmission>,
    live: HashSet<RequestIdentity>,
    replay_store: CultCache,
    max_expiry_skew_ms: u64,
}

impl TransportService {
    pub fn open(
        replay_store_path: &Path,
        admissions: impl IntoIterator<Item = CallerAdmission>,
        max_expiry_skew_ms: u64,
    ) -> Result<Self, ServiceError> {
        if max_expiry_skew_ms == 0 {
            return Err(ServiceError::InvalidAdmission);
        }
        let mut callers = HashMap::new();
        let mut keys = HashSet::new();
        for admission in admissions {
            if !keys.insert(admission.security.0) {
                return Err(ServiceError::SharedCallerKey);
            }
            let caller_runtime_id = admission.caller_runtime_id.clone();
            if callers.insert(caller_runtime_id, admission).is_some() {
                return Err(ServiceError::DuplicateCaller);
            }
        }
        if callers.is_empty() {
            return Err(ServiceError::InvalidAdmission);
        }

        let mut replay_store = CultCache::new();
        replay_store
            .register_entry_type::<ReplayRecord>()
            .map_err(replay_store_error)?;
        replay_store.add_generic_backing_store(
            OwnedRedbMessagePackBackingStore::new(replay_store_path).map_err(replay_store_error)?,
        );
        replay_store
            .pull_all_backing_stores()
            .map_err(replay_store_error)?;

        for (key, record) in replay_store
            .get_all_with_keys::<ReplayRecord>()
            .map_err(replay_store_error)?
        {
            let identity = RequestIdentity {
                caller_runtime_id: record.caller_runtime_id.clone(),
                request_id: record.request_id.clone(),
            };
            if key != replay_key(&identity)
                || record.invocation_sha256 == [0; 32]
                || record.expires_at_unix_ms == 0
            {
                return Err(ServiceError::InvalidReplayRecord);
            }
            let Some(caller) = callers.get(&record.caller_runtime_id) else {
                continue;
            };
            if record.connection_key_epoch != caller.connection_key_epoch {
                return Err(ServiceError::ReplayCallerKeyMismatch);
            }
        }
        Ok(Self {
            callers,
            live: HashSet::new(),
            replay_store,
            max_expiry_skew_ms,
        })
    }

    /// Admits one request. `max_frame_bytes` is the frame every reply must
    /// fit, the same bound `complete` is given: a recorded result that no
    /// longer fits it (the service reopened at a smaller frame) is answered
    /// with the typed `result_size` failure, which is recorded in its place.
    /// A request id longer than `MAX_IDENTITY_BYTES` is refused as malformed,
    /// the refusal echoing the id like every other. The connection is dropped
    /// (`FrameBound`) only when that sealed refusal does not fit `max_frame_bytes`.
    pub fn begin(
        &mut self,
        envelope: &TransportEnvelope,
        now_unix_ms: u64,
        max_frame_bytes: usize,
    ) -> Result<TransportAdmission, ServiceError> {
        validate_envelope(envelope, EnvelopeKind::Invocation)?;
        let caller = self
            .callers
            .get(&envelope.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        let security = caller.security.clone();
        let max_concurrent_requests = caller.max_concurrent_requests;
        let invocation = decrypt_invocation(envelope, &security)?;
        if envelope.request_id.len() > MAX_IDENTITY_BYTES {
            let refusal = encrypt_result(
                &TransportResult::refused(&invocation, Refusal::Malformed),
                &security,
            )?;
            return if fits_frame(&refusal, max_frame_bytes)? {
                Ok(TransportAdmission::Reply(refusal))
            } else {
                Err(ServiceError::FrameBound)
            };
        }
        if envelope.ciphertext.len() > caller.max_payload_bytes {
            return self.reply_refusal(&invocation, Refusal::PayloadBound, &security);
        }
        if let Err(error) = invocation.validate(now_unix_ms, self.max_expiry_skew_ms) {
            return self.reply_refusal(&invocation, contract_refusal(&error), &security);
        }
        if !caller.allowed_models.contains(&invocation.request.model) {
            return self.reply_refusal(&invocation, Refusal::ModelNotAllowed, &security);
        }
        if invocation.request.max_output_tokens > caller.max_output_tokens {
            return self.reply_refusal(&invocation, Refusal::OutputBound, &security);
        }

        let identity = RequestIdentity {
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            request_id: invocation.request_id().to_string(),
        };
        let invocation_sha256: [u8; 32] =
            Sha256::digest(canonical_invocation_bytes(&invocation)?).into();
        if let Some(record) = self
            .replay_store
            .get::<ReplayRecord>(&replay_key(&identity))
            .map_err(replay_store_error)?
        {
            if record.invocation_sha256 != invocation_sha256 {
                return self.reply_refusal(&invocation, Refusal::ReplayConflict, &security);
            }
            return match &record.state {
                ReplayState::Completed { response } => {
                    if fits_frame(response, max_frame_bytes)? {
                        return Ok(TransportAdmission::Reply(response.clone()));
                    }
                    let stand_in = self.seal_stand_in(&invocation, &security, max_frame_bytes)?;
                    self.replay_store
                        .put(
                            replay_key(&identity),
                            &ReplayRecord {
                                state: ReplayState::Completed {
                                    response: stand_in.clone(),
                                },
                                ..record.clone()
                            },
                        )
                        .map_err(replay_store_error)?;
                    Ok(TransportAdmission::Reply(stand_in))
                }
                ReplayState::Active => {
                    let refusal = if self.live.contains(&identity) {
                        Refusal::InFlight
                    } else {
                        Refusal::Indeterminate
                    };
                    self.reply_refusal(&invocation, refusal, &security)
                }
            };
        }
        let active_for_caller = self
            .live
            .iter()
            .filter(|key| key.caller_runtime_id == invocation.caller_runtime_id)
            .count();
        if active_for_caller >= max_concurrent_requests {
            return self.reply_refusal(&invocation, Refusal::Capacity, &security);
        }

        let replay_record = ReplayRecord {
            caller_runtime_id: identity.caller_runtime_id.clone(),
            request_id: identity.request_id.clone(),
            connection_key_epoch: caller.connection_key_epoch,
            invocation_sha256,
            expires_at_unix_ms: invocation.expires_at_unix_ms,
            state: ReplayState::Active,
        };
        self.replay_store
            .put(replay_key(&identity), &replay_record)
            .map_err(replay_store_error)?;
        self.live.insert(identity);
        Ok(TransportAdmission::Execute(Box::new(ExecutionClaim {
            invocation,
            invocation_sha256,
        })))
    }

    /// Records a result and seals it. `max_frame_bytes` bounds the serialized
    /// envelope, which is what a frame carries: a result whose sealed envelope
    /// does not fit is recorded as the typed `result_size` failure instead, so
    /// no completed record is ever undeliverable and a retry replays bytes
    /// that fit.
    pub fn complete(
        &mut self,
        claim: ExecutionClaim,
        result: TransportResult,
        max_frame_bytes: usize,
    ) -> Result<TransportEnvelope, ServiceError> {
        if !matches!(
            &result.disposition,
            TransportDisposition::Transported { .. }
        ) {
            return Err(ServiceError::InvalidCompletion);
        }
        result.validate_against(&claim.invocation)?;
        let identity = RequestIdentity {
            caller_runtime_id: claim.invocation.caller_runtime_id.clone(),
            request_id: claim.invocation.request_id().to_string(),
        };
        if !self.live.contains(&identity) {
            return Err(ServiceError::NoActiveRequest);
        }
        let active = self
            .replay_store
            .get::<ReplayRecord>(&replay_key(&identity))
            .map_err(replay_store_error)?
            .ok_or(ServiceError::NoActiveRequest)?;
        if active.invocation_sha256 != claim.invocation_sha256
            || !matches!(active.state, ReplayState::Active)
        {
            return Err(ServiceError::ActiveRequestMismatch);
        }
        let caller = self
            .callers
            .get(&identity.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        let security = caller.security.clone();
        let mut response = encrypt_result(&result, &security)?;
        if !fits_frame(&response, max_frame_bytes)? {
            response = match self.seal_stand_in(&claim.invocation, &security, max_frame_bytes) {
                Ok(stand_in) => stand_in,
                Err(error) => {
                    // Nothing is recorded, but the caller's slot is not held
                    // by a request that can no longer finish.
                    self.live.remove(&identity);
                    return Err(error);
                }
            };
        }
        let caller = self
            .callers
            .get(&identity.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        let replay_record = ReplayRecord {
            caller_runtime_id: identity.caller_runtime_id.clone(),
            request_id: identity.request_id.clone(),
            connection_key_epoch: caller.connection_key_epoch,
            invocation_sha256: claim.invocation_sha256,
            expires_at_unix_ms: claim.invocation.expires_at_unix_ms,
            state: ReplayState::Completed {
                response: response.clone(),
            },
        };
        self.replay_store
            .put(replay_key(&identity), &replay_record)
            .map_err(replay_store_error)?;
        self.live.remove(&identity);
        Ok(response)
    }

    /// The `result_size` failure sealed for `invocation`, if it fits the frame.
    fn seal_stand_in(
        &self,
        invocation: &TransportInvocation,
        security: &TransportKey,
        max_frame_bytes: usize,
    ) -> Result<TransportEnvelope, ServiceError> {
        let stand_in = encrypt_result(
            &result_size_failure(
                &invocation.caller_runtime_id,
                invocation.request_id(),
                &invocation.request.model,
                invocation.native_request_sha256,
                invocation.provider_request_sha256,
            ),
            security,
        )?;
        if fits_frame(&stand_in, max_frame_bytes)? {
            Ok(stand_in)
        } else {
            Err(ServiceError::FrameBound)
        }
    }

    fn reply_refusal(
        &self,
        invocation: &TransportInvocation,
        refusal: Refusal,
        security: &TransportKey,
    ) -> Result<TransportAdmission, ServiceError> {
        Ok(TransportAdmission::Reply(encrypt_result(
            &TransportResult::refused(invocation, refusal),
            security,
        )?))
    }
}

fn fits_frame(envelope: &TransportEnvelope, max_frame_bytes: usize) -> Result<bool, ServiceError> {
    rmp_serde::to_vec(envelope)
        .map(|bytes| bytes.len() <= max_frame_bytes)
        .map_err(|_| ServiceError::Encoding)
}

/// The provider named on the stand-in failure, fixed so its size is bounded.
const STAND_IN_PROVIDER: &str = "model-connector";

/// The failed result that stands in for one whose sealed frame cannot be
/// carried: the same shape a provider failure takes, with nothing a provider
/// controls but the identities the invocation already bound.
pub(crate) fn result_size_failure(
    caller_runtime_id: &str,
    request_id: &str,
    model: &str,
    native_request_sha256: [u8; 32],
    provider_request_sha256: [u8; 32],
) -> TransportResult {
    TransportResult {
        schema_id: RESULT_SCHEMA_ID.to_string(),
        request_id: request_id.to_string(),
        caller_runtime_id: caller_runtime_id.to_string(),
        disposition: TransportDisposition::Transported {
            events: Vec::new(),
            receipt: Box::new(TransportReceipt {
                schema_id: RECEIPT_SCHEMA_ID.to_string(),
                request_id: request_id.to_string(),
                caller_runtime_id: caller_runtime_id.to_string(),
                native_request_sha256,
                provider_request_sha256,
                model: model.to_string(),
                provider: STAND_IN_PROVIDER.to_string(),
                outcome: TransportOutcome::Failed {
                    kind: FailureKind::ResultSize,
                    message: "provider result exceeded its byte bound".to_string(),
                },
            }),
        },
    }
}

fn replay_key(identity: &RequestIdentity) -> String {
    let mut hasher = Sha256::new();
    hasher.update((identity.caller_runtime_id.len() as u64).to_be_bytes());
    hasher.update(identity.caller_runtime_id.as_bytes());
    hasher.update((identity.request_id.len() as u64).to_be_bytes());
    hasher.update(identity.request_id.as_bytes());
    hex(hasher.finalize().into())
}

fn hex(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

fn replay_store_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::ReplayStore(error.to_string())
}

fn contract_refusal(error: &ContractError) -> Refusal {
    match error {
        ContractError::Expiry => Refusal::Expired,
        ContractError::Identity => Refusal::IdentitySubstitution,
        ContractError::ProviderDigest => Refusal::ProviderDigestSubstitution,
        _ => Refusal::Malformed,
    }
}

#[cfg(all(test, feature = "daemon"))]
mod tests {
    use super::*;
    use crate::fixtures::*;
    use crate::{contract::*, envelope::*};

    const FRAME: usize = 1 << 20;

    #[test]
    fn service_refuses_shared_keys_and_isolates_caller_request_identities() {
        let store = TestStore::new();
        assert!(matches!(
            TransportService::open(
                &store.path,
                [
                    caller("epiphany-yggdrasil", "shared-key", 1),
                    caller("ghostlight-yggdrasil", "shared-key", 1),
                ],
                5_000,
            ),
            Err(ServiceError::SharedCallerKey)
        ));

        let epiphany = invocation_for("epiphany-yggdrasil", "shared-request-id");
        let ghostlight = invocation_for("ghostlight-yggdrasil", "shared-request-id");
        let mut service = open_service(&store, 1);
        assert!(matches!(
            service
                .begin(
                    &encrypt_invocation(&epiphany, &security("epiphany-distinct-test-key"))
                        .unwrap(),
                    1_000,
                    FRAME,
                )
                .unwrap(),
            TransportAdmission::Execute(_)
        ));
        assert!(matches!(
            service
                .begin(
                    &encrypt_invocation(&ghostlight, &security("ghostlight-distinct-test-key"))
                        .unwrap(),
                    1_000,
                    FRAME,
                )
                .unwrap(),
            TransportAdmission::Execute(_)
        ));
    }

    #[test]
    fn service_returns_exact_completed_replay_and_refuses_conflicting_replay() {
        let store = TestStore::new();
        let invocation = invocation();
        let security = security("epiphany-distinct-test-key");
        let mut service = open_service(&store, 1);
        let claim = match service
            .begin(
                &encrypt_invocation(&invocation, &security).unwrap(),
                1_000,
                FRAME,
            )
            .unwrap()
        {
            TransportAdmission::Execute(claim) => claim,
            TransportAdmission::Reply(_) => panic!("first invocation must execute"),
        };
        let response = service
            .complete(
                *claim,
                TransportResult::transported(
                    &invocation,
                    vec![TransportEvent {
                        sequence: 0,
                        payload: TransportEventPayload::ToolCall {
                            call_id: "call-1".to_string(),
                            name: "read_source".to_string(),
                            arguments: "{}".to_string(),
                        },
                    }],
                    receipt(&invocation),
                ),
                1 << 20,
            )
            .unwrap();
        drop(service);
        let mut service = open_service(&store, 1);

        let replay = match service
            .begin(
                &encrypt_invocation(&invocation, &security).unwrap(),
                1_000,
                FRAME,
            )
            .unwrap()
        {
            TransportAdmission::Reply(response) => response,
            TransportAdmission::Execute(_) => panic!("completed invocation re-executed"),
        };
        assert_eq!(replay, response);
        let decoded = decrypt_result(&replay, &security, &invocation).unwrap();
        assert!(matches!(
            decoded.disposition,
            TransportDisposition::Transported { .. }
        ));

        let mut changed_request = request();
        changed_request.instructions.push_str(" Different cargo.");
        let conflicting =
            TransportInvocation::new("epiphany-yggdrasil", 2_000, [7; 32], changed_request)
                .unwrap();
        let refusal = match service
            .begin(
                &encrypt_invocation(&conflicting, &security).unwrap(),
                1_000,
                FRAME,
            )
            .unwrap()
        {
            TransportAdmission::Reply(response) => response,
            TransportAdmission::Execute(_) => panic!("conflicting replay executed"),
        };
        assert!(matches!(
            decrypt_result(&refusal, &security, &conflicting)
                .unwrap()
                .disposition,
            TransportDisposition::Refused(Refusal::ReplayConflict)
        ));
    }

    #[test]
    fn service_refuses_duplicate_inflight_and_per_caller_capacity() {
        let store = TestStore::new();
        let first = invocation_for("epiphany-yggdrasil", "request-1");
        let second = invocation_for("epiphany-yggdrasil", "request-2");
        let security = security("epiphany-distinct-test-key");
        let mut service = open_service(&store, 1);
        let first_envelope = encrypt_invocation(&first, &security).unwrap();
        assert!(matches!(
            service.begin(&first_envelope, 1_000, FRAME).unwrap(),
            TransportAdmission::Execute(_)
        ));

        for (invocation, expected) in [(&first, Refusal::InFlight), (&second, Refusal::Capacity)] {
            let response = match service
                .begin(
                    &encrypt_invocation(invocation, &security).unwrap(),
                    1_000,
                    FRAME,
                )
                .unwrap()
            {
                TransportAdmission::Reply(response) => response,
                TransportAdmission::Execute(_) => panic!("refused invocation executed"),
            };
            assert_eq!(
                decrypt_result(&response, &security, invocation)
                    .unwrap()
                    .disposition,
                TransportDisposition::Refused(expected)
            );
        }
    }

    #[test]
    fn restart_refuses_ambiguous_claim_without_consuming_live_capacity() {
        let store = TestStore::new();
        let first = invocation_for("epiphany-yggdrasil", "request-1");
        let second = invocation_for("epiphany-yggdrasil", "request-2");
        let security = security("epiphany-distinct-test-key");
        let mut service = open_service(&store, 1);
        assert!(matches!(
            service
                .begin(
                    &encrypt_invocation(&first, &security).unwrap(),
                    1_000,
                    FRAME
                )
                .unwrap(),
            TransportAdmission::Execute(_)
        ));
        drop(service);

        let mut restarted = open_service(&store, 1);
        let ambiguous = match restarted
            .begin(
                &encrypt_invocation(&first, &security).unwrap(),
                1_000,
                FRAME,
            )
            .unwrap()
        {
            TransportAdmission::Reply(response) => response,
            TransportAdmission::Execute(_) => panic!("ambiguous claim re-executed"),
        };
        assert_eq!(
            decrypt_result(&ambiguous, &security, &first)
                .unwrap()
                .disposition,
            TransportDisposition::Refused(Refusal::Indeterminate)
        );
        assert!(matches!(
            restarted
                .begin(
                    &encrypt_invocation(&second, &security).unwrap(),
                    1_000,
                    FRAME
                )
                .unwrap(),
            TransportAdmission::Execute(_)
        ));
        drop(restarted);
        assert!(matches!(
            TransportService::open(
                &store.path,
                [CallerAdmission::new(
                    "epiphany-yggdrasil",
                    "rotated-connection-key",
                    2,
                    ["gpt-5.4".to_string()],
                    1,
                    64 * 1024,
                    32_768,
                )
                .unwrap()],
                5_000,
            ),
            Err(ServiceError::ReplayCallerKeyMismatch)
        ));
    }

    const CALLER: &str = "epiphany-yggdrasil";
    const KEY: &str = "epiphany-distinct-test-key";

    fn run(
        service: &mut TransportService,
        request_id: &str,
        edit: impl FnOnce(&mut ProviderRequest),
    ) -> (TransportAdmission, TransportInvocation) {
        let mut request = invocation_for(CALLER, request_id).request;
        edit(&mut request);
        let invocation = TransportInvocation::new(CALLER, 2_000, [7; 32], request).unwrap();
        let envelope = encrypt_invocation(&invocation, &security(KEY)).unwrap();
        (service.begin(&envelope, 1_000, FRAME).unwrap(), invocation)
    }

    fn refusal_of(admission: TransportAdmission, invocation: &TransportInvocation) -> Refusal {
        let TransportAdmission::Reply(envelope) = admission else {
            panic!("expected a refusal reply");
        };
        match decrypt_result(&envelope, &security(KEY), invocation)
            .unwrap()
            .disposition
        {
            TransportDisposition::Refused(refusal) => refusal,
            TransportDisposition::Transported { .. } => panic!("expected a refusal"),
        }
    }

    fn raw_envelope(invocation: &TransportInvocation) -> TransportEnvelope {
        encrypt_message(
            &invocation.caller_runtime_id,
            invocation.request_id(),
            EnvelopeKind::Invocation,
            &rmp_serde::to_vec(invocation).unwrap(),
            &security(KEY),
        )
        .unwrap()
    }

    #[test]
    fn caller_admission_reports_its_runtime_id() {
        assert_eq!(
            caller("ghostlight-yggdrasil", "some-key", 1).caller_runtime_id(),
            "ghostlight-yggdrasil"
        );
    }

    #[test]
    fn an_unlisted_model_is_refused_model_not_allowed() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let (admission, invocation) = run(&mut service, "unlisted-model", |request| {
            request.model = "other-model".to_string();
        });
        assert_eq!(refusal_of(admission, &invocation), Refusal::ModelNotAllowed);
        let (admission, _) = run(&mut service, "listed-model", |_| {});
        assert!(matches!(admission, TransportAdmission::Execute(_)));
    }

    #[test]
    fn output_tokens_over_the_caller_cap_are_refused_output_bound_inclusively() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let (admission, invocation) = run(&mut service, "over-cap", |request| {
            request.max_output_tokens = 32_769;
        });
        assert_eq!(refusal_of(admission, &invocation), Refusal::OutputBound);
        for (id, tokens) in [("at-cap", 32_768), ("under-cap", 100)] {
            let (admission, _) = run(&mut service, id, |request| {
                request.max_output_tokens = tokens;
            });
            assert!(matches!(admission, TransportAdmission::Execute(_)), "{id}");
        }
    }

    #[test]
    fn payload_bound_is_inclusive_of_the_encrypted_size() {
        let invocation = invocation_for(CALLER, "sized");
        let envelope = encrypt_invocation(&invocation, &security(KEY)).unwrap();
        let size = envelope.ciphertext.len();
        let admit = |max_payload_bytes: usize| {
            let store = TestStore::new();
            let admission = CallerAdmission::new(
                CALLER,
                KEY,
                1,
                ["gpt-5.4".to_string()],
                4,
                max_payload_bytes,
                32_768,
            )
            .unwrap();
            TransportService::open(&store.path, [admission], 5_000)
                .unwrap()
                .begin(&envelope, 1_000, FRAME)
        };
        assert!(matches!(admit(size), Ok(TransportAdmission::Execute(_))));
        let refused = admit(size - 1).unwrap();
        assert_eq!(refusal_of(refused, &invocation), Refusal::PayloadBound);
    }

    #[test]
    fn contract_failures_are_refused_with_the_matching_refusal() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);

        let mut expired = invocation_for(CALLER, "expired");
        expired.expires_at_unix_ms = 10;
        let reply = service
            .begin(&raw_envelope(&expired), 1_000, FRAME)
            .unwrap();
        assert_eq!(refusal_of(reply, &expired), Refusal::Expired);

        let mut substituted = invocation_for(CALLER, "substituted");
        substituted.provider_request_sha256 = [9; 32];
        let reply = service
            .begin(&raw_envelope(&substituted), 1_000, FRAME)
            .unwrap();
        assert_eq!(
            refusal_of(reply, &substituted),
            Refusal::ProviderDigestSubstitution
        );

        let mut malformed = invocation_for(CALLER, "malformed");
        malformed.native_request_sha256 = [0; 32];
        let reply = service
            .begin(&raw_envelope(&malformed), 1_000, FRAME)
            .unwrap();
        assert_eq!(refusal_of(reply, &malformed), Refusal::Malformed);
    }

    fn seed(path: &Path, key: &str, edit: impl FnOnce(&mut ReplayRecord)) {
        let mut record = ReplayRecord {
            caller_runtime_id: CALLER.to_string(),
            request_id: "seeded".to_string(),
            connection_key_epoch: 1,
            invocation_sha256: [1; 32],
            expires_at_unix_ms: 5_000,
            state: ReplayState::Active,
        };
        edit(&mut record);
        let mut cache = CultCache::new();
        cache.register_entry_type::<ReplayRecord>().unwrap();
        cache.add_generic_backing_store(OwnedRedbMessagePackBackingStore::new(path).unwrap());
        cache.pull_all_backing_stores().unwrap();
        cache.put(key.to_string(), &record).unwrap();
    }

    fn seeded_key() -> String {
        replay_key(&RequestIdentity {
            caller_runtime_id: CALLER.to_string(),
            request_id: "seeded".to_string(),
        })
    }

    #[test]
    fn restart_refuses_each_malformed_replay_record() {
        let control = TestStore::new();
        seed(&control.path, &seeded_key(), |_| {});
        assert!(TransportService::open(&control.path, [caller(CALLER, KEY, 1)], 5_000).is_ok());

        type Edit = fn(&mut ReplayRecord);
        let cases: [(&str, Edit); 3] = [
            ("wrong-key", |_| {}),
            ("zero-digest", |record| record.invocation_sha256 = [0; 32]),
            ("zero-expiry", |record| record.expires_at_unix_ms = 0),
        ];
        for (name, edit) in cases {
            let store = TestStore::new();
            let key = if name == "wrong-key" {
                "not-the-replay-key".to_string()
            } else {
                seeded_key()
            };
            seed(&store.path, &key, edit);
            assert!(
                matches!(
                    TransportService::open(&store.path, [caller(CALLER, KEY, 1)], 5_000),
                    Err(ServiceError::InvalidReplayRecord)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn completion_refuses_a_claim_that_is_not_the_active_request() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let (admission, invocation) = run(&mut service, "request-1", |_| {});
        let TransportAdmission::Execute(claim) = admission else {
            panic!("first invocation must execute");
        };
        let result = TransportResult::transported(
            claim.invocation(),
            vec![TransportEvent {
                sequence: 0,
                payload: TransportEventPayload::TextDelta {
                    text: "done".to_string(),
                },
            }],
            receipt(claim.invocation()),
        );

        let mut forged = (*claim).clone();
        forged.invocation_sha256 = [1; 32];
        assert_eq!(
            service
                .complete(forged, result.clone(), 1 << 20)
                .unwrap_err(),
            ServiceError::ActiveRequestMismatch
        );

        let key = replay_key(&RequestIdentity {
            caller_runtime_id: CALLER.to_string(),
            request_id: invocation.request_id().to_string(),
        });
        let mut record = service
            .replay_store
            .get::<ReplayRecord>(&key)
            .unwrap()
            .unwrap();
        record.state = ReplayState::Completed {
            response: encrypt_result(&result, &security(KEY)).unwrap(),
        };
        service.replay_store.put(key, &record).unwrap();
        assert_eq!(
            service.complete(*claim, result, 1 << 20).unwrap_err(),
            ServiceError::ActiveRequestMismatch
        );
    }

    #[test]
    fn identities_are_bounded_at_admission_and_on_the_request() {
        let admit = |caller_id: String, model: String| {
            CallerAdmission::new(caller_id, KEY, 1, [model], 4, 64 * 1024, 32_768)
        };
        let at = "i".repeat(MAX_IDENTITY_BYTES);
        let over = "i".repeat(MAX_IDENTITY_BYTES + 1);
        assert!(admit(at.clone(), at.clone()).is_ok());
        assert!(matches!(
            admit(over.clone(), at.clone()),
            Err(ServiceError::InvalidAdmission)
        ));
        assert!(matches!(
            admit(at.clone(), over.clone()),
            Err(ServiceError::InvalidAdmission)
        ));

        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let ok = invocation_for(CALLER, &at);
        assert!(matches!(
            service.begin(&raw_envelope(&ok), 1_000, FRAME).unwrap(),
            TransportAdmission::Execute(_)
        ));
    }

    #[test]
    fn a_request_id_past_the_bound_is_refused_malformed_echoing_the_id() {
        for length in [
            MAX_IDENTITY_BYTES + 1,
            MAX_IDENTITY_BYTES + 2,
            5_000,
            100_000,
        ] {
            let store = TestStore::new();
            let mut service = open_service(&store, 1);
            let id = "i".repeat(length);
            let long = invocation_for(CALLER, &id);
            let TransportAdmission::Reply(reply) =
                service.begin(&raw_envelope(&long), 1_000, FRAME).unwrap()
            else {
                panic!("an over-long id must be refused, not executed ({length})");
            };
            assert_eq!(reply.request_id, id, "{length}");
            let result: TransportResult =
                rmp_serde::from_slice(&decrypt_message(&reply, &security(KEY)).unwrap()).unwrap();
            assert_eq!(
                result.disposition,
                TransportDisposition::Refused(Refusal::Malformed)
            );
            assert_eq!(result.request_id, id);
            result.validate_against(&long).unwrap();
            // Nothing was recorded or held: the caller's one slot is free.
            let (_claim, _) = claim_for(&mut service, "after-the-long-one");
        }
    }

    #[test]
    fn an_over_long_id_drops_the_connection_only_when_its_refusal_cannot_fit() {
        let id = "i".repeat(5_000);
        let long = invocation_for(CALLER, &id);
        let sealed = encrypt_result(
            &TransportResult::refused(&long, Refusal::Malformed),
            &security(KEY),
        )
        .unwrap();
        // The sealed size varies with the random nonce and ciphertext bytes
        // (a byte of 128 or more takes two), so bracket it: the ciphertext
        // plus the id is a floor, twice the ciphertext plus the id and the
        // envelope's other fields is a ceiling.
        let floor = sealed.ciphertext.len() + id.len();
        let ceiling = 2 * sealed.ciphertext.len() + id.len() + 512;
        let store = TestStore::new();
        let mut service = open_service(&store, 1);
        assert!(matches!(
            service.begin(&raw_envelope(&long), 1_000, ceiling).unwrap(),
            TransportAdmission::Reply(_)
        ));
        assert_eq!(
            service
                .begin(&raw_envelope(&long), 1_000, floor - 1)
                .unwrap_err(),
            ServiceError::FrameBound
        );
        let (_claim, _) = claim_for(&mut service, "after-the-drop");
    }

    #[test]
    fn a_frame_check_is_inclusive_of_the_serialized_envelope() {
        let envelope =
            encrypt_invocation(&invocation_for(CALLER, "sized"), &security(KEY)).unwrap();
        let size = rmp_serde::to_vec(&envelope).unwrap().len();
        assert_eq!(fits_frame(&envelope, size), Ok(true));
        assert_eq!(fits_frame(&envelope, size - 1), Ok(false));
    }

    fn claim_for(
        service: &mut TransportService,
        request_id: &str,
    ) -> (Box<ExecutionClaim>, TransportInvocation) {
        let invocation = invocation_for(CALLER, request_id);
        match service
            .begin(&raw_envelope(&invocation), 1_000, FRAME)
            .unwrap()
        {
            TransportAdmission::Execute(claim) => (claim, invocation),
            TransportAdmission::Reply(_) => panic!("expected an execution claim"),
        }
    }

    fn text_result(
        invocation: &TransportInvocation,
        text: &str,
        transport: &str,
    ) -> TransportResult {
        let mut receipt = receipt(invocation);
        receipt.provider = transport.to_string();
        TransportResult::transported(
            invocation,
            vec![TransportEvent {
                sequence: 0,
                payload: TransportEventPayload::TextDelta {
                    text: text.to_string(),
                },
            }],
            receipt,
        )
    }

    #[test]
    fn a_result_whose_sealed_envelope_exceeds_the_frame_is_recorded_as_the_stand_in_failure() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let (claim, invocation) = claim_for(&mut service, "stand-in");
        let big = text_result(&invocation, &"y".repeat(4000), &"t".repeat(5000));
        let response = service.complete(*claim, big, 2000).unwrap();
        assert!(rmp_serde::to_vec(&response).unwrap().len() <= 2000);
        let stand_in = decrypt_result(&response, &security(KEY), &invocation).unwrap();
        assert_eq!(
            stand_in,
            result_size_failure(
                CALLER,
                "stand-in",
                &invocation.request.model,
                invocation.native_request_sha256,
                invocation.provider_request_sha256,
            )
        );
        let TransportDisposition::Transported { receipt, .. } = &stand_in.disposition else {
            panic!("expected a transported failure");
        };
        assert_eq!(receipt.transport, "model-connector");

        // The recorded replay is the stand-in's exact bytes.
        let TransportAdmission::Reply(replay) = service
            .begin(&raw_envelope(&invocation), 1_000, FRAME)
            .unwrap()
        else {
            panic!("expected a replay");
        };
        assert_eq!(replay, response);
    }

    #[test]
    fn a_result_whose_sealed_envelope_fits_is_recorded_as_the_backend_made_it() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let (claim, invocation) = claim_for(&mut service, "fits");
        let small = text_result(&invocation, "done", "fixture-sse");
        let response = service.complete(*claim, small.clone(), 1 << 20).unwrap();
        assert_eq!(
            decrypt_result(&response, &security(KEY), &invocation).unwrap(),
            small
        );
    }

    #[test]
    fn a_frame_bound_failure_releases_the_callers_slot() {
        let store = TestStore::new();
        let mut service = open_service(&store, 1);
        let (claim, invocation) = claim_for(&mut service, "wedge");
        let big = text_result(&invocation, "y", "fixture-sse");
        assert_eq!(
            service.complete(*claim, big, 10).unwrap_err(),
            ServiceError::FrameBound
        );
        // The caller's only slot is free again, and the dead request is no
        // longer in flight.
        let (_next, _) = claim_for(&mut service, "after-wedge");
        let TransportAdmission::Reply(reply) = service
            .begin(&raw_envelope(&invocation), 1_000, FRAME)
            .unwrap()
        else {
            panic!("expected a refusal");
        };
        assert_eq!(
            decrypt_result(&reply, &security(KEY), &invocation)
                .unwrap()
                .disposition,
            TransportDisposition::Refused(Refusal::Indeterminate)
        );
    }

    #[test]
    fn a_recorded_result_replayed_after_a_restart_at_a_smaller_frame_is_re_measured() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let (claim, invocation) = claim_for(&mut service, "restart");
        let big = text_result(&invocation, &"y".repeat(4000), "fixture-sse");
        let recorded = service.complete(*claim, big, FRAME).unwrap();
        assert!(rmp_serde::to_vec(&recorded).unwrap().len() > 2000);
        drop(service);

        let mut service = open_service(&store, 8);
        let TransportAdmission::Reply(same) = service
            .begin(&raw_envelope(&invocation), 1_000, FRAME)
            .unwrap()
        else {
            panic!("expected a replay");
        };
        assert_eq!(same, recorded, "a frame that still fits replays the record");
        drop(service);

        let mut service = open_service(&store, 8);
        let TransportAdmission::Reply(smaller) = service
            .begin(&raw_envelope(&invocation), 1_000, 2000)
            .unwrap()
        else {
            panic!("expected a replay");
        };
        assert!(rmp_serde::to_vec(&smaller).unwrap().len() <= 2000);
        assert_eq!(
            decrypt_result(&smaller, &security(KEY), &invocation).unwrap(),
            result_size_failure(
                CALLER,
                "restart",
                &invocation.request.model,
                invocation.native_request_sha256,
                invocation.provider_request_sha256,
            )
        );
        // The stand-in is what is recorded now, byte for byte, at any frame.
        let TransportAdmission::Reply(again) = service
            .begin(&raw_envelope(&invocation), 1_000, FRAME)
            .unwrap()
        else {
            panic!("expected a replay");
        };
        assert_eq!(again, smaller);
    }

    #[test]
    fn a_replay_whose_stand_in_cannot_fit_either_is_a_frame_bound_failure() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let (claim, invocation) = claim_for(&mut service, "no-room");
        let big = text_result(&invocation, "y", "fixture-sse");
        service.complete(*claim, big, FRAME).unwrap();
        assert_eq!(
            service.begin(&raw_envelope(&invocation), 1_000, 10).err(),
            Some(ServiceError::FrameBound)
        );
    }

    #[test]
    fn nothing_is_recorded_when_not_even_the_stand_in_fits() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let (claim, invocation) = claim_for(&mut service, "nothing-fits");
        let big = text_result(&invocation, "y", "fixture-sse");
        assert_eq!(
            service.complete(*claim, big, 10).unwrap_err(),
            ServiceError::FrameBound
        );
        // Still active, never completed, and no longer live: the retry is told the
        // outcome is indeterminate.
        let TransportAdmission::Reply(reply) = service
            .begin(&raw_envelope(&invocation), 1_000, FRAME)
            .unwrap()
        else {
            panic!("expected a refusal");
        };
        assert_eq!(
            decrypt_result(&reply, &security(KEY), &invocation)
                .unwrap()
                .disposition,
            TransportDisposition::Refused(Refusal::Indeterminate)
        );
    }
}
