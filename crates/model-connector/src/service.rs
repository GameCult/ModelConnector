use std::collections::{HashMap, HashSet};
use std::path::Path;

use cultcache_rs::{CultCache, DatabaseEntry, OwnedRedbMessagePackBackingStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::contract::{
    ContractError, Refusal, TransportDisposition, TransportInvocation, TransportKey,
    TransportResult, canonical_invocation_bytes, require_id,
};
use crate::envelope::{
    EnvelopeKind, ServiceError, TransportEnvelope, decrypt_invocation, encrypt_result,
    validate_envelope,
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
            || allowed_models
                .iter()
                .any(|model| require_id(model, "allowed_model").is_err())
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

    pub fn begin(
        &mut self,
        envelope: &TransportEnvelope,
        now_unix_ms: u64,
    ) -> Result<TransportAdmission, ServiceError> {
        validate_envelope(envelope, EnvelopeKind::Invocation)?;
        let caller = self
            .callers
            .get(&envelope.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        if envelope.ciphertext.len() > caller.max_payload_bytes {
            return Err(ServiceError::PayloadTooLarge);
        }
        let security = caller.security.clone();
        let max_concurrent_requests = caller.max_concurrent_requests;
        let invocation = decrypt_invocation(envelope, &security)?;
        if let Err(error) = invocation.validate(now_unix_ms, self.max_expiry_skew_ms) {
            return self.reply_refusal(&invocation, contract_refusal(&error), &security);
        }
        if !caller.allowed_models.contains(&invocation.request.model)
            || invocation
                .request
                .max_output_tokens
                .is_some_and(|limit| limit > caller.max_output_tokens)
        {
            return self.reply_refusal(&invocation, Refusal::Policy, &security);
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
            return match record.state {
                ReplayState::Completed { response } => {
                    Ok(TransportAdmission::Reply(response))
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
        Ok(TransportAdmission::Execute(Box::new(
            ExecutionClaim {
                invocation,
                invocation_sha256,
            },
        )))
    }

    pub fn complete(
        &mut self,
        claim: ExecutionClaim,
        result: TransportResult,
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
        let response = encrypt_result(&result, &caller.security)?;
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

fn replay_key(identity: &RequestIdentity) -> String {
    let mut hasher = Sha256::new();
    hasher.update((identity.caller_runtime_id.len() as u64).to_be_bytes());
    hasher.update(identity.caller_runtime_id.as_bytes());
    hasher.update((identity.request_id.len() as u64).to_be_bytes());
    hasher.update(identity.request_id.as_bytes());
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = hasher.finalize();
    let mut key = String::with_capacity(64);
    for byte in digest {
        key.push(HEX[(byte >> 4) as usize] as char);
        key.push(HEX[(byte & 0x0f) as usize] as char);
    }
    key
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
            .begin(&encrypt_invocation(&invocation, &security).unwrap(), 1_000)
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
            )
            .unwrap();
        drop(service);
        let mut service = open_service(&store, 1);

        let replay = match service
            .begin(&encrypt_invocation(&invocation, &security).unwrap(), 1_000)
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
            .begin(&encrypt_invocation(&conflicting, &security).unwrap(), 1_000)
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
            service.begin(&first_envelope, 1_000).unwrap(),
            TransportAdmission::Execute(_)
        ));

        for (invocation, expected) in [
            (&first, Refusal::InFlight),
            (&second, Refusal::Capacity),
        ] {
            let response = match service
                .begin(&encrypt_invocation(invocation, &security).unwrap(), 1_000)
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
                .begin(&encrypt_invocation(&first, &security).unwrap(), 1_000)
                .unwrap(),
            TransportAdmission::Execute(_)
        ));
        drop(service);

        let mut restarted = open_service(&store, 1);
        let ambiguous = match restarted
            .begin(&encrypt_invocation(&first, &security).unwrap(), 1_000)
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
                .begin(&encrypt_invocation(&second, &security).unwrap(), 1_000)
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
        (service.begin(&envelope, 1_000).unwrap(), invocation)
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
    fn policy_refuses_unlisted_models_and_output_tokens_over_the_caller_cap() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);

        let (admission, invocation) = run(&mut service, "unlisted-model", |request| {
            request.model = "other-model".to_string();
        });
        assert_eq!(refusal_of(admission, &invocation), Refusal::Policy);

        let (admission, invocation) = run(&mut service, "over-cap", |request| {
            request.max_output_tokens = Some(32_769);
        });
        assert_eq!(refusal_of(admission, &invocation), Refusal::Policy);

        for (id, tokens) in [
            ("at-cap", Some(32_768)),
            ("under-cap", Some(100)),
            ("unset", None),
        ] {
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
                .begin(&envelope, 1_000)
        };
        assert!(matches!(admit(size), Ok(TransportAdmission::Execute(_))));
        assert_eq!(admit(size - 1).unwrap_err(), ServiceError::PayloadTooLarge);
    }

    #[test]
    fn contract_failures_are_refused_with_the_matching_refusal() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);

        let mut expired = invocation_for(CALLER, "expired");
        expired.expires_at_unix_ms = 10;
        let reply = service.begin(&raw_envelope(&expired), 1_000).unwrap();
        assert_eq!(refusal_of(reply, &expired), Refusal::Expired);

        let mut substituted = invocation_for(CALLER, "substituted");
        substituted.provider_request_sha256 = [9; 32];
        let reply = service.begin(&raw_envelope(&substituted), 1_000).unwrap();
        assert_eq!(
            refusal_of(reply, &substituted),
            Refusal::ProviderDigestSubstitution
        );

        let mut malformed = invocation_for(CALLER, "malformed");
        malformed.native_request_sha256 = [0; 32];
        let reply = service.begin(&raw_envelope(&malformed), 1_000).unwrap();
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
            service.complete(forged, result.clone()).unwrap_err(),
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
            service.complete(*claim, result).unwrap_err(),
            ServiceError::ActiveRequestMismatch
        );
    }
}
