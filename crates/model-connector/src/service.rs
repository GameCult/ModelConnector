use std::collections::{HashMap, HashSet};
use std::path::Path;

use cultcache_rs::{CacheBackingStore, CultCache, DatabaseEntry, OwnedRedbMessagePackBackingStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::contract::{
    ContractError, FailureKind, InputItem, ProviderRequest, RECEIPT_SCHEMA_ID, RESULT_SCHEMA_ID,
    Refusal, TransportDisposition, TransportEvent, TransportInvocation, TransportKey,
    TransportOutcome, TransportReceipt, TransportResult, canonical_invocation_bytes, require_id,
};
use crate::envelope::{
    EnvelopeKind, MAX_IDENTITY_BYTES, ServiceError, TransportEnvelope, decrypt_invocation,
    decrypt_usage_readout_request, encode_result_frame, encode_usage_readout_response_frame,
    encrypt_result, encrypt_usage_readout, validate_envelope,
};
use crate::readout::{PlanQuotaSnapshot, UsageReadout};

/// The rule that admitted callers are distinct: no two share a connection key
/// (a key names its caller), and no two share a caller id. `TransportService`
/// opens only under it, and a readiness check that must agree with opening
/// asks the same function.
pub fn distinct_admissions(admissions: &[CallerAdmission]) -> Result<(), ServiceError> {
    let mut keys = HashSet::new();
    let mut ids = HashSet::new();
    for admission in admissions {
        if !keys.insert(admission.security.0) {
            return Err(ServiceError::SharedCallerKey);
        }
        if !ids.insert(admission.caller_runtime_id.as_str()) {
            return Err(ServiceError::DuplicateCaller);
        }
    }
    Ok(())
}

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

/// The status a window carries while the provider itself refuses.
const REJECTED: &str = "rejected";

/// Whether the provider is refusing right now: some window of `plan` is
/// `rejected` and its own reset lies in the future. The one usage-derived
/// refusal there is. It repeats the provider's word with the provider's
/// expiry, and no utilization figure is ever compared to anything.
pub(crate) fn provider_rejects(plan: &PlanQuotaSnapshot, now_unix_ms: u64) -> bool {
    plan.windows
        .iter()
        .any(|window| window.status == REJECTED && window.resets_at_unix_ms > now_unix_ms)
}

/// A Self run's or Persona turn's credential lease while its holder keeps it.
#[derive(Debug, Clone, Copy)]
struct LiveLease {
    turn: LeaseTurn,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestIdentity {
    caller_runtime_id: String,
    request_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum ReplayState {
    /// Admitted and possibly executing.
    Active,
    Completed {
        response: TransportEnvelope,
    },
}

/// Idempotency only: what was asked and what was answered. Nothing here is a
/// charge.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "gamecult.model.replay_record.v3")]
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

/// What a backend is handed: the request with every foreign reasoning item
/// already removed, and the means to answer it. The caller's own invocation is
/// not held here at all, so no path from a call (Debug included) reaches
/// foreign reasoning state, and a backend cannot write the identity of its
/// receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCall {
    request: ProviderRequest,
    receipt: TransportReceipt,
}

impl ProviderCall {
    /// The request as the provider may see it: foreign reasoning items absent,
    /// every other item in the caller's order.
    pub fn request(&self) -> &ProviderRequest {
        &self.request
    }

    /// The caller this call was admitted for: the caller whose key sealed the
    /// invocation, never a name the request carries.
    pub fn caller_runtime_id(&self) -> &str {
        &self.receipt.caller_runtime_id
    }

    /// How many foreign reasoning items the service removed from the request.
    pub fn foreign_reasoning_dropped(&self) -> u32 {
        self.receipt.foreign_reasoning_dropped
    }

    /// The result of this call. The whole receipt (schema, ids, both digests,
    /// model, provider tag and drop count) is derived here, so a backend
    /// writes only the events and the outcome.
    pub fn transported(
        &self,
        events: Vec<TransportEvent>,
        outcome: TransportOutcome,
    ) -> TransportResult {
        TransportResult::transported(
            events,
            TransportReceipt {
                outcome,
                ..self.receipt.clone()
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaim {
    call: ProviderCall,
    invocation: TransportInvocation,
    invocation_sha256: [u8; 32],
}

impl ExecutionClaim {
    pub fn call(&self) -> &ProviderCall {
        &self.call
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportAdmission {
    Execute(Box<ExecutionClaim>),
    Reply(TransportEnvelope),
}

pub struct TransportService {
    callers: HashMap<String, CallerAdmission>,
    /// The requests between claim and completion.
    live: HashSet<RequestIdentity>,
    /// The credential leases their holders keep, in memory only: a lease
    /// decides `Busy` and nothing else, and ends when its holder lets go or
    /// its expiry passes.
    leases: HashMap<RequestIdentity, LiveLease>,
    replay_store: CultCache,
    max_expiry_skew_ms: u64,
    provider: String,
}

impl TransportService {
    /// `provider` is the tag of the backend this service fronts. The service
    /// owns it from here on: it decides which reasoning state is foreign and
    /// what provider every receipt names.
    pub fn open(
        replay_store_path: &Path,
        provider: &str,
        admissions: impl IntoIterator<Item = CallerAdmission>,
        max_expiry_skew_ms: u64,
    ) -> Result<Self, ServiceError> {
        Self::with_store(
            OwnedRedbMessagePackBackingStore::new(replay_store_path).map_err(replay_store_error)?,
            provider,
            admissions,
            max_expiry_skew_ms,
        )
    }

    /// `open` over any backing store, so a test can inject one that fails.
    pub fn with_store(
        store: impl CacheBackingStore + 'static,
        provider: &str,
        admissions: impl IntoIterator<Item = CallerAdmission>,
        max_expiry_skew_ms: u64,
    ) -> Result<Self, ServiceError> {
        if max_expiry_skew_ms == 0
            || require_id(provider, "provider").is_err()
            || provider == STAND_IN_PROVIDER
        {
            return Err(ServiceError::InvalidAdmission);
        }
        let admissions: Vec<CallerAdmission> = admissions.into_iter().collect();
        distinct_admissions(&admissions)?;
        let callers: HashMap<String, CallerAdmission> = admissions
            .into_iter()
            .map(|admission| (admission.caller_runtime_id.clone(), admission))
            .collect();
        if callers.is_empty() {
            return Err(ServiceError::InvalidAdmission);
        }

        let mut replay_store = CultCache::new();
        replay_store
            .register_entry_type::<ReplayRecord>()
            .map_err(replay_store_error)?;
        replay_store
            .add_generic_backing_store(store)
            .map_err(replay_store_error)?;
        // A record of any other type id (the dollar era's v2 included) has no
        // registered schema, so the pull fails and the store is refused.
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
            leases: HashMap::new(),
            replay_store,
            max_expiry_skew_ms,
            provider: provider.to_string(),
        })
    }

    /// Answers one sealed usage readout request with the backend's plan quota
    /// as it stands. Read-only: nothing is recorded. Any admitted caller reads
    /// it; the usage is the operator's and the callers are all hers.
    /// `max_frame_bytes` bounds the reply like it bounds `complete`'s.
    pub fn usage_readout(
        &self,
        envelope: &TransportEnvelope,
        now_unix_ms: u64,
        plan: PlanQuotaSnapshot,
        max_frame_bytes: usize,
    ) -> Result<TransportEnvelope, ServiceError> {
        validate_envelope(envelope, EnvelopeKind::UsageReadoutRequest)?;
        let asker = self
            .callers
            .get(&envelope.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        decrypt_usage_readout_request(envelope, &asker.security)?;
        let readout = UsageReadout::new(now_unix_ms, plan);
        let sealed = encrypt_usage_readout(
            &envelope.caller_runtime_id,
            &envelope.request_id,
            &readout,
            &asker.security,
        )?;
        if !readout_fits_frame(&sealed, max_frame_bytes)? {
            return Err(ServiceError::FrameBound);
        }
        Ok(sealed)
    }

    /// Admits one request. `plan` is the backend's plan quota as it stands: a
    /// provider that is refusing right now is repeated as `ProviderRejected`
    /// for new work. `max_frame_bytes` is the frame every reply must
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
        plan: &PlanQuotaSnapshot,
        max_frame_bytes: usize,
    ) -> Result<TransportAdmission, ServiceError> {
        validate_envelope(envelope, EnvelopeKind::Invocation)?;
        let caller = self
            .callers
            .get(&envelope.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        let security = caller.security.clone();
        let max_concurrent_requests = caller.max_concurrent_requests;
        let connection_key_epoch = caller.connection_key_epoch;
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
        let (request, foreign_reasoning_dropped) =
            match partition_reasoning(&invocation.request, &self.provider) {
                Ok(partition) => partition,
                Err(refusal) => return self.reply_refusal(&invocation, refusal, &security),
            };
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
                    let stand_in = self.seal_stand_in(
                        &invocation,
                        &security,
                        max_frame_bytes,
                        FailureKind::ResultSize,
                    )?;
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
        // The provider's own refusal binds new work only: a request already
        // recorded is answered whatever the provider says now.
        if provider_rejects(plan, now_unix_ms) {
            return self.reply_refusal(&invocation, Refusal::ProviderRejected, &security);
        }
        if self
            .live
            .iter()
            .filter(|key| key.caller_runtime_id == invocation.caller_runtime_id)
            .count()
            >= max_concurrent_requests
        {
            return self.reply_refusal(&invocation, Refusal::Capacity, &security);
        }

        // Claiming the request is one write: a store that cannot be written
        // means nothing runs.
        let replay_record = ReplayRecord {
            caller_runtime_id: identity.caller_runtime_id.clone(),
            request_id: identity.request_id.clone(),
            connection_key_epoch,
            invocation_sha256,
            expires_at_unix_ms: invocation.expires_at_unix_ms,
            state: ReplayState::Active,
        };
        self.replay_store
            .put(replay_key(&identity), &replay_record)
            .map_err(replay_store_error)?;
        self.live.insert(identity);
        Ok(TransportAdmission::Execute(Box::new(ExecutionClaim {
            call: ProviderCall {
                receipt: TransportReceipt {
                    schema_id: RECEIPT_SCHEMA_ID.to_string(),
                    request_id: invocation.request_id().to_string(),
                    caller_runtime_id: invocation.caller_runtime_id.clone(),
                    native_request_sha256: invocation.native_request_sha256,
                    provider_request_sha256: invocation.provider_request_sha256,
                    model: invocation.request.model.clone(),
                    provider: self.provider.clone(),
                    foreign_reasoning_dropped,
                    // Replaced by the backend's outcome in `transported`.
                    outcome: TransportOutcome::Failed {
                        kind: FailureKind::Provider,
                        message: String::new(),
                        usage: None,
                    },
                },
                request,
            },
            invocation,
            invocation_sha256,
        })))
    }

    /// Records a result and seals it. `max_frame_bytes` bounds the frame the
    /// sealed envelope travels in (its carriage): a result whose sealed envelope
    /// does not fit is recorded as the typed `result_size` failure instead, so
    /// no completed record is ever undeliverable and a retry replays bytes
    /// that fit.
    pub fn complete(
        &mut self,
        claim: ExecutionClaim,
        result: TransportResult,
        max_frame_bytes: usize,
    ) -> Result<TransportEnvelope, ServiceError> {
        let invocation = &claim.invocation;
        let identity = RequestIdentity {
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            request_id: invocation.request_id().to_string(),
        };
        if !self.live.contains(&identity) {
            return Err(ServiceError::NoActiveRequest);
        }
        let active = self
            .replay_store
            .get::<ReplayRecord>(&replay_key(&identity))
            .map_err(replay_store_error)?
            .ok_or(ServiceError::NoActiveRequest)?;
        if active.state != ReplayState::Active || active.invocation_sha256 != claim.invocation_sha256
        {
            return Err(ServiceError::ActiveRequestMismatch);
        }
        let caller = self
            .callers
            .get(&identity.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        let security = caller.security.clone();
        let connection_key_epoch = caller.connection_key_epoch;
        // A result the service refuses (not a transported result, not bound to
        // this invocation, or carrying a provider tag or drop count the call
        // did not derive) is answered like an oversized one: a typed failure
        // is recorded and the slot released, so the caller gets an answer and
        // a retry replays it.
        let response = if self.admits_result(&result, &claim) {
            let sealed = encrypt_result(&result, &security).inspect_err(|_| {
                self.live.remove(&identity);
            })?;
            if fits_frame(&sealed, max_frame_bytes)? {
                sealed
            } else {
                // Nothing is recorded when even the stand-in cannot be
                // carried, but the caller's slot is not held by a request
                // that can no longer finish.
                self.seal_stand_in(
                    invocation,
                    &security,
                    max_frame_bytes,
                    FailureKind::ResultSize,
                )
                .inspect_err(|_| {
                    self.live.remove(&identity);
                })?
            }
        } else {
            self.seal_stand_in(
                invocation,
                &security,
                max_frame_bytes,
                FailureKind::Provider,
            )
            .inspect_err(|_| {
                self.live.remove(&identity);
            })?
        };
        let replay_record = ReplayRecord {
            caller_runtime_id: identity.caller_runtime_id.clone(),
            request_id: identity.request_id.clone(),
            connection_key_epoch,
            invocation_sha256: claim.invocation_sha256,
            expires_at_unix_ms: invocation.expires_at_unix_ms,
            state: ReplayState::Completed {
                response: response.clone(),
            },
        };
        // A failed write frees the caller's slot and answers the typed store
        // failure; the Active record stays, so a retry is told the request is
        // indeterminate.
        self.replay_store
            .put(replay_key(&identity), &replay_record)
            .map_err(replay_store_error)
            .inspect_err(|_| {
                self.live.remove(&identity);
            })?;
        self.live.remove(&identity);
        Ok(response)
    }

    /// The `result_size` failure sealed for `invocation`, if it fits the frame.
    fn seal_stand_in(
        &self,
        invocation: &TransportInvocation,
        security: &TransportKey,
        max_frame_bytes: usize,
        kind: FailureKind,
    ) -> Result<TransportEnvelope, ServiceError> {
        let (_, foreign_reasoning_dropped) =
            partition_reasoning(&invocation.request, &self.provider)
                .map_err(|_| ServiceError::InvalidCompletion)?;
        let stand_in = encrypt_result(
            &stand_in_failure(
                &invocation.caller_runtime_id,
                invocation.request_id(),
                &invocation.request.model,
                invocation.native_request_sha256,
                invocation.provider_request_sha256,
                foreign_reasoning_dropped,
                kind,
            ),
            security,
        )?;
        if fits_frame(&stand_in, max_frame_bytes)? {
            Ok(stand_in)
        } else {
            Err(ServiceError::FrameBound)
        }
    }

    /// Whether `result` is the answer to this claim's call: transported,
    /// bound to the caller's invocation, and carrying the provider tag and
    /// drop count the service derived.
    fn admits_result(&self, result: &TransportResult, claim: &ExecutionClaim) -> bool {
        let TransportDisposition::Transported { receipt, .. } = &result.disposition else {
            return false;
        };
        result.validate_against(&claim.invocation).is_ok()
            && receipt.provider == self.provider
            && receipt.foreign_reasoning_dropped == claim.call.receipt.foreign_reasoning_dropped
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
    encode_result_frame(envelope).map(|bytes| bytes.len() <= max_frame_bytes)
}

/// `fits_frame` for the frame a usage readout answer travels in.
fn readout_fits_frame(
    envelope: &TransportEnvelope,
    max_frame_bytes: usize,
) -> Result<bool, ServiceError> {
    encode_usage_readout_response_frame(envelope).map(|bytes| bytes.len() <= max_frame_bytes)
}

/// The provider named on the stand-in failure, fixed so its size is bounded.
const STAND_IN_PROVIDER: &str = "model-connector";

/// The failed result that stands in for one whose sealed frame cannot be
/// carried: the same shape a provider failure takes, with nothing a provider
/// controls but the identities the invocation already bound.
#[cfg(test)]
pub(crate) fn result_size_failure(
    caller_runtime_id: &str,
    request_id: &str,
    model: &str,
    native_request_sha256: [u8; 32],
    provider_request_sha256: [u8; 32],
    foreign_reasoning_dropped: u32,
) -> TransportResult {
    stand_in_failure(
        caller_runtime_id,
        request_id,
        model,
        native_request_sha256,
        provider_request_sha256,
        foreign_reasoning_dropped,
        FailureKind::ResultSize,
    )
}

/// The stand-in failure for `kind`: `ResultSize` for a result that cannot be
/// carried, `Provider` for one the service refused.
fn stand_in_failure(
    caller_runtime_id: &str,
    request_id: &str,
    model: &str,
    native_request_sha256: [u8; 32],
    provider_request_sha256: [u8; 32],
    foreign_reasoning_dropped: u32,
    kind: FailureKind,
) -> TransportResult {
    let message = match kind {
        FailureKind::ResultSize => "provider result exceeded its byte bound",
        _ => "the service refused the backend's result",
    };
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
                foreign_reasoning_dropped,
                outcome: TransportOutcome::Failed {
                    kind,
                    message: message.to_string(),
                    usage: None,
                },
            }),
        },
    }
}

fn partition_reasoning(
    request: &ProviderRequest,
    provider: &str,
) -> Result<(ProviderRequest, u32), Refusal> {
    let in_flight_from = request
        .input
        .iter()
        .rposition(|item| matches!(item, InputItem::UserText { .. }))
        .map_or(0, |last_user_text| last_user_text + 1);
    let mut input = Vec::with_capacity(request.input.len());
    let mut dropped = 0u32;
    for (position, item) in request.input.iter().enumerate() {
        if let InputItem::ReasoningState { provider: tag, .. } = item
            && tag != provider
        {
            if position >= in_flight_from {
                return Err(Refusal::ForeignReasoningState);
            }
            dropped += 1;
            continue;
        }
        input.push(item.clone());
    }
    let mut filtered = request.clone();
    filtered.input = input;
    Ok((filtered, dropped))
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

mod lease;
pub use lease::{LeaseAdmission, LeaseGrant, LeaseRefusal, LeaseTurn};

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
                "fixture-sse",
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
                .begin_unplanned(
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
                .begin_unplanned(
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
            .begin_unplanned(
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
            .begin_unplanned(
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
        let conflicting = TransportInvocation::new(
            "epiphany-yggdrasil",
            2_000,
            [7; 32],
            changed_request,
        )
        .unwrap();
        let refusal = match service
            .begin_unplanned(
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
            service.begin_unplanned(&first_envelope, 1_000, FRAME).unwrap(),
            TransportAdmission::Execute(_)
        ));

        for (invocation, expected) in [(&first, Refusal::InFlight), (&second, Refusal::Capacity)] {
            let response = match service
                .begin_unplanned(
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
                .begin_unplanned(
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
            .begin_unplanned(
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
                .begin_unplanned(
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
                "fixture-sse",
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
        let invocation =
            TransportInvocation::new(CALLER, 2_000, [7; 32], request).unwrap();
        let envelope = encrypt_invocation(&invocation, &security(KEY)).unwrap();
        (service.begin_unplanned(&envelope, 1_000, FRAME).unwrap(), invocation)
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
            &crate::contract::wire_encode(invocation).unwrap(),
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
            TransportService::open(
                &store.path,
                "fixture-sse",
                [admission],
                5_000,
            )
            .unwrap()
            .begin_unplanned(&envelope, 1_000, FRAME)
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
            .begin_unplanned(&raw_envelope(&expired), 1_000, FRAME)
            .unwrap();
        assert_eq!(refusal_of(reply, &expired), Refusal::Expired);

        let mut substituted = invocation_for(CALLER, "substituted");
        substituted.provider_request_sha256 = [9; 32];
        let reply = service
            .begin_unplanned(&raw_envelope(&substituted), 1_000, FRAME)
            .unwrap();
        assert_eq!(
            refusal_of(reply, &substituted),
            Refusal::ProviderDigestSubstitution
        );

        let mut malformed = invocation_for(CALLER, "malformed");
        malformed.native_request_sha256 = [0; 32];
        let reply = service
            .begin_unplanned(&raw_envelope(&malformed), 1_000, FRAME)
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
        cache
            .add_generic_backing_store(OwnedRedbMessagePackBackingStore::new(path).unwrap())
            .unwrap();
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
        assert!(
            TransportService::open(
                &control.path,
                "fixture-sse",
                [caller(CALLER, KEY, 1)],
                5_000
            )
            .is_ok()
        );

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
                    TransportService::open(
                        &store.path,
                        "fixture-sse",
                        [caller(CALLER, KEY, 1)],
                        5_000
                    ),
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
        let result = text_result(claim.call(), "done");

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
            CallerAdmission::new(
                caller_id,
                KEY,
                1,
                [model],
                4,
                64 * 1024,
                32_768,
            )
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
            service.begin_unplanned(&raw_envelope(&ok), 1_000, FRAME).unwrap(),
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
                service.begin_unplanned(&raw_envelope(&long), 1_000, FRAME).unwrap()
            else {
                panic!("an over-long id must be refused, not executed ({length})");
            };
            assert_eq!(reply.request_id, id, "{length}");
            let result: TransportResult =
                crate::contract::wire_decode(&decrypt_message(&reply, &security(KEY)).unwrap())
                    .unwrap();
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
        // The frame carries the id twice (the message id and the envelope's
        // request id) and the base64 of the envelope, so bracket it: the
        // ciphertext plus the id is a floor, twice the ciphertext and both
        // ids plus the envelope's other fields is a frame_cap.
        let floor = sealed.ciphertext.len() + id.len();
        let frame_cap = 2 * (sealed.ciphertext.len() + 2 * id.len()) + 512;
        let store = TestStore::new();
        let mut service = open_service(&store, 1);
        assert!(matches!(
            service.begin_unplanned(&raw_envelope(&long), 1_000, frame_cap).unwrap(),
            TransportAdmission::Reply(_)
        ));
        assert_eq!(
            service
                .begin_unplanned(&raw_envelope(&long), 1_000, floor - 1)
                .unwrap_err(),
            ServiceError::FrameBound
        );
        let (_claim, _) = claim_for(&mut service, "after-the-drop");
    }

    #[test]
    fn a_frame_check_is_inclusive_of_the_serialized_envelope() {
        let envelope =
            encrypt_invocation(&invocation_for(CALLER, "sized"), &security(KEY)).unwrap();
        let size = encode_result_frame(&envelope).unwrap().len();
        assert_eq!(fits_frame(&envelope, size), Ok(true));
        assert_eq!(fits_frame(&envelope, size - 1), Ok(false));
    }

    #[test]
    fn a_readout_frame_check_is_inclusive_of_the_serialized_envelope() {
        let readout = UsageReadout::new(1, PlanQuotaSnapshot::default());
        let envelope = encrypt_usage_readout(CALLER, "sized", &readout, &security(KEY)).unwrap();
        let size = encode_usage_readout_response_frame(&envelope)
            .unwrap()
            .len();
        assert_eq!(readout_fits_frame(&envelope, size), Ok(true));
        assert_eq!(readout_fits_frame(&envelope, size - 1), Ok(false));
    }

    fn claim_for(
        service: &mut TransportService,
        request_id: &str,
    ) -> (Box<ExecutionClaim>, TransportInvocation) {
        let invocation = invocation_for(CALLER, request_id);
        match service
            .begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME)
            .unwrap()
        {
            TransportAdmission::Execute(claim) => (claim, invocation),
            TransportAdmission::Reply(_) => panic!("expected an execution claim"),
        }
    }

    fn text_result(call: &ProviderCall, text: &str) -> TransportResult {
        call.transported(
            vec![TransportEvent {
                sequence: 0,
                payload: TransportEventPayload::TextDelta {
                    text: text.to_string(),
                },
            }],
            receipt(&invocation_for(CALLER, "outcome")).outcome,
        )
    }

    #[test]
    fn a_result_whose_sealed_envelope_exceeds_the_frame_is_recorded_as_the_stand_in_failure() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let (claim, invocation) = claim_for(&mut service, "stand-in");
        let big = text_result(claim.call(), &"y".repeat(4000));
        let response = service.complete(*claim, big, 2000).unwrap();
        assert!(encode_result_frame(&response).unwrap().len() <= 2000);
        let stand_in = decrypt_result(&response, &security(KEY), &invocation).unwrap();
        assert_eq!(
            stand_in,
            result_size_failure(
                CALLER,
                "stand-in",
                &invocation.request.model,
                invocation.native_request_sha256,
                invocation.provider_request_sha256,
                0,
            )
        );
        let TransportDisposition::Transported { receipt, .. } = &stand_in.disposition else {
            panic!("expected a transported failure");
        };
        assert_eq!(receipt.provider, "model-connector");

        // The recorded replay is the stand-in's exact bytes.
        let TransportAdmission::Reply(replay) = service
            .begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME)
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
        let (claim, invocation) = claim_for(&mut service, "request-4");
        let small = text_result(claim.call(), "done");
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
        let big = text_result(claim.call(), "y");
        assert_eq!(
            service.complete(*claim, big, 10).unwrap_err(),
            ServiceError::FrameBound
        );
        // The caller's only slot is free again, and the dead request is no
        // longer in flight.
        let (_next, _) = claim_for(&mut service, "after-wedge");
        let TransportAdmission::Reply(reply) = service
            .begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME)
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
        let big = text_result(claim.call(), &"y".repeat(4000));
        let recorded = service.complete(*claim, big, FRAME).unwrap();
        assert!(encode_result_frame(&recorded).unwrap().len() > 2000);
        drop(service);

        let mut service = open_service(&store, 8);
        let TransportAdmission::Reply(same) = service
            .begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME)
            .unwrap()
        else {
            panic!("expected a replay");
        };
        assert_eq!(same, recorded, "a frame that still fits replays the record");
        drop(service);

        let mut service = open_service(&store, 8);
        let TransportAdmission::Reply(smaller) = service
            .begin_unplanned(&raw_envelope(&invocation), 1_000, 2000)
            .unwrap()
        else {
            panic!("expected a replay");
        };
        assert!(encode_result_frame(&smaller).unwrap().len() <= 2000);
        assert_eq!(
            decrypt_result(&smaller, &security(KEY), &invocation).unwrap(),
            result_size_failure(
                CALLER,
                "restart",
                &invocation.request.model,
                invocation.native_request_sha256,
                invocation.provider_request_sha256,
                0,
            )
        );
        // The stand-in is what is recorded now, byte for byte, at any frame.
        let TransportAdmission::Reply(again) = service
            .begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME)
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
        let big = text_result(claim.call(), "y");
        service.complete(*claim, big, FRAME).unwrap();
        assert_eq!(
            service.begin_unplanned(&raw_envelope(&invocation), 1_000, 10).err(),
            Some(ServiceError::FrameBound)
        );
    }

    #[test]
    fn nothing_is_recorded_when_not_even_the_stand_in_fits() {
        let store = TestStore::new();
        let mut service = open_service(&store, 8);
        let (claim, invocation) = claim_for(&mut service, "nothing-fits");
        let big = text_result(claim.call(), "y");
        assert_eq!(
            service.complete(*claim, big, 10).unwrap_err(),
            ServiceError::FrameBound
        );
        // Still active, never completed, and no longer live: the retry is told the
        // outcome is indeterminate.
        let TransportAdmission::Reply(reply) = service
            .begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME)
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
    fn contract_refusal_maps_each_error() {
        assert_eq!(contract_refusal(&ContractError::Expiry), Refusal::Expired);
        assert_eq!(
            contract_refusal(&ContractError::Identity),
            Refusal::IdentitySubstitution
        );
        assert_eq!(
            contract_refusal(&ContractError::ProviderDigest),
            Refusal::ProviderDigestSubstitution
        );
        for other in [
            ContractError::Schema,
            ContractError::Invalid("model"),
            ContractError::NativeDigest,
            ContractError::EventSequence,
        ] {
            assert_eq!(contract_refusal(&other), Refusal::Malformed, "{other:?}");
        }
    }

    fn user(text: &str) -> InputItem {
        InputItem::UserText {
            text: text.to_string(),
        }
    }

    fn state(provider: &str, model: &str, byte: u8) -> InputItem {
        InputItem::ReasoningState {
            provider: provider.to_string(),
            model: model.to_string(),
            state: vec![byte],
        }
    }

    fn admit_input(
        service: &mut TransportService,
        request_id: &str,
        input: Vec<InputItem>,
    ) -> (TransportAdmission, TransportInvocation) {
        run(service, request_id, |request| request.input = input)
    }

    #[test]
    fn foreign_reasoning_in_flight_is_refused_and_never_executed() {
        let store = TestStore::new();
        let mut service = open_service(&store, 1);
        let (admission, invocation) = admit_input(
            &mut service,
            "in-flight",
            vec![
                user("question"),
                state("fixture-sse", "gpt-5.4", 1),
                state("other-provider", "x", 2),
                InputItem::ToolResult {
                    call_id: "call-1".to_string(),
                    output: "evidence".to_string(),
                },
            ],
        );
        assert_eq!(
            refusal_of(admission, &invocation),
            Refusal::ForeignReasoningState
        );
        // Nothing was recorded or held: the caller's one slot is free and the
        // same request id is not a replay.
        let (admission, _) = admit_input(&mut service, "in-flight", vec![user("question")]);
        assert!(matches!(admission, TransportAdmission::Execute(_)));
    }

    #[test]
    fn foreign_reasoning_with_no_user_text_is_in_flight() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let (admission, invocation) = admit_input(
            &mut service,
            "no-user-text",
            vec![
                state("other-provider", "x", 2),
                InputItem::AssistantText {
                    text: "earlier".to_string(),
                },
            ],
        );
        assert_eq!(
            refusal_of(admission, &invocation),
            Refusal::ForeignReasoningState
        );
        // The boundary is the position after the last user text: a foreign item
        // directly after it is in flight too.
        let (admission, invocation) = admit_input(
            &mut service,
            "just-after",
            vec![user("a"), state("other-provider", "x", 2)],
        );
        assert_eq!(
            refusal_of(admission, &invocation),
            Refusal::ForeignReasoningState
        );
    }

    #[test]
    fn foreign_reasoning_in_completed_turns_is_dropped_and_counted() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let own = state("fixture-sse", "gpt-5.4", 3);
        let tool_call = InputItem::ToolCall {
            call_id: "call-1".to_string(),
            name: "read_source".to_string(),
            arguments: "{}".to_string(),
        };
        let (admission, invocation) = admit_input(
            &mut service,
            "completed-turns",
            vec![
                state("other-provider", "x", 1),
                user("first"),
                own.clone(),
                state("third-provider", "y", 2),
                tool_call.clone(),
                user("second"),
                tool_call.clone(),
                own.clone(),
            ],
        );
        let TransportAdmission::Execute(claim) = admission else {
            panic!("foreign state in completed turns must not stop the request");
        };
        assert_eq!(
            claim.call().request().input,
            vec![
                user("first"),
                own.clone(),
                tool_call.clone(),
                user("second"),
                tool_call,
                own,
            ]
        );
        assert_eq!(claim.call().foreign_reasoning_dropped(), 2);
        // The caller's digest binds what the caller sent, not the filtered view,
        // and the completion below is accepted against it.
        assert_ne!(
            invocation.provider_request_sha256,
            provider_request_sha256(claim.call().request()).unwrap()
        );
        let result = text_result(claim.call(), "done");
        let response = service.complete(*claim, result, FRAME).unwrap();
        let TransportDisposition::Transported { receipt, .. } =
            decrypt_result(&response, &security(KEY), &invocation)
                .unwrap()
                .disposition
        else {
            panic!("completed");
        };
        assert_eq!(receipt.foreign_reasoning_dropped, 2);
    }

    #[test]
    fn same_provider_other_model_reasoning_passes_through() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let other_model = state("fixture-sse", "some-other-model", 9);
        let (admission, _) = admit_input(
            &mut service,
            "other-model",
            vec![other_model.clone(), user("first"), other_model.clone()],
        );
        let TransportAdmission::Execute(claim) = admission else {
            panic!("an own-provider item is never foreign");
        };
        assert_eq!(
            claim.call().request().input,
            vec![other_model.clone(), user("first"), other_model]
        );
        assert_eq!(claim.call().foreign_reasoning_dropped(), 0);
    }

    #[test]
    fn open_refuses_a_blank_or_stand_in_provider_tag() {
        let store = TestStore::new();
        for tag in ["", " ", STAND_IN_PROVIDER] {
            assert!(
                matches!(
                    TransportService::open(
                        &store.path,
                        tag,
                        [caller(CALLER, KEY, 1)],
                        5_000
                    ),
                    Err(ServiceError::InvalidAdmission)
                ),
                "{tag:?}"
            );
        }
        assert!(
            TransportService::open(
                &store.path,
                "fixture-sse",
                [caller(CALLER, KEY, 1)],
                5_000
            )
            .is_ok()
        );
    }

    #[test]
    fn complete_answers_a_hand_built_receipt_with_another_provider_or_count_as_a_typed_failure() {
        let store = TestStore::new();
        let mut service = open_service(&store, 1);
        let input = vec![state("other-provider", "x", 1), user("first")];
        let tamper_edits: [fn(&mut TransportReceipt); 4] = [
            |receipt| receipt.provider = "other-provider".to_string(),
            |receipt| receipt.provider = STAND_IN_PROVIDER.to_string(),
            |receipt| receipt.foreign_reasoning_dropped = 2,
            |receipt| receipt.foreign_reasoning_dropped = 0,
        ];
        for (index, edit) in tamper_edits.into_iter().enumerate() {
            let id = format!("hand-built-{index}");
            let (admission, invocation) = admit_input(&mut service, &id, input.clone());
            let TransportAdmission::Execute(claim) = admission else {
                panic!("a refused completion must have released the slot");
            };
            assert_eq!(claim.call().foreign_reasoning_dropped(), 1);
            let mut bad = text_result(claim.call(), "done");
            let TransportDisposition::Transported { receipt, .. } = &mut bad.disposition else {
                unreachable!();
            };
            edit(receipt);
            let response = service.complete(*claim, bad, FRAME).unwrap();
            let answer = decrypt_result(&response, &security(KEY), &invocation).unwrap();
            let TransportDisposition::Transported { events, receipt } = &answer.disposition else {
                panic!("a typed failure is transported");
            };
            assert!(events.is_empty());
            assert_eq!(receipt.provider, STAND_IN_PROVIDER);
            assert_eq!(receipt.foreign_reasoning_dropped, 1);
            assert!(matches!(
                receipt.outcome,
                TransportOutcome::Failed {
                    kind: FailureKind::Provider,
                    ..
                }
            ));
            // A retry of the same id replays the failure, not ReplayConflict.
            let TransportAdmission::Reply(replay) = service
                .begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME)
                .unwrap()
            else {
                panic!("a retry must replay the recorded failure");
            };
            assert_eq!(replay, response);
        }
    }

    #[test]
    fn a_result_that_fails_validation_is_answered_as_a_typed_failure_and_releases_the_slot() {
        let store = TestStore::new();
        let mut service = open_service(&store, 1);
        let (claim, invocation) = claim_for(&mut service, "invalid-result");
        let mut bad = text_result(claim.call(), "done");
        bad.request_id = "someone-elses".to_string();
        let response = service.complete(*claim, bad, FRAME).unwrap();
        let answer = decrypt_result(&response, &security(KEY), &invocation).unwrap();
        let TransportDisposition::Transported { receipt, .. } = &answer.disposition else {
            panic!("a typed failure is transported");
        };
        assert!(matches!(
            receipt.outcome,
            TransportOutcome::Failed {
                kind: FailureKind::Provider,
                ..
            }
        ));
        // The caller's only slot is free for the next request.
        let (next, _) = claim_for(&mut service, "next");
        drop(next);
    }

    #[test]
    fn a_provider_call_formats_without_foreign_reasoning_state() {
        let store = TestStore::new();
        let mut service = open_service(&store, 1);
        let canary = "canary-foreign-provider-tag";
        let foreign = InputItem::ReasoningState {
            provider: canary.to_string(),
            model: canary.to_string(),
            state: vec![0xC7, 0xC8, 0xC9, 0xCA],
        };
        let (admission, _) = admit_input(&mut service, "debug-leak", vec![foreign, user("first")]);
        let TransportAdmission::Execute(claim) = admission else {
            panic!("expected an execution claim");
        };
        assert_eq!(claim.call().foreign_reasoning_dropped(), 1);
        for text in [
            format!("{:?}", claim.call()),
            format!("{:#?}", claim.call()),
        ] {
            assert!(!text.contains(canary), "{text}");
            assert!(!text.contains("199, 200, 201, 202"), "{text}");
        }
    }

    #[test]
    fn stand_in_carries_the_drop_count() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let input = vec![state("other-provider", "x", 1), user("first")];
        let (admission, invocation) = admit_input(&mut service, "stand-in-count", input.clone());
        let TransportAdmission::Execute(claim) = admission else {
            panic!("expected an execution claim");
        };
        let big = text_result(claim.call(), &"y".repeat(4000));
        let response = service.complete(*claim, big, 2000).unwrap();
        let expected = result_size_failure(
            CALLER,
            "stand-in-count",
            &invocation.request.model,
            invocation.native_request_sha256,
            invocation.provider_request_sha256,
            1,
        );
        assert_eq!(
            decrypt_result(&response, &security(KEY), &invocation).unwrap(),
            expected
        );

        // A recorded wide result replayed at a smaller frame keeps the count too.
        let (admission, invocation) = admit_input(&mut service, "replay-count", input);
        let TransportAdmission::Execute(claim) = admission else {
            panic!("expected an execution claim");
        };
        let big = text_result(claim.call(), &"y".repeat(4000));
        service.complete(*claim, big, FRAME).unwrap();
        let TransportAdmission::Reply(smaller) = service
            .begin_unplanned(&raw_envelope(&invocation), 1_000, 2000)
            .unwrap()
        else {
            panic!("expected a replay");
        };
        let TransportDisposition::Transported { receipt, .. } =
            decrypt_result(&smaller, &security(KEY), &invocation)
                .unwrap()
                .disposition
        else {
            panic!("expected the stand-in");
        };
        assert_eq!(receipt.provider, STAND_IN_PROVIDER);
        assert_eq!(receipt.foreign_reasoning_dropped, 1);
    }

    // ---- usage readout, the provider's refusal, the dollar era ----

    impl TransportService {
        /// `begin` while the provider reports no plan at all.
        fn begin_unplanned(
            &mut self,
            envelope: &TransportEnvelope,
            now_unix_ms: u64,
            max_frame_bytes: usize,
        ) -> Result<TransportAdmission, ServiceError> {
            self.begin(
                envelope,
                now_unix_ms,
                &PlanQuotaSnapshot::default(),
                max_frame_bytes,
            )
        }
    }

    fn plan_of(permille: u32, status: &str, resets_at_unix_ms: u64) -> PlanQuotaSnapshot {
        PlanQuotaSnapshot {
            windows: vec![crate::readout::PlanQuota {
                window: "five_hour".to_string(),
                utilization_permille: Some(permille),
                resets_at_unix_ms,
                status: status.to_string(),
                observed_at_unix_ms: 1_000,
            }],
        }
    }

    fn begin_under(
        service: &mut TransportService,
        request_id: &str,
        now: u64,
        plan: &PlanQuotaSnapshot,
    ) -> (TransportAdmission, TransportInvocation) {
        let mut request = invocation_for(CALLER, request_id).request;
        request.request_id = request_id.to_string();
        let invocation = TransportInvocation::new(CALLER, now + 1_000, [7; 32], request).unwrap();
        let admission = service
            .begin(&raw_envelope(&invocation), now, plan, FRAME)
            .unwrap();
        (admission, invocation)
    }

    fn readout_as(
        service: &TransportService,
        caller: &str,
        key: &str,
        plan: PlanQuotaSnapshot,
        frame: usize,
    ) -> Result<UsageReadout, ServiceError> {
        let sealed = encrypt_usage_readout_request(caller, "readout-1", &security(key)).unwrap();
        let answer = service.usage_readout(&sealed, 1_500, plan, frame)?;
        assert_eq!(answer.request_id, "readout-1");
        Ok(decrypt_usage_readout(&answer, &security(key)).unwrap())
    }

    #[test]
    fn a_rejected_window_refuses_invoke_until_its_reset() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let rejected = plan_of(1_000, "rejected", 10_000);
        let (refused, invocation) = begin_under(&mut service, "request-1", 9_999, &rejected);
        assert_eq!(refusal_of(refused, &invocation), Refusal::ProviderRejected);
        // At the provider's own reset the refusal lifts, and it was never
        // recorded: the same id is admitted.
        assert!(matches!(
            begin_under(&mut service, "request-1", 10_000, &rejected).0,
            TransportAdmission::Execute(_)
        ));
    }

    #[test]
    fn high_utilization_refuses_nothing() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        for (n, status) in ["allowed", "allowed_warning"].into_iter().enumerate() {
            let plan = plan_of(999, status, 1_000_000);
            assert!(matches!(
                begin_under(&mut service, &format!("request-{n}"), 1_000, &plan).0,
                TransportAdmission::Execute(_)
            ));
        }
    }

    #[test]
    fn a_recorded_answer_replays_while_the_provider_rejects() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let (claim, invocation) = claim_for(&mut service, "request-1");
        let result = text_result(claim.call(), "done");
        let answer = service.complete(*claim, result, FRAME).unwrap();
        let rejected = plan_of(1_000, "rejected", 1_000_000);
        let again = service
            .begin(&raw_envelope(&invocation), 1_000, &rejected, FRAME)
            .unwrap();
        assert_eq!(again, TransportAdmission::Reply(answer));
    }

    #[test]
    fn a_dollar_era_replay_store_is_refused_at_open() {
        use cultcache_rs::{CultCache, DatabaseEntry, OwnedRedbMessagePackBackingStore};

        // A record under the dollar era's type id, in the dollar era's shape.
        #[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
        #[cultcache(type = "gamecult.model.replay_record.v2")]
        struct DollarEraRecord {
            #[cultcache(key = 0)]
            caller_runtime_id: String,
            #[cultcache(key = 1)]
            charged: u64,
        }

        let store = TestStore::new();
        {
            let mut cache = CultCache::new();
            cache.register_entry_type::<DollarEraRecord>().unwrap();
            cache
                .add_generic_backing_store(
                    OwnedRedbMessagePackBackingStore::new(&store.path).unwrap(),
                )
                .unwrap();
            cache
                .put(
                    "old".to_string(),
                    &DollarEraRecord {
                        caller_runtime_id: CALLER.to_string(),
                        charged: 75,
                    },
                )
                .unwrap();
        }
        assert!(matches!(
            TransportService::open(
                &store.path,
                "fixture-sse",
                [caller(CALLER, KEY, 1)],
                5_000
            ),
            Err(ServiceError::ReplayStore(_))
        ));
    }

    #[test]
    fn the_usage_readout_is_the_plan_as_it_stands_and_changes_nothing() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let (claim, _) = claim_for(&mut service, "request-1");
        let plan = plan_of(80, "allowed", 1_793_307_000_000);
        // In flight, completed, asked by either caller: the same plan.
        let readout = readout_as(&service, CALLER, KEY, plan.clone(), FRAME).unwrap();
        assert_eq!(readout.at_unix_ms, 1_500);
        assert_eq!(readout.plan_quota, plan.windows);
        let result = text_result(claim.call(), "done");
        service.complete(*claim, result, FRAME).unwrap();
        let ghostlight = readout_as(
            &service,
            "ghostlight-yggdrasil",
            "ghostlight-distinct-test-key",
            plan.clone(),
            FRAME,
        )
        .unwrap();
        assert_eq!(ghostlight, readout);
        // A key that belongs to no admitted caller reads nothing.
        assert!(readout_as(&service, "ghostlight-yggdrasil", KEY, plan, FRAME).is_err());
    }

    #[test]
    fn a_readout_is_refused_to_a_stranger_a_wrong_key_and_an_invocation() {
        let store = TestStore::new();
        let service = open_service(&store, 4);
        let sealed = |caller: &str, key: &str| {
            encrypt_usage_readout_request(caller, "readout-1", &security(key)).unwrap()
        };
        assert_eq!(
            service
                .usage_readout(
                    &sealed("nobody", KEY),
                    1,
                    PlanQuotaSnapshot::default(),
                    FRAME
                )
                .unwrap_err(),
            ServiceError::CallerNotAdmitted
        );
        assert_eq!(
            service
                .usage_readout(
                    &sealed(CALLER, "another-key"),
                    1,
                    PlanQuotaSnapshot::default(),
                    FRAME
                )
                .unwrap_err(),
            ServiceError::Encryption
        );
        let invocation = invocation_for(CALLER, "request-1");
        assert_eq!(
            service
                .usage_readout(
                    &raw_envelope(&invocation),
                    1,
                    PlanQuotaSnapshot::default(),
                    FRAME
                )
                .unwrap_err(),
            ServiceError::Envelope
        );
    }

    #[test]
    fn a_readout_that_cannot_fit_the_frame_is_a_frame_bound_failure() {
        let store = TestStore::new();
        let service = open_service(&store, 4);
        assert_eq!(
            readout_as(&service, CALLER, KEY, PlanQuotaSnapshot::default(), 64).unwrap_err(),
            ServiceError::FrameBound
        );
        assert!(readout_as(&service, CALLER, KEY, PlanQuotaSnapshot::default(), FRAME).is_ok());
    }

    #[test]
    fn the_connector_service_has_exactly_two_operations() {
        assert_eq!(Operation::from_name("readout"), None);
        assert_eq!(Operation::from_name("invoke"), Some(Operation::Invoke));
        assert_eq!(
            Operation::from_name("usage_readout"),
            Some(Operation::UsageReadout)
        );
    }

    #[test]
    fn a_store_that_cannot_be_written_executes_nothing_and_holds_no_slot() {
        let store = FlakyStore::new(0);
        let allowance = store.allowance();
        let mut service =
            TransportService::with_store(store, "fixture-sse", [caller(CALLER, KEY, 1)], 5_000)
                .unwrap();
        let invocation = invocation_for(CALLER, "request-1");
        assert!(matches!(
            service.begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME),
            Err(ServiceError::ReplayStore(_))
        ));
        allowance.store(10, Ordering::SeqCst);
        assert!(matches!(
            service.begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME),
            Ok(TransportAdmission::Execute(_))
        ));
    }

    #[test]
    fn a_failed_completion_write_answers_the_store_failure_and_frees_the_slot() {
        let store = FlakyStore::new(1);
        let allowance = store.allowance();
        let mut service =
            TransportService::with_store(store, "fixture-sse", [caller(CALLER, KEY, 1)], 5_000)
                .unwrap();
        let (claim, invocation) = claim_for(&mut service, "request-1");
        let result = text_result(claim.call(), "done");
        assert!(matches!(
            service.complete(*claim, result, FRAME),
            Err(ServiceError::ReplayStore(_))
        ));
        // The slot is free (one concurrent request is admitted), and the retry
        // of the unfinished id is told it is indeterminate, not in flight.
        allowance.store(10, Ordering::SeqCst);
        let again = service
            .begin_unplanned(&raw_envelope(&invocation), 1_000, FRAME)
            .unwrap();
        assert_eq!(refusal_of(again, &invocation), Refusal::Indeterminate);
        let _ = claim_for(&mut service, "request-2");
    }
}
