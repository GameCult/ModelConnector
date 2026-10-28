use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use cultcache_rs::{CacheBackingStore, CultCache, DatabaseEntry, OwnedRedbMessagePackBackingStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::contract::{
    CacheRetention, ContractError, FailureKind, InputItem, ProviderRequest, RECEIPT_SCHEMA_ID,
    RESULT_SCHEMA_ID, Refusal, TransportDisposition, TransportEvent, TransportInvocation,
    TransportKey, TransportOutcome, TransportReceipt, TransportResult, Usage,
    canonical_invocation_bytes, require_id, wire_encode,
};
use crate::envelope::{
    EnvelopeKind, MAX_IDENTITY_BYTES, ServiceError, TransportEnvelope, decrypt_invocation,
    encode_result_frame, encrypt_result, validate_envelope,
};

/// What a caller may spend in one window, in micro-USD. A distinct type from
/// [`SpendWindowMs`] so the pair cannot be passed swapped:
///
/// ```
/// use model_connector::{CallerAdmission, SpendCeiling, SpendWindowMs};
/// CallerAdmission::new(
///     "caller-1", "a-connection-key", 1, ["model-1".to_string()], 1, 1, 1,
///     SpendCeiling(50_000_000), SpendWindowMs(3_600_000),
/// )
/// .unwrap();
/// ```
///
/// ```compile_fail
/// use model_connector::{CallerAdmission, SpendCeiling, SpendWindowMs};
/// CallerAdmission::new(
///     "caller-1", "a-connection-key", 1, ["model-1".to_string()], 1, 1, 1,
///     SpendWindowMs(3_600_000), SpendCeiling(50_000_000),
/// )
/// .unwrap();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendCeiling(pub u64);

/// How long a spend window lasts, in milliseconds. Windows are fixed and
/// aligned to the unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendWindowMs(pub u64);

pub struct CallerAdmission {
    caller_runtime_id: String,
    connection_key_epoch: u32,
    security: TransportKey,
    allowed_models: HashSet<String>,
    max_concurrent_requests: usize,
    max_payload_bytes: usize,
    max_output_tokens: u32,
    spend_ceiling_micro_usd: u64,
    spend_window_ms: u64,
}

impl CallerAdmission {
    // The ceiling and window ride beside the other limits the root-owned caller
    // config sets, one parameter each.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        caller_runtime_id: impl Into<String>,
        connection_key: impl Into<String>,
        connection_key_epoch: u32,
        allowed_models: impl IntoIterator<Item = String>,
        max_concurrent_requests: usize,
        max_payload_bytes: usize,
        max_output_tokens: u32,
        spend_ceiling: SpendCeiling,
        spend_window: SpendWindowMs,
    ) -> Result<Self, ServiceError> {
        let (spend_ceiling_micro_usd, spend_window_ms) = (spend_ceiling.0, spend_window.0);
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
            || spend_ceiling_micro_usd == 0
            || spend_window_ms == 0
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
            spend_ceiling_micro_usd,
            spend_window_ms,
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

/// What one million tokens of each class cost, in micro-USD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rates {
    pub input: u64,
    pub cache_write_short: u64,
    pub cache_write_long: u64,
    pub cache_read: u64,
    pub output: u64,
}

/// The rates a prompt strictly above `above_prompt_tokens` is priced at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongContext {
    pub above_prompt_tokens: u64,
    pub rates: Rates,
}

/// One model's price. Explicit zero rates are admitted (a local model is
/// free); a missing price is not. `overhead_tokens` is added to the byte
/// bound of a request when its worst case is reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelPrice {
    pub rates: Rates,
    pub long_context: Option<LongContext>,
    pub overhead_tokens: u64,
}

/// The price of every model a caller may be allowed, supplied at open by the
/// connector binary's config document.
pub type PriceTable = BTreeMap<String, ModelPrice>;

const TOKENS_PER_RATE: u128 = 1_000_000;

/// Rounds up to whole micro-USD; `None` when the amount does not fit a u64.
fn checked_ceil_micro_usd(rate_weighted_tokens: u128) -> Option<u64> {
    let whole = rate_weighted_tokens / TOKENS_PER_RATE;
    let rounded = whole + u128::from(!rate_weighted_tokens.is_multiple_of(TOKENS_PER_RATE));
    u64::try_from(rounded).ok()
}

fn ceil_micro_usd(rate_weighted_tokens: u128) -> u64 {
    checked_ceil_micro_usd(rate_weighted_tokens).unwrap_or(u64::MAX)
}

impl Rates {
    /// The dearer of each class.
    fn dearest(self, other: Rates) -> Rates {
        Rates {
            input: self.input.max(other.input),
            cache_write_short: self.cache_write_short.max(other.cache_write_short),
            cache_write_long: self.cache_write_long.max(other.cache_write_long),
            cache_read: self.cache_read.max(other.cache_read),
            output: self.output.max(other.output),
        }
    }
}

fn rates_for(price: &ModelPrice, prompt_tokens: u128) -> &Rates {
    match &price.long_context {
        Some(long) if prompt_tokens > u128::from(long.above_prompt_tokens) => &long.rates,
        _ => &price.rates,
    }
}

/// A cache write nobody asked to keep short is priced dear.
fn write_rate(rates: &Rates, retention: Option<CacheRetention>) -> u64 {
    match retention {
        Some(CacheRetention::Short) => rates.cache_write_short,
        Some(CacheRetention::Long) | None => rates.cache_write_long,
    }
}

/// What `usage` costs under `price`, in micro-USD: the sum over token classes
/// of tokens times rate, rounded up once, saturating at `u64::MAX`.
pub(crate) fn cost_micro_usd(
    price: &ModelPrice,
    usage: &Usage,
    retention: Option<CacheRetention>,
) -> u64 {
    let prompt = u128::from(usage.input_tokens)
        + u128::from(usage.cache_read_tokens)
        + u128::from(usage.cache_write_tokens);
    let rates = rates_for(price, prompt);
    let total = [
        u128::from(usage.input_tokens) * u128::from(rates.input),
        u128::from(usage.cache_read_tokens) * u128::from(rates.cache_read),
        u128::from(usage.cache_write_tokens) * u128::from(write_rate(rates, retention)),
        u128::from(usage.output_tokens) * u128::from(rates.output),
    ]
    .into_iter()
    .fold(0u128, u128::saturating_add);
    ceil_micro_usd(total)
}

/// The worst case `request` can cost, in micro-USD: its encoded length plus
/// the model's overhead as input tokens (a token is at least one byte) at the
/// dearest input rate the cache retention allows, plus `max_output_tokens` at
/// the output rate, rounded up once. A prompt that may cross the long-context
/// threshold is bounded at the dearer of the two rate sets, so a backend whose
/// usage prices above this broke its contract. `None` when the worst case does
/// not fit a u64: such a request can never be afforded.
pub(crate) fn reservation_micro_usd(
    price: &ModelPrice,
    request: &ProviderRequest,
) -> Result<Option<u64>, ContractError> {
    let bound = (wire_encode(request)?.len() as u128) + u128::from(price.overhead_tokens);
    let rates = match &price.long_context {
        Some(long) if bound > u128::from(long.above_prompt_tokens) => {
            price.rates.dearest(long.rates)
        }
        _ => price.rates,
    };
    let input_rate = rates
        .input
        .max(rates.cache_read)
        .max(write_rate(&rates, request.cache_retention));
    let total = bound.checked_mul(u128::from(input_rate)).and_then(|input| {
        input.checked_add(u128::from(request.max_output_tokens) * u128::from(rates.output))
    });
    Ok(total.and_then(checked_ceil_micro_usd))
}

/// Moves `held` of a caller's window: releases `release`, then adds `charge`.
fn add_spend(
    window_spend: &mut HashMap<String, BTreeMap<u64, u64>>,
    caller_runtime_id: &str,
    window: u64,
    release: u64,
    charge: u64,
) {
    let held = window_spend
        .entry(caller_runtime_id.to_string())
        .or_default()
        .entry(window)
        .or_insert(0);
    *held = held.saturating_sub(release).saturating_add(charge);
}

/// The clock a request is admitted at: `now`, held monotonic per caller. A
/// caller's window never moves back, so a clock that steps back (or a boot
/// with the clock behind a recorded window) cannot reopen spent budget: the
/// request is admitted into the caller's newest recorded window. The record
/// stores this value, so the window re-derives from the records at open.
fn admission_clock(
    window_spend: &HashMap<String, BTreeMap<u64, u64>>,
    caller_runtime_id: &str,
    now_unix_ms: u64,
    spend_window_ms: u64,
) -> u64 {
    let newest = window_spend
        .get(caller_runtime_id)
        .and_then(|windows| windows.keys().next_back().copied())
        .unwrap_or(0);
    now_unix_ms.max(newest.saturating_mul(spend_window_ms))
}

/// Drops the windows of `caller_runtime_id` that nothing can still read:
/// those before `floor` that hold no live request's reservation. Admission
/// reads the current window alone, and a live request settles into the window
/// it was admitted in, so nothing older is kept.
fn prune_windows(
    window_spend: &mut HashMap<String, BTreeMap<u64, u64>>,
    live: &HashMap<RequestIdentity, u64>,
    caller_runtime_id: &str,
    floor: u64,
) {
    if let Some(windows) = window_spend.get_mut(caller_runtime_id) {
        windows.retain(|window, _| {
            *window >= floor
                || live.iter().any(|(identity, live_window)| {
                    live_window == window && identity.caller_runtime_id == caller_runtime_id
                })
        });
    }
}

/// `prune_windows` with the caller's newest window as the floor, for the
/// places that do not know the clock (open, settle).
fn prune_to_latest(
    window_spend: &mut HashMap<String, BTreeMap<u64, u64>>,
    live: &HashMap<RequestIdentity, u64>,
    caller_runtime_id: &str,
) {
    let latest = window_spend
        .get(caller_runtime_id)
        .and_then(|windows| windows.keys().next_back().copied());
    if let Some(latest) = latest {
        prune_windows(window_spend, live, caller_runtime_id, latest);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestIdentity {
    caller_runtime_id: String,
    request_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum ReplayState {
    /// Admitted and possibly executing: the worst case is held against the
    /// caller's window until the request settles (an indeterminate one is
    /// billed at it).
    Active { reserved_micro_usd: u64 },
    /// `overrun_micro_usd` is what the charge exceeded the reservation by: a
    /// backend contract breach, kept so a replayed stand-in still says so.
    Completed {
        response: TransportEnvelope,
        charged_micro_usd: u64,
        overrun_micro_usd: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "gamecult.model.replay_record.v2")]
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
    #[cultcache(key = 6)]
    admitted_at_unix_ms: u64,
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
    price: ModelPrice,
    reserved_micro_usd: u64,
}

impl ProviderCall {
    /// The request as the provider may see it: foreign reasoning items absent,
    /// every other item in the caller's order.
    pub fn request(&self) -> &ProviderRequest {
        &self.request
    }

    /// How many foreign reasoning items the service removed from the request.
    pub fn foreign_reasoning_dropped(&self) -> u32 {
        self.receipt.foreign_reasoning_dropped
    }

    /// The result of this call. The whole receipt (schema, ids, both digests,
    /// model, provider tag, drop count and cost) is derived here, so a backend
    /// writes only the events and the outcome.
    pub fn transported(
        &self,
        events: Vec<TransportEvent>,
        outcome: TransportOutcome,
    ) -> TransportResult {
        TransportResult::transported(events, {
            let cost_micro_usd = self.cost_of(&outcome);
            TransportReceipt {
                cost_micro_usd,
                overrun_micro_usd: self.overrun_of(cost_micro_usd),
                outcome,
                ..self.receipt.clone()
            }
        })
    }

    /// How far `cost_micro_usd` exceeds what was reserved. The reservation is
    /// the worst case the kit can compute, so a nonzero overrun means the
    /// backend broke its contract (usage above its own request's bounds).
    fn overrun_of(&self, cost_micro_usd: u64) -> u64 {
        cost_micro_usd.saturating_sub(self.reserved_micro_usd)
    }

    /// What `outcome` costs: its usage priced, or the whole reservation when a
    /// failure does not say what it billed (unknown is billed as the worst case).
    fn cost_of(&self, outcome: &TransportOutcome) -> u64 {
        match outcome {
            TransportOutcome::Completed { usage, .. }
            | TransportOutcome::Failed {
                usage: Some(usage), ..
            } => cost_micro_usd(&self.price, usage, self.request.cache_retention),
            TransportOutcome::Failed { usage: None, .. } => self.reserved_micro_usd,
        }
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
    /// The requests between claim and settlement, each with the window it was
    /// admitted in.
    live: HashMap<RequestIdentity, u64>,
    replay_store: CultCache,
    max_expiry_skew_ms: u64,
    provider: String,
    prices: PriceTable,
    /// Per caller, what each spend window holds: the reservations of its
    /// Active records and the charges of its Completed ones. A cache of the
    /// replay records, re-derived at open and moved only after a record's put
    /// returns Ok; the records are the ledger. A request belongs to the window
    /// it was admitted in, so settlement never moves it to another. Only what
    /// admission and settlement can still read is kept: the caller's newest
    /// window and any older one a live request is reserved in.
    window_spend: HashMap<String, BTreeMap<u64, u64>>,
}

impl TransportService {
    /// `provider` is the tag of the backend this service fronts. The service
    /// owns it from here on: it decides which reasoning state is foreign and
    /// what provider every receipt names. `prices` must price every model any
    /// caller is allowed.
    pub fn open(
        replay_store_path: &Path,
        provider: &str,
        prices: PriceTable,
        admissions: impl IntoIterator<Item = CallerAdmission>,
        max_expiry_skew_ms: u64,
    ) -> Result<Self, ServiceError> {
        Self::with_store(
            OwnedRedbMessagePackBackingStore::new(replay_store_path).map_err(replay_store_error)?,
            provider,
            prices,
            admissions,
            max_expiry_skew_ms,
        )
    }

    /// `open` over any backing store, so a test can inject one that fails.
    pub fn with_store(
        store: impl CacheBackingStore + 'static,
        provider: &str,
        prices: PriceTable,
        admissions: impl IntoIterator<Item = CallerAdmission>,
        max_expiry_skew_ms: u64,
    ) -> Result<Self, ServiceError> {
        if max_expiry_skew_ms == 0
            || require_id(provider, "provider").is_err()
            || provider == STAND_IN_PROVIDER
        {
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
        if let Some(model) = callers
            .values()
            .flat_map(|caller| caller.allowed_models.iter())
            .filter(|model| !prices.contains_key(*model))
            .min()
        {
            return Err(ServiceError::UnpricedModel(model.clone()));
        }

        let mut replay_store = CultCache::new();
        replay_store
            .register_entry_type::<ReplayRecord>()
            .map_err(replay_store_error)?;
        replay_store
            .add_generic_backing_store(store)
            .map_err(replay_store_error)?;
        replay_store
            .pull_all_backing_stores()
            .map_err(replay_store_error)?;

        let mut window_spend: HashMap<String, BTreeMap<u64, u64>> = HashMap::new();
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
                || record.admitted_at_unix_ms == 0
            {
                return Err(ServiceError::InvalidReplayRecord);
            }
            let Some(caller) = callers.get(&record.caller_runtime_id) else {
                continue;
            };
            if record.connection_key_epoch != caller.connection_key_epoch {
                return Err(ServiceError::ReplayCallerKeyMismatch);
            }
            // An Active record left by a crash counts at its full reservation:
            // indeterminate is billed as the worst case.
            let held = match &record.state {
                ReplayState::Active { reserved_micro_usd } => *reserved_micro_usd,
                ReplayState::Completed {
                    charged_micro_usd, ..
                } => *charged_micro_usd,
            };
            add_spend(
                &mut window_spend,
                &record.caller_runtime_id,
                record.admitted_at_unix_ms / caller.spend_window_ms,
                0,
                held,
            );
        }
        let live = HashMap::new();
        let spenders: Vec<String> = window_spend.keys().cloned().collect();
        for caller_runtime_id in &spenders {
            prune_to_latest(&mut window_spend, &live, caller_runtime_id);
        }
        Ok(Self {
            callers,
            live,
            replay_store,
            max_expiry_skew_ms,
            provider: provider.to_string(),
            prices,
            window_spend,
        })
    }

    /// What `caller_runtime_id`'s spend window `window` holds.
    pub(crate) fn window_spend(&self, caller_runtime_id: &str, window: u64) -> u64 {
        self.window_spend
            .get(caller_runtime_id)
            .and_then(|windows| windows.get(&window))
            .copied()
            .unwrap_or(0)
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
        let connection_key_epoch = caller.connection_key_epoch;
        let spend_ceiling = caller.spend_ceiling_micro_usd;
        let spend_window_ms = caller.spend_window_ms;
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
                ReplayState::Completed {
                    response,
                    charged_micro_usd,
                    overrun_micro_usd,
                } => {
                    if fits_frame(response, max_frame_bytes)? {
                        return Ok(TransportAdmission::Reply(response.clone()));
                    }
                    // The stand-in keeps the recorded charge: the request cost
                    // what it cost whatever frame its answer travels in.
                    let stand_in = self.seal_stand_in(
                        &invocation,
                        &security,
                        max_frame_bytes,
                        FailureKind::ResultSize,
                        Charge {
                            cost_micro_usd: *charged_micro_usd,
                            overrun_micro_usd: *overrun_micro_usd,
                        },
                    )?;
                    self.replay_store
                        .put(
                            replay_key(&identity),
                            &ReplayRecord {
                                state: ReplayState::Completed {
                                    response: stand_in.clone(),
                                    charged_micro_usd: *charged_micro_usd,
                                    overrun_micro_usd: *overrun_micro_usd,
                                },
                                ..record.clone()
                            },
                        )
                        .map_err(replay_store_error)?;
                    Ok(TransportAdmission::Reply(stand_in))
                }
                ReplayState::Active { .. } => {
                    let refusal = if self.live.contains_key(&identity) {
                        Refusal::InFlight
                    } else {
                        Refusal::Indeterminate
                    };
                    self.reply_refusal(&invocation, refusal, &security)
                }
            };
        }
        // The worst case is priced at today's table, so it is checked only for
        // new work: a request already recorded is answered whatever it would
        // cost now.
        let price = *self
            .prices
            .get(&invocation.request.model)
            .ok_or_else(|| ServiceError::UnpricedModel(invocation.request.model.clone()))?;
        let reserved_micro_usd = match reservation_micro_usd(&price, &request)? {
            Some(reserved) if reserved <= invocation.max_cost_micro_usd => reserved,
            _ => return self.reply_refusal(&invocation, Refusal::CostBound, &security),
        };
        let active_for_caller = self
            .live
            .keys()
            .filter(|key| key.caller_runtime_id == invocation.caller_runtime_id)
            .count();
        if active_for_caller >= max_concurrent_requests {
            return self.reply_refusal(&invocation, Refusal::Capacity, &security);
        }
        // A request belongs to the window it is admitted in. The ceiling is
        // checked after the replay lookup, so a recorded answer is replayed
        // whatever the caller has left.
        let admitted_at_unix_ms = admission_clock(
            &self.window_spend,
            &identity.caller_runtime_id,
            now_unix_ms,
            spend_window_ms,
        );
        let window = admitted_at_unix_ms / spend_window_ms;
        prune_windows(
            &mut self.window_spend,
            &self.live,
            &identity.caller_runtime_id,
            window,
        );
        if self
            .window_spend(&identity.caller_runtime_id, window)
            .saturating_add(reserved_micro_usd)
            > spend_ceiling
        {
            // A clock reading behind the caller's newest window is named: the
            // refusal holds until the clock reaches that window's start.
            let refusal = if now_unix_ms < window.saturating_mul(spend_window_ms) {
                Refusal::ClockBehindAdmissionWindow
            } else {
                Refusal::SpendCeiling
            };
            return self.reply_refusal(&invocation, refusal, &security);
        }

        // Reserving and claiming the request are one write: a ledger that
        // cannot be written means nothing runs.
        let replay_record = ReplayRecord {
            caller_runtime_id: identity.caller_runtime_id.clone(),
            request_id: identity.request_id.clone(),
            connection_key_epoch,
            invocation_sha256,
            expires_at_unix_ms: invocation.expires_at_unix_ms,
            state: ReplayState::Active { reserved_micro_usd },
            admitted_at_unix_ms,
        };
        self.replay_store
            .put(replay_key(&identity), &replay_record)
            .map_err(replay_store_error)?;
        add_spend(
            &mut self.window_spend,
            &identity.caller_runtime_id,
            window,
            0,
            reserved_micro_usd,
        );
        self.live.insert(identity, window);
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
                    cost_micro_usd: 0,
                    overrun_micro_usd: 0,
                    outcome: TransportOutcome::Failed {
                        kind: FailureKind::Provider,
                        message: String::new(),
                        usage: None,
                    },
                },
                request,
                price,
                reserved_micro_usd,
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
        if !self.live.contains_key(&identity) {
            return Err(ServiceError::NoActiveRequest);
        }
        let active = self
            .replay_store
            .get::<ReplayRecord>(&replay_key(&identity))
            .map_err(replay_store_error)?
            .ok_or(ServiceError::NoActiveRequest)?;
        let ReplayState::Active { reserved_micro_usd } = active.state else {
            return Err(ServiceError::ActiveRequestMismatch);
        };
        if active.invocation_sha256 != claim.invocation_sha256 {
            return Err(ServiceError::ActiveRequestMismatch);
        }
        let caller = self
            .callers
            .get(&identity.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        let security = caller.security.clone();
        let connection_key_epoch = caller.connection_key_epoch;
        let spend_window_ms = caller.spend_window_ms;
        // A result the service refuses (not a transported result, not bound to
        // this invocation, or carrying a provider tag or drop count the call
        // did not derive) is answered like an oversized one: a typed failure
        // is recorded and the slot released, so the caller gets an answer and
        // a retry replays it.
        let admissible = self.admits_result(&result, &claim);
        // The service prices what the backend reported, but only for a result
        // bound to this invocation: a transported result charges the cost its
        // own outcome's usage derives, and its overrun past the reservation,
        // whatever its receipt says (a receipt that misstates either is
        // replaced by the stand-in but still charged the true cost). Any
        // other result, including one bound to another request, charges the
        // whole reservation.
        let charge = match &result.disposition {
            TransportDisposition::Transported { receipt, .. }
                if result.validate_against(invocation).is_ok() =>
            {
                let cost_micro_usd = claim.call.cost_of(&receipt.outcome);
                Charge {
                    cost_micro_usd,
                    overrun_micro_usd: claim.call.overrun_of(cost_micro_usd),
                }
            }
            _ => Charge {
                cost_micro_usd: reserved_micro_usd,
                overrun_micro_usd: 0,
            },
        };
        let charged_micro_usd = charge.cost_micro_usd;
        let mut response = if admissible {
            encrypt_result(&result, &security).inspect_err(|_| {
                self.live.remove(&identity);
            })?
        } else {
            self.seal_stand_in(
                invocation,
                &security,
                max_frame_bytes,
                FailureKind::Provider,
                charge,
            )
            .inspect_err(|_| {
                self.live.remove(&identity);
            })?
        };
        if admissible && !fits_frame(&response, max_frame_bytes)? {
            // Nothing is recorded when even the stand-in cannot be carried,
            // but the caller's slot is not held by a request that can no
            // longer finish.
            response = self
                .seal_stand_in(
                    invocation,
                    &security,
                    max_frame_bytes,
                    FailureKind::ResultSize,
                    charge,
                )
                .inspect_err(|_| {
                    self.live.remove(&identity);
                })?;
        }
        let replay_record = ReplayRecord {
            caller_runtime_id: identity.caller_runtime_id.clone(),
            request_id: identity.request_id.clone(),
            connection_key_epoch,
            invocation_sha256: claim.invocation_sha256,
            expires_at_unix_ms: invocation.expires_at_unix_ms,
            state: ReplayState::Completed {
                response: response.clone(),
                charged_micro_usd,
                overrun_micro_usd: charge.overrun_micro_usd,
            },
            admitted_at_unix_ms: active.admitted_at_unix_ms,
        };
        // A failed settle write frees the caller's slot and answers the typed
        // store failure; the Active record stays, so the reservation stays
        // counted and a retry is told the request is indeterminate.
        self.replay_store
            .put(replay_key(&identity), &replay_record)
            .map_err(replay_store_error)
            .inspect_err(|_| {
                self.live.remove(&identity);
            })?;
        // Settled: the window the request was admitted in holds the charge in
        // place of the reservation. A failed put above leaves the reservation
        // counted, as the store does.
        add_spend(
            &mut self.window_spend,
            &identity.caller_runtime_id,
            active.admitted_at_unix_ms / spend_window_ms,
            reserved_micro_usd,
            charged_micro_usd,
        );
        self.live.remove(&identity);
        prune_to_latest(
            &mut self.window_spend,
            &self.live,
            &identity.caller_runtime_id,
        );
        Ok(response)
    }

    /// The `result_size` failure sealed for `invocation`, if it fits the frame.
    fn seal_stand_in(
        &self,
        invocation: &TransportInvocation,
        security: &TransportKey,
        max_frame_bytes: usize,
        kind: FailureKind,
        charge: Charge,
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
                charge,
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
    /// bound to the caller's invocation, and carrying the provider tag, drop
    /// count and cost the service derived.
    fn admits_result(&self, result: &TransportResult, claim: &ExecutionClaim) -> bool {
        let TransportDisposition::Transported { receipt, .. } = &result.disposition else {
            return false;
        };
        result.validate_against(&claim.invocation).is_ok()
            && receipt.provider == self.provider
            && receipt.foreign_reasoning_dropped == claim.call.receipt.foreign_reasoning_dropped
            && receipt.cost_micro_usd == claim.call.cost_of(&receipt.outcome)
            && receipt.overrun_micro_usd == claim.call.overrun_of(receipt.cost_micro_usd)
    }

    /// Where `caller_runtime_id`'s newest admission window starts, in unix
    /// milliseconds, or `None` when the caller has none: the instant the host
    /// clock must reach before a `ClockBehindAdmissionWindow` refusal can end.
    pub fn admission_window_start_unix_ms(&self, caller_runtime_id: &str) -> Option<u64> {
        let spend_window_ms = self.callers.get(caller_runtime_id)?.spend_window_ms;
        let newest = self
            .window_spend
            .get(caller_runtime_id)?
            .keys()
            .next_back()?;
        Some(newest.saturating_mul(spend_window_ms))
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
    cost_micro_usd: u64,
) -> TransportResult {
    let charge = Charge {
        cost_micro_usd,
        overrun_micro_usd: 0,
    };
    stand_in_failure(
        caller_runtime_id,
        request_id,
        model,
        native_request_sha256,
        provider_request_sha256,
        foreign_reasoning_dropped,
        FailureKind::ResultSize,
        charge,
    )
}

/// What a request cost, and by how much that exceeded its reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Charge {
    cost_micro_usd: u64,
    overrun_micro_usd: u64,
}

/// The stand-in failure for `kind`: `ResultSize` for a result that cannot be
/// carried, `Provider` for one the service refused.
// One argument per fact the stand-in repeats from the invocation it answers.
#[allow(clippy::too_many_arguments)]
fn stand_in_failure(
    caller_runtime_id: &str,
    request_id: &str,
    model: &str,
    native_request_sha256: [u8; 32],
    provider_request_sha256: [u8; 32],
    foreign_reasoning_dropped: u32,
    kind: FailureKind,
    charge: Charge,
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
                cost_micro_usd: charge.cost_micro_usd,
                overrun_micro_usd: charge.overrun_micro_usd,
                outcome: TransportOutcome::Failed {
                    kind,
                    message: message.to_string(),
                    usage: None,
                },
            }),
        },
    }
}

/// The one place foreignness is decided. A reasoning item of another provider
/// in the in-flight exchange (after the last user text; the whole input when
/// there is none) is refused, because dropping it would break the provider's
/// own tool-exchange rules. Earlier foreign items are removed and counted.
/// Foreignness is the provider tag alone: another model of this provider
/// passes through for the provider to judge.
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
                fixture_prices(),
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
        let conflicting = TransportInvocation::new(
            "epiphany-yggdrasil",
            2_000,
            [7; 32],
            MAX_COST,
            changed_request,
        )
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
                "fixture-sse",
                fixture_prices(),
                [CallerAdmission::new(
                    "epiphany-yggdrasil",
                    "rotated-connection-key",
                    2,
                    ["gpt-5.4".to_string()],
                    1,
                    64 * 1024,
                    32_768,
                    SpendCeiling(CEILING),
                    SpendWindowMs(WINDOW_MS)
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
            TransportInvocation::new(CALLER, 2_000, [7; 32], MAX_COST, request).unwrap();
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
                SpendCeiling(CEILING),
                SpendWindowMs(WINDOW_MS),
            )
            .unwrap();
            TransportService::open(
                &store.path,
                "fixture-sse",
                fixture_prices(),
                [admission],
                5_000,
            )
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
            state: ReplayState::Active {
                reserved_micro_usd: 1,
            },
            admitted_at_unix_ms: 1_000,
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
                fixture_prices(),
                [caller(CALLER, KEY, 1)],
                5_000
            )
            .is_ok()
        );

        type Edit = fn(&mut ReplayRecord);
        let cases: [(&str, Edit); 4] = [
            ("wrong-key", |_| {}),
            ("zero-digest", |record| record.invocation_sha256 = [0; 32]),
            ("zero-expiry", |record| record.expires_at_unix_ms = 0),
            ("zero-admission", |record| record.admitted_at_unix_ms = 0),
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
                        fixture_prices(),
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
            charged_micro_usd: 0,
            overrun_micro_usd: 0,
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
                SpendCeiling(CEILING),
                SpendWindowMs(WINDOW_MS),
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
        // ids plus the envelope's other fields is a ceiling.
        let floor = sealed.ciphertext.len() + id.len();
        let ceiling = 2 * (sealed.ciphertext.len() + 2 * id.len()) + 512;
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
        let size = encode_result_frame(&envelope).unwrap().len();
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
                FIXTURE_USAGE_COST,
            )
        );
        let TransportDisposition::Transported { receipt, .. } = &stand_in.disposition else {
            panic!("expected a transported failure");
        };
        assert_eq!(receipt.provider, "model-connector");

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
        let big = text_result(claim.call(), &"y".repeat(4000));
        let recorded = service.complete(*claim, big, FRAME).unwrap();
        assert!(encode_result_frame(&recorded).unwrap().len() > 2000);
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
                FIXTURE_USAGE_COST,
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
        let big = text_result(claim.call(), "y");
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
        let big = text_result(claim.call(), "y");
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
                        fixture_prices(),
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
                fixture_prices(),
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
                .begin(&raw_envelope(&invocation), 1_000, FRAME)
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
            FIXTURE_USAGE_COST,
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
            .begin(&raw_envelope(&invocation), 1_000, 2000)
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

    // ---- spend ----

    fn usage(input: u64, cache_read: u64, cache_write: u64, output: u64) -> Usage {
        Usage {
            input_tokens: input,
            cache_read_tokens: cache_read,
            cache_write_tokens: cache_write,
            output_tokens: output,
            reasoning_tokens: None,
        }
    }

    const MTOK: u64 = 1_000_000;

    fn flat_price(rate: u64) -> ModelPrice {
        ModelPrice {
            rates: Rates {
                input: rate,
                cache_write_short: rate,
                cache_write_long: rate,
                cache_read: rate,
                output: rate,
            },
            long_context: None,
            overhead_tokens: 0,
        }
    }

    fn dearest_input(rates: &Rates, retention: Option<CacheRetention>) -> u64 {
        let write = match retention {
            Some(CacheRetention::Short) => rates.cache_write_short,
            Some(CacheRetention::Long) | None => rates.cache_write_long,
        };
        rates.input.max(rates.cache_read).max(write)
    }

    /// ceil(((encoded length + overhead) x dearest input rate + max_output_tokens
    /// x output rate) / 1e6), spelled out apart from the service.
    fn expected_reservation(request: &ProviderRequest, rates: &Rates, overhead: u64) -> u64 {
        let bound = wire_encode(request).unwrap().len() as u128 + u128::from(overhead);
        let total = bound * u128::from(dearest_input(rates, request.cache_retention))
            + u128::from(request.max_output_tokens) * u128::from(rates.output);
        total.div_ceil(1_000_000) as u64
    }

    /// What every fixture request (request ids of one length) reserves.
    fn reservation() -> u64 {
        expected_reservation(&request(), &fixture_price().rates, 100)
    }

    fn invocation_at(request_id: &str, now: u64, max_cost: u64) -> TransportInvocation {
        let mut request = request();
        request.request_id = request_id.to_string();
        TransportInvocation::new(CALLER, now + 1_000, [7; 32], max_cost, request).unwrap()
    }

    fn begin_at(
        service: &mut TransportService,
        request_id: &str,
        now: u64,
        max_cost: u64,
    ) -> (TransportAdmission, TransportInvocation) {
        let invocation = invocation_at(request_id, now, max_cost);
        let admission = service
            .begin(&raw_envelope(&invocation), now, FRAME)
            .unwrap();
        (admission, invocation)
    }

    fn claim_at(service: &mut TransportService, request_id: &str, now: u64) -> Box<ExecutionClaim> {
        match begin_at(service, request_id, now, MAX_COST).0 {
            TransportAdmission::Execute(claim) => claim,
            TransportAdmission::Reply(_) => panic!("{request_id} should have executed"),
        }
    }

    fn refusal_at(
        service: &mut TransportService,
        request_id: &str,
        now: u64,
        max_cost: u64,
    ) -> Refusal {
        let (admission, invocation) = begin_at(service, request_id, now, max_cost);
        refusal_of(admission, &invocation)
    }

    fn open_limited(store: &TestStore, ceiling: u64, window_ms: u64) -> TransportService {
        TransportService::open(
            &store.path,
            "fixture-sse",
            fixture_prices(),
            [CallerAdmission::new(
                CALLER,
                KEY,
                1,
                ["gpt-5.4".to_string()],
                8,
                65_536,
                32_768,
                SpendCeiling(ceiling),
                SpendWindowMs(window_ms),
            )
            .unwrap()],
            5_000,
        )
        .unwrap()
    }

    fn record_of(service: &TransportService, request_id: &str) -> Option<ReplayRecord> {
        service
            .replay_store
            .get::<ReplayRecord>(&replay_key(&RequestIdentity {
                caller_runtime_id: CALLER.to_string(),
                request_id: request_id.to_string(),
            }))
            .unwrap()
    }

    fn charged_of(service: &TransportService, request_id: &str) -> u64 {
        match record_of(service, request_id).unwrap().state {
            ReplayState::Completed {
                charged_micro_usd, ..
            } => charged_micro_usd,
            ReplayState::Active { .. } => panic!("{request_id} is not completed"),
        }
    }

    fn receipt_of(
        response: &TransportEnvelope,
        invocation: &TransportInvocation,
    ) -> TransportReceipt {
        let TransportDisposition::Transported { receipt, .. } =
            decrypt_result(response, &security(KEY), invocation)
                .unwrap()
                .disposition
        else {
            panic!("expected a transported result");
        };
        *receipt
    }

    #[test]
    fn cost_prices_each_usage_class_at_its_own_rate() {
        let price = fixture_price();
        let cost = |usage: Usage| cost_micro_usd(&price, &usage, Some(CacheRetention::Long));
        assert_eq!(cost(usage(MTOK, 0, 0, 0)), 3_000_000);
        assert_eq!(cost(usage(0, MTOK, 0, 0)), 300_000);
        assert_eq!(cost(usage(0, 0, MTOK, 0)), 6_000_000);
        assert_eq!(cost(usage(0, 0, 0, MTOK)), 15_000_000);
        assert_eq!(
            cost(usage(2 * MTOK, 3 * MTOK, 5 * MTOK, 7 * MTOK)),
            6_000_000 + 900_000 + 30_000_000 + 105_000_000
        );
        // Reasoning tokens are a detail of the output tokens, never priced apart.
        let mut reasoning_only = usage(0, 0, 0, 0);
        reasoning_only.reasoning_tokens = Some(MTOK);
        assert_eq!(cost(reasoning_only), 0);
        let mut detailed = usage(0, 0, 0, MTOK);
        detailed.reasoning_tokens = Some(MTOK);
        assert_eq!(cost(detailed), 15_000_000);
    }

    #[test]
    fn cost_rounds_up_once_per_request() {
        let price = flat_price(10_000);
        let cost = |usage: Usage| cost_micro_usd(&price, &usage, None);
        assert_eq!(cost(usage(0, 1, 0, 0)), 1);
        assert_eq!(cost(usage(0, 0, 0, 0)), 0);
        // Four classes at one token each: 40,000 / 1e6 rounds up once, to 1.
        assert_eq!(cost(usage(1, 1, 1, 1)), 1);
        assert_eq!(cost(usage(100, 0, 0, 0)), 1);
        assert_eq!(cost(usage(101, 0, 0, 0)), 2);
    }

    #[test]
    fn cache_writes_price_by_retention() {
        let price = fixture_price();
        let written = usage(0, 0, MTOK, 0);
        assert_eq!(
            cost_micro_usd(&price, &written, Some(CacheRetention::Short)),
            3_750_000
        );
        assert_eq!(
            cost_micro_usd(&price, &written, Some(CacheRetention::Long)),
            6_000_000
        );
        // A write nobody asked to keep short is priced dear.
        assert_eq!(cost_micro_usd(&price, &written, None), 6_000_000);
    }

    #[test]
    fn long_context_rates_apply_strictly_above_the_threshold() {
        let long = Rates {
            input: 9_000_000,
            cache_write_short: 9_500_000,
            cache_write_long: 12_000_000,
            cache_read: 900_000,
            output: 45_000_000,
        };
        let price = |above_prompt_tokens: u64, overhead_tokens: u64| ModelPrice {
            long_context: Some(LongContext {
                above_prompt_tokens,
                rates: long,
            }),
            overhead_tokens,
            ..fixture_price()
        };
        // Prompt tokens are input + cache reads + cache writes.
        let at_threshold = cost_micro_usd(&price(100, 0), &usage(1, 1, 98, 0), None);
        assert_eq!(at_threshold, 592); // 3e6 + 3e5 + 98 x 6e6 = 591.3e6, base rates
        let above = cost_micro_usd(&price(100, 0), &usage(1, 1, 99, 0), None);
        assert_eq!(above, 1198); // 9e6 + 9e5 + 99 x 12e6 = 1197.9e6, long rates
        assert_eq!(
            cost_micro_usd(&price(100, 0), &usage(100, 0, 0, 0), None),
            300
        );
        assert_eq!(
            cost_micro_usd(&price(100, 0), &usage(101, 0, 0, 0), None),
            909
        );

        // The reservation switches at the same strict threshold, on its byte bound.
        let request = request();
        let length = wire_encode(&request).unwrap().len() as u64;
        let bound = length + 7;
        assert_eq!(
            reservation_micro_usd(&price(bound, 7), &request)
                .unwrap()
                .unwrap(),
            expected_reservation(&request, &fixture_price().rates, 7)
        );
        assert_eq!(
            reservation_micro_usd(&price(bound - 1, 7), &request)
                .unwrap()
                .unwrap(),
            expected_reservation(&request, &long, 7)
        );
    }

    #[test]
    fn cost_saturates_instead_of_wrapping() {
        let price = fixture_price();
        for huge in [
            usage(u64::MAX, 0, 0, 0),
            usage(0, 0, u64::MAX, 0),
            usage(0, 0, 0, u64::MAX),
            usage(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        ] {
            assert_eq!(cost_micro_usd(&price, &huge, None), u64::MAX, "{huge:?}");
        }
        // A class that does not overflow is exact: 300,000 x u64::MAX / 1e6, rounded up.
        assert_eq!(
            cost_micro_usd(&price, &usage(0, u64::MAX, 0, 0), None),
            5_534_023_222_112_865_485
        );
    }

    #[test]
    fn reservation_is_the_byte_bound_plus_max_output() {
        let rate_sets = [
            (fixture_price().rates, 100),
            // The dearest input rate is a cache read here...
            (
                Rates {
                    input: 1_000_000,
                    cache_write_short: 2_000_000,
                    cache_write_long: 3_000_000,
                    cache_read: 8_000_000,
                    output: 5_000_000,
                },
                7,
            ),
            // ...and plain input here.
            (
                Rates {
                    input: 9_000_000,
                    cache_write_short: 1_000_000,
                    cache_write_long: 2_000_000,
                    cache_read: 3_000_000,
                    output: 4_000_000,
                },
                0,
            ),
        ];
        for (rates, overhead_tokens) in rate_sets {
            let price = ModelPrice {
                rates,
                long_context: None,
                overhead_tokens,
            };
            for retention in [
                None,
                Some(CacheRetention::Short),
                Some(CacheRetention::Long),
            ] {
                let mut request = request();
                request.cache_retention = retention;
                assert_eq!(
                    reservation_micro_usd(&price, &request).unwrap().unwrap(),
                    expected_reservation(&request, &rates, overhead_tokens),
                    "{rates:?} {retention:?}"
                );
            }
        }
        // More output costs at least its price, and the bound follows the encoding
        // (a wider integer is more bytes).
        let price = fixture_price();
        let mut reserved = Vec::new();
        for max_output_tokens in [1, 1_000, 1_001_000] {
            let mut request = request();
            request.max_output_tokens = max_output_tokens;
            let amount = reservation_micro_usd(&price, &request).unwrap().unwrap();
            assert_eq!(
                amount,
                expected_reservation(&request, &price.rates, 100),
                "{max_output_tokens}"
            );
            reserved.push(amount);
        }
        assert!(reserved[2] - reserved[1] >= 15_000_000);
    }

    #[test]
    fn worst_case_over_max_cost_is_refused_cost_bound_inclusively() {
        let store = TestStore::new();
        let mut service = open_service(&store, 1);
        let reserved = reservation();
        let (admission, _) = begin_at(&mut service, "request-1", 1_000, reserved);
        assert!(matches!(admission, TransportAdmission::Execute(_)));
        // The only slot is taken: a request refused for its cost is refused
        // for that, before the replay lookup and the capacity check.
        assert_eq!(
            refusal_at(&mut service, "request-2", 1_000, reserved - 1),
            Refusal::CostBound
        );
        assert!(record_of(&service, "request-2").is_none());
        assert_eq!(service.window_spend(CALLER, 0), reserved);
        assert_eq!(
            refusal_at(&mut service, "request-3", 1_000, reserved),
            Refusal::Capacity
        );
    }

    #[test]
    fn max_cost_zero_is_malformed() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        assert_eq!(
            refusal_at(&mut service, "request-1", 1_000, 0),
            Refusal::Malformed
        );
        assert!(record_of(&service, "request-1").is_none());
    }

    #[test]
    fn a_changed_max_cost_is_a_replay_conflict() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let claim = claim_at(&mut service, "request-1", 1_000);
        let result = text_result(claim.call(), "done");
        service.complete(*claim, result, FRAME).unwrap();
        assert_eq!(
            refusal_at(&mut service, "request-1", 1_000, MAX_COST + 1),
            Refusal::ReplayConflict
        );
    }

    #[test]
    fn spend_ceiling_refuses_inclusively_and_resets_next_window() {
        let reserved = reservation();
        let window = 10_000;
        let store = TestStore::new();
        let mut service = open_limited(&store, 2 * reserved, window);
        claim_at(&mut service, "request-1", 1_000);
        // Windows are aligned to the epoch: the last millisecond of window 0.
        claim_at(&mut service, "request-2", 9_999);
        assert_eq!(service.window_spend(CALLER, 0), 2 * reserved);
        assert_eq!(
            refusal_at(&mut service, "request-3", 9_999, MAX_COST),
            Refusal::SpendCeiling
        );
        assert!(record_of(&service, "request-3").is_none());
        // The first millisecond of window 1: the same request id is admitted.
        claim_at(&mut service, "request-3", 10_000);
        assert_eq!(service.window_spend(CALLER, 0), 2 * reserved);
        assert_eq!(service.window_spend(CALLER, 1), reserved);

        // One micro-USD below the two reservations refuses the second.
        let store = TestStore::new();
        let mut service = open_limited(&store, 2 * reserved - 1, window);
        claim_at(&mut service, "request-1", 1_000);
        assert_eq!(
            refusal_at(&mut service, "request-2", 1_000, MAX_COST),
            Refusal::SpendCeiling
        );
    }

    #[test]
    fn a_recorded_answer_replays_past_an_exhausted_ceiling() {
        let reserved = reservation();
        let store = TestStore::new();
        let mut service = open_limited(&store, reserved, 3_600_000);
        let (admission, _) = begin_at(&mut service, "request-1", 1_000, MAX_COST);
        let TransportAdmission::Execute(claim) = admission else {
            panic!("the first request fits the ceiling exactly");
        };
        let result = text_result(claim.call(), "done");
        let response = service.complete(*claim, result, FRAME).unwrap();
        // Spent 75 of a ceiling that holds one reservation: nothing else fits.
        assert_eq!(
            refusal_at(&mut service, "request-2", 1_000, MAX_COST),
            Refusal::SpendCeiling
        );
        // The recorded answer is replayed whatever the caller has left.
        let (replay, _) = begin_at(&mut service, "request-1", 1_000, MAX_COST);
        assert_eq!(replay, TransportAdmission::Reply(response));
    }

    #[test]
    fn settlement_replaces_the_reservation_with_the_charge() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let claim = claim_at(&mut service, "request-1", 1_000);
        assert_eq!(service.window_spend(CALLER, 0), reservation());
        let result = text_result(claim.call(), "done");
        service.complete(*claim, result, FRAME).unwrap();
        assert_eq!(service.window_spend(CALLER, 0), FIXTURE_USAGE_COST);
        assert_eq!(charged_of(&service, "request-1"), FIXTURE_USAGE_COST);
    }

    #[test]
    fn failed_with_usage_charges_usage_and_failed_without_keeps_the_reservation() {
        let failed = |usage: Option<Usage>| TransportOutcome::Failed {
            kind: FailureKind::Provider,
            message: "the provider refused".to_string(),
            usage,
        };
        let store = TestStore::new();
        let mut service = open_service(&store, 4);

        let claim = claim_at(&mut service, "request-1", 1_000);
        let result = claim
            .call()
            .transported(Vec::new(), failed(Some(usage(0, 0, 0, 0))));
        let invocation = invocation_at("request-1", 1_000, MAX_COST);
        let response = service.complete(*claim, result, FRAME).unwrap();
        assert_eq!(receipt_of(&response, &invocation).cost_micro_usd, 0);
        assert_eq!(charged_of(&service, "request-1"), 0);
        assert_eq!(service.window_spend(CALLER, 0), 0);

        let claim = claim_at(&mut service, "request-2", 1_000);
        let result = claim
            .call()
            .transported(Vec::new(), failed(Some(usage(MTOK, 0, 0, 0))));
        service.complete(*claim, result, FRAME).unwrap();
        assert_eq!(charged_of(&service, "request-2"), 3_000_000);

        let claim = claim_at(&mut service, "request-3", 1_000);
        let result = claim.call().transported(Vec::new(), failed(None));
        let invocation = invocation_at("request-3", 1_000, MAX_COST);
        let response = service.complete(*claim, result, FRAME).unwrap();
        assert_eq!(
            receipt_of(&response, &invocation).cost_micro_usd,
            reservation()
        );
        assert_eq!(charged_of(&service, "request-3"), reservation());
        assert_eq!(service.window_spend(CALLER, 0), 3_000_000 + reservation());
    }

    #[test]
    fn a_backend_cost_misreport_is_answered_with_the_stand_in() {
        let edits: [fn(u64) -> u64; 3] = [|cost| cost + 1, |cost| cost - 1, |_| 0];
        for (index, edit) in edits.into_iter().enumerate() {
            let store = TestStore::new();
            let mut service = open_service(&store, 4);
            let id = format!("request-{index}");
            let claim = claim_at(&mut service, &id, 1_000);
            let mut result = text_result(claim.call(), "done");
            let TransportDisposition::Transported { receipt, .. } = &mut result.disposition else {
                unreachable!();
            };
            receipt.cost_micro_usd = edit(receipt.cost_micro_usd);
            let invocation = invocation_at(&id, 1_000, MAX_COST);
            let response = service.complete(*claim, result, FRAME).unwrap();
            let receipt = receipt_of(&response, &invocation);
            assert_eq!(receipt.provider, STAND_IN_PROVIDER, "{index}");
            // A result the service refused is still billed what its usage costs.
            assert_eq!(receipt.cost_micro_usd, FIXTURE_USAGE_COST, "{index}");
            assert_eq!(charged_of(&service, &id), FIXTURE_USAGE_COST, "{index}");
            assert_eq!(
                service.window_spend(CALLER, 0),
                FIXTURE_USAGE_COST,
                "{index}"
            );
        }
    }

    #[test]
    fn result_size_stand_in_keeps_the_real_charge() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let claim = claim_at(&mut service, "request-1", 1_000);
        let big = text_result(claim.call(), &"y".repeat(4000));
        let invocation = invocation_at("request-1", 1_000, MAX_COST);
        let response = service.complete(*claim, big, 2000).unwrap();
        let receipt = receipt_of(&response, &invocation);
        assert_eq!(receipt.provider, STAND_IN_PROVIDER);
        assert_eq!(receipt.cost_micro_usd, FIXTURE_USAGE_COST);
        assert_eq!(charged_of(&service, "request-1"), FIXTURE_USAGE_COST);
        assert_eq!(service.window_spend(CALLER, 0), FIXTURE_USAGE_COST);

        // The replay path: a wide record re-measured at a smaller frame.
        let claim = claim_at(&mut service, "request-2", 1_000);
        let big = text_result(claim.call(), &"y".repeat(4000));
        service.complete(*claim, big, FRAME).unwrap();
        drop(service);
        let mut service = open_service(&store, 4);
        let invocation = invocation_at("request-2", 1_000, MAX_COST);
        let TransportAdmission::Reply(smaller) = service
            .begin(&raw_envelope(&invocation), 1_000, 2000)
            .unwrap()
        else {
            panic!("expected a replay");
        };
        let receipt = receipt_of(&smaller, &invocation);
        assert_eq!(receipt.provider, STAND_IN_PROVIDER);
        assert_eq!(receipt.cost_micro_usd, FIXTURE_USAGE_COST);
        assert_eq!(charged_of(&service, "request-2"), FIXTURE_USAGE_COST);
        assert_eq!(service.window_spend(CALLER, 0), 2 * FIXTURE_USAGE_COST);
    }

    #[test]
    fn a_ledger_write_failure_executes_nothing() {
        let refusing = FlakyStore::new(0);
        let healthy = refusing.reopened(5);
        let mut service = open_flaky(refusing);
        let invocation = invocation_for(CALLER, "request-1");
        assert!(matches!(
            service.begin(&raw_envelope(&invocation), 1_000, FRAME),
            Err(ServiceError::ReplayStore(_))
        ));
        assert_eq!(service.window_spend(CALLER, 0), 0);
        assert!(service.live.is_empty());
        assert!(record_of(&service, "request-1").is_none());
        drop(service);

        // Nothing was written, so the same ledger admits the request afresh.
        let mut service = open_flaky(healthy);
        claim_at(&mut service, "request-1", 1_000);
    }

    #[test]
    fn a_settle_write_failure_keeps_the_reservation_counted() {
        let one_write = FlakyStore::new(1);
        let restart = one_write.reopened(5);
        let mut service = open_flaky(one_write);
        let claim = claim_at(&mut service, "request-1", 1_000);
        let result = text_result(claim.call(), "done");
        assert!(matches!(
            service.complete(*claim, result, FRAME),
            Err(ServiceError::ReplayStore(_))
        ));
        assert_eq!(service.window_spend(CALLER, 0), reservation());
        assert!(matches!(
            record_of(&service, "request-1").unwrap().state,
            ReplayState::Active { .. }
        ));
        drop(service);

        // A restart bills the indeterminate request at its whole reservation.
        let service = open_flaky(restart);
        assert_eq!(service.window_spend(CALLER, 0), reservation());
    }

    #[test]
    fn restart_rederives_window_spend_from_the_records() {
        let reserved = reservation();
        let window = 10_000;
        let store = TestStore::new();
        let mut service = open_limited(&store, 1 << 40, window);
        // An earlier window: completed.
        let claim = claim_at(&mut service, "request-1", 1_000);
        let result = text_result(claim.call(), "done");
        service.complete(*claim, result, FRAME).unwrap();
        // The current window: one completed, one left Active by a crash.
        let claim = claim_at(&mut service, "request-2", 10_500);
        let result = text_result(claim.call(), "done");
        service.complete(*claim, result, FRAME).unwrap();
        claim_at(&mut service, "request-3", 10_600);
        drop(service);

        let mut service = open_limited(&store, FIXTURE_USAGE_COST + 2 * reserved, window);
        // Only the current window is kept: the earlier one is pruned.
        assert_eq!(service.window_spend(CALLER, 0), 0);
        assert_eq!(
            service.window_spend(CALLER, 1),
            FIXTURE_USAGE_COST + reserved
        );
        // The ceiling sees the rebuilt window: one more reservation fits it
        // exactly, and the next does not. The earlier window counts for nothing.
        claim_at(&mut service, "request-4", 11_000);
        assert_eq!(
            refusal_at(&mut service, "request-5", 11_100, MAX_COST),
            Refusal::SpendCeiling
        );
    }

    #[test]
    fn open_refuses_an_unpriced_model_and_admits_a_zero_price() {
        let store = TestStore::new();
        assert_eq!(
            TransportService::open(
                &store.path,
                "fixture-sse",
                PriceTable::from([("another-model".to_string(), fixture_price())]),
                [caller(CALLER, KEY, 1)],
                5_000,
            )
            .err(),
            Some(ServiceError::UnpricedModel("gpt-5.4".to_string()))
        );

        let free = PriceTable::from([("gpt-5.4".to_string(), flat_price(0))]);
        let mut service = TransportService::open(
            &store.path,
            "fixture-sse",
            free,
            [caller(CALLER, KEY, 1)],
            5_000,
        )
        .unwrap();
        let claim = claim_at(&mut service, "request-1", 1_000);
        assert_eq!(service.window_spend(CALLER, 0), 0);
        let result = text_result(claim.call(), "done");
        service.complete(*claim, result, FRAME).unwrap();
        assert_eq!(charged_of(&service, "request-1"), 0);
        assert_eq!(service.window_spend(CALLER, 0), 0);
    }

    #[test]
    fn a_ceiling_and_a_window_are_required_nonzero() {
        let admit = |ceiling: u64, window_ms: u64| {
            CallerAdmission::new(
                CALLER,
                KEY,
                1,
                ["gpt-5.4".to_string()],
                4,
                64 * 1024,
                32_768,
                SpendCeiling(ceiling),
                SpendWindowMs(window_ms),
            )
        };
        assert!(admit(1, 1).is_ok());
        assert!(matches!(admit(0, 1), Err(ServiceError::InvalidAdmission)));
        assert!(matches!(admit(1, 0), Err(ServiceError::InvalidAdmission)));
    }

    // ---- settle past the reservation, pruning, extremes ----

    fn overrun_result(call: &ProviderCall, text: &str) -> TransportResult {
        let mut outcome = receipt(&invocation_for(CALLER, "outcome")).outcome;
        let TransportOutcome::Completed { usage, .. } = &mut outcome else {
            unreachable!();
        };
        // 2 million output tokens at 15,000,000 per million: 30,000,000.
        *usage = self::usage(0, 0, 0, 2 * MTOK);
        call.transported(
            vec![TransportEvent {
                sequence: 0,
                payload: TransportEventPayload::TextDelta {
                    text: text.to_string(),
                },
            }],
            outcome,
        )
    }

    const OVERRUN_COST: u64 = 30_000_000;

    #[test]
    fn an_overrun_settles_at_the_true_cost_and_the_receipt_says_so() {
        let reserved = reservation();
        let store = TestStore::new();
        let mut service = open_limited(&store, 2 * reserved, 3_600_000);
        let claim = claim_at(&mut service, "request-1", 1_000);
        let result = overrun_result(claim.call(), "done");
        let invocation = invocation_at("request-1", 1_000, MAX_COST);
        let response = service.complete(*claim, result, FRAME).unwrap();
        let receipt = receipt_of(&response, &invocation);
        // The provider's own answer, not a stand-in, carrying the true cost
        // and the marker.
        assert_eq!(receipt.provider, "fixture-sse");
        assert_eq!(receipt.cost_micro_usd, OVERRUN_COST);
        assert_eq!(receipt.overrun_micro_usd, OVERRUN_COST - reserved);
        assert_eq!(charged_of(&service, "request-1"), OVERRUN_COST);
        assert_eq!(service.window_spend(CALLER, 0), OVERRUN_COST);
        // The ceiling holds for every later request in the window.
        assert_eq!(
            refusal_at(&mut service, "request-2", 1_000, MAX_COST),
            Refusal::SpendCeiling
        );
        // A result inside its reservation carries no marker.
        drop(service);
        let mut service = open_service(&store, 4);
        let claim = claim_at(&mut service, "request-3", 1_000);
        let result = text_result(claim.call(), "done");
        let invocation = invocation_at("request-3", 1_000, MAX_COST);
        let response = service.complete(*claim, result, FRAME).unwrap();
        assert_eq!(receipt_of(&response, &invocation).overrun_micro_usd, 0);
    }

    #[test]
    fn an_overrun_survives_the_result_size_stand_in_and_its_replay() {
        let reserved = reservation();
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let claim = claim_at(&mut service, "request-1", 1_000);
        let big = overrun_result(claim.call(), &"y".repeat(4000));
        let invocation = invocation_at("request-1", 1_000, MAX_COST);
        let response = service.complete(*claim, big, 2000).unwrap();
        let receipt = receipt_of(&response, &invocation);
        assert_eq!(receipt.provider, STAND_IN_PROVIDER);
        assert_eq!(receipt.cost_micro_usd, OVERRUN_COST);
        assert_eq!(receipt.overrun_micro_usd, OVERRUN_COST - reserved);

        let claim = claim_at(&mut service, "request-2", 1_000);
        let big = overrun_result(claim.call(), &"y".repeat(4000));
        service.complete(*claim, big, FRAME).unwrap();
        drop(service);
        let mut service = open_service(&store, 4);
        let invocation = invocation_at("request-2", 1_000, MAX_COST);
        let TransportAdmission::Reply(smaller) = service
            .begin(&raw_envelope(&invocation), 1_000, 2000)
            .unwrap()
        else {
            panic!("expected a replay");
        };
        let receipt = receipt_of(&smaller, &invocation);
        assert_eq!(receipt.provider, STAND_IN_PROVIDER);
        assert_eq!(receipt.cost_micro_usd, OVERRUN_COST);
        assert_eq!(receipt.overrun_micro_usd, OVERRUN_COST - reserved);
    }

    #[test]
    fn a_backend_overrun_misreport_is_answered_with_the_stand_in() {
        let reserved = reservation();
        for (index, overrun) in [1, 0].into_iter().enumerate() {
            let store = TestStore::new();
            let mut service = open_service(&store, 4);
            let id = format!("request-{index}");
            let claim = claim_at(&mut service, &id, 1_000);
            // The first result is inside its reservation and claims an overrun;
            // the second overran and claims none.
            let mut result = if index == 0 {
                text_result(claim.call(), "done")
            } else {
                overrun_result(claim.call(), "done")
            };
            let TransportDisposition::Transported { receipt, .. } = &mut result.disposition else {
                unreachable!();
            };
            receipt.overrun_micro_usd = overrun;
            let invocation = invocation_at(&id, 1_000, MAX_COST);
            let response = service.complete(*claim, result, FRAME).unwrap();
            let receipt = receipt_of(&response, &invocation);
            // The service prices the usage itself: the stand-in and the ledger
            // carry the true cost and the true overrun, whatever was claimed.
            let (cost, true_overrun) = if index == 0 {
                (FIXTURE_USAGE_COST, 0)
            } else {
                (OVERRUN_COST, OVERRUN_COST - reserved)
            };
            assert_eq!(receipt.provider, STAND_IN_PROVIDER, "{index}");
            assert_eq!(receipt.cost_micro_usd, cost, "{index}");
            assert_eq!(receipt.overrun_micro_usd, true_overrun, "{index}");
            assert_eq!(charged_of(&service, &id), cost, "{index}");
            assert_eq!(service.window_spend(CALLER, 0), cost, "{index}");
        }
    }

    #[test]
    fn the_window_map_stays_bounded_live_and_after_reopen() {
        let window = 10;
        let store = TestStore::new();
        let mut service = open_limited(&store, 1 << 40, window);
        let held =
            |service: &TransportService| service.window_spend.get(CALLER).map_or(0, |w| w.len());
        for index in 0..300u64 {
            let id = format!("request-{index}");
            let claim = claim_at(&mut service, &id, 1_000 + index * window);
            let result = text_result(claim.call(), "done");
            service.complete(*claim, result, FRAME).unwrap();
            assert_eq!(held(&service), 1, "{index}");
        }
        // A request still in flight keeps its own window until it settles.
        let early = claim_at(&mut service, "request-e", 1_000 + 300 * window);
        claim_at(&mut service, "request-l", 1_000 + 305 * window);
        assert_eq!(held(&service), 2);
        let result = text_result(early.call(), "done");
        service.complete(*early, result, FRAME).unwrap();
        assert_eq!(held(&service), 1);
        drop(service);
        let service = open_limited(&store, 1 << 40, window);
        assert_eq!(held(&service), 1);
        assert_eq!(
            service.window_spend(CALLER, 1_000 / window + 305),
            reservation()
        );
    }

    #[test]
    fn a_reservation_that_overflows_is_refused_cost_bound_not_wrapped() {
        for price in [
            ModelPrice {
                overhead_tokens: u64::MAX,
                ..flat_price(u64::MAX)
            },
            ModelPrice {
                overhead_tokens: u64::MAX,
                ..flat_price(1 << 40)
            },
        ] {
            assert_eq!(reservation_micro_usd(&price, &request()).unwrap(), None);
            let store = TestStore::new();
            let mut service = TransportService::open(
                &store.path,
                "fixture-sse",
                PriceTable::from([("gpt-5.4".to_string(), price)]),
                [caller(CALLER, KEY, 4)],
                5_000,
            )
            .unwrap();
            // Not even a caller that bounds its request at u64::MAX can afford it.
            assert_eq!(
                refusal_at(&mut service, "request-1", 1_000, u64::MAX),
                Refusal::CostBound
            );
            assert!(record_of(&service, "request-1").is_none());
        }
    }

    #[test]
    fn a_recorded_answer_replays_after_a_price_raise() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let (admission, _) = begin_at(&mut service, "request-1", 1_000, reservation());
        let TransportAdmission::Execute(claim) = admission else {
            panic!("expected an execution claim");
        };
        let result = text_result(claim.call(), "done");
        service.complete(*claim, result, FRAME).unwrap();
        drop(service);

        let mut dear = fixture_price();
        dear.rates.output *= 2;
        let mut service = TransportService::open(
            &store.path,
            "fixture-sse",
            PriceTable::from([("gpt-5.4".to_string(), dear)]),
            [caller(CALLER, KEY, 4)],
            5_000,
        )
        .unwrap();
        let (admission, invocation) = begin_at(&mut service, "request-1", 1_000, reservation());
        let TransportAdmission::Reply(response) = admission else {
            panic!("expected the recorded answer");
        };
        assert_eq!(
            receipt_of(&response, &invocation).cost_micro_usd,
            FIXTURE_USAGE_COST
        );
        // New work is still checked against today's prices.
        assert_eq!(
            refusal_at(&mut service, "request-2", 1_000, reservation()),
            Refusal::CostBound
        );
    }

    #[test]
    fn a_settle_write_failure_releases_the_slot_and_keeps_the_reservation() {
        let store = FlakyStore::new(1);
        let allowance = store.allowance();
        let mut service = open_flaky(store);
        let claim = claim_at(&mut service, "request-1", 1_000);
        let result = text_result(claim.call(), "done");
        assert!(matches!(
            service.complete(*claim, result, FRAME),
            Err(ServiceError::ReplayStore(_))
        ));
        assert!(service.live.is_empty());
        assert_eq!(service.window_spend(CALLER, 0), reservation());
        // The store recovers: the caller's only slot is free again, and the
        // unsettled request is told it is indeterminate, not in flight.
        allowance.store(5, std::sync::atomic::Ordering::SeqCst);
        claim_at(&mut service, "request-2", 1_000);
        assert_eq!(service.window_spend(CALLER, 0), 2 * reservation());
        let (admission, invocation) = begin_at(&mut service, "request-1", 1_000, MAX_COST);
        assert_eq!(refusal_of(admission, &invocation), Refusal::Indeterminate);
    }

    fn open_flaky(store: FlakyStore) -> TransportService {
        TransportService::with_store(
            store,
            "fixture-sse",
            fixture_prices(),
            [caller(CALLER, KEY, 1)],
            5_000,
        )
        .unwrap()
    }

    fn run_window(service: &mut TransportService, prefix: &str, now: u64) -> u32 {
        let mut admitted = 0;
        for i in 0..20u64 {
            let (admission, _) = begin_at(service, &format!("{prefix}-{i:02}"), now, MAX_COST);
            let TransportAdmission::Execute(claim) = admission else {
                break;
            };
            admitted += 1;
            let result = text_result(claim.call(), "done");
            service.complete(*claim, result, FRAME).unwrap();
        }
        admitted
    }

    #[test]
    fn a_clock_stepping_back_cannot_reopen_the_callers_budget() {
        let window = 10_000;
        // Room for the reservation plus two settled requests: three admitted.
        let ceiling = reservation() + 2 * FIXTURE_USAGE_COST;
        let control_store = TestStore::new();
        let mut control = open_limited(&control_store, ceiling, window);
        assert_eq!(run_window(&mut control, "back", 20_000), 3);

        let store = TestStore::new();
        let mut service = open_limited(&store, ceiling, window);
        let claim = claim_at(&mut service, "ahead", 50_000);
        let result = text_result(claim.call(), "done");
        service.complete(*claim, result, FRAME).unwrap();
        // The clock now reads window 2, behind the recorded window 5: the
        // request belongs to window 5, which already holds one.
        assert_eq!(run_window(&mut service, "back", 20_000), 2);
        assert_eq!(service.window_spend(CALLER, 5), 3 * FIXTURE_USAGE_COST);
        assert_eq!(service.window_spend(CALLER, 2), 0);
        drop(service);

        let mut service = open_limited(&store, ceiling, window);
        assert_eq!(service.window_spend(CALLER, 5), 3 * FIXTURE_USAGE_COST);
        assert_eq!(run_window(&mut service, "again", 20_100), 0);
        assert_eq!(
            refusal_at(&mut service, "last", 20_200, MAX_COST),
            Refusal::ClockBehindAdmissionWindow
        );
    }

    #[test]
    fn a_clock_jumping_forward_opens_a_fresh_window() {
        let window = 10_000;
        let ceiling = reservation() + 2 * FIXTURE_USAGE_COST;
        let store = TestStore::new();
        let mut service = open_limited(&store, ceiling, window);
        assert_eq!(run_window(&mut service, "early", 20_000), 3);
        assert_eq!(run_window(&mut service, "later", 90_000), 3);
        assert_eq!(service.window_spend(CALLER, 9), 3 * FIXTURE_USAGE_COST);
        assert_eq!(service.window_spend(CALLER, 2), 0);
    }

    /// Hand-written rates: the long tier is cheaper on input and dearer on
    /// output, so neither tier alone bounds both.
    fn mixed_long_tier(above_prompt_tokens: u64) -> ModelPrice {
        ModelPrice {
            rates: Rates {
                input: 3_000_000,
                cache_write_short: 3_750_000,
                cache_write_long: 6_000_000,
                cache_read: 300_000,
                output: 15_000_000,
            },
            long_context: Some(LongContext {
                above_prompt_tokens,
                rates: Rates {
                    input: 1_000_000,
                    cache_write_short: 1_250_000,
                    cache_write_long: 2_000_000,
                    cache_read: 100_000,
                    output: 30_000_000,
                },
            }),
            overhead_tokens: 100,
        }
    }

    #[test]
    fn the_reservation_is_the_dearer_of_both_tiers_class_by_class() {
        let request = request();
        let bound = wire_encode(&request).unwrap().len() as u64 + 100;
        // Above the threshold: input at the base tier's dearer rate, output at
        // the long tier's.
        let dearest = Rates {
            input: 3_000_000,
            cache_write_short: 3_750_000,
            cache_write_long: 6_000_000,
            cache_read: 300_000,
            output: 30_000_000,
        };
        assert_eq!(
            reservation_micro_usd(&mixed_long_tier(bound - 1), &request).unwrap(),
            Some(expected_reservation(&request, &dearest, 100))
        );
        // At the threshold the base tier alone applies.
        assert_eq!(
            reservation_micro_usd(&mixed_long_tier(bound), &request).unwrap(),
            Some(expected_reservation(&request, &fixture_price().rates, 100))
        );
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_rates(state: &mut u64) -> Rates {
        Rates {
            input: xorshift(state) % 50_000_000,
            cache_write_short: xorshift(state) % 50_000_000,
            cache_write_long: xorshift(state) % 50_000_000,
            cache_read: xorshift(state) % 50_000_000,
            output: xorshift(state) % 200_000_000,
        }
    }

    #[test]
    fn the_property_test_generator_is_xorshift64_within_the_rate_bounds() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let first: Vec<u64> = (0..3).map(|_| xorshift(&mut s)).collect();
        assert_eq!(
            first,
            [0xdc1b77ae0bf34dad, 0x64f0eeb9026e6076, 0x7b07ce91e5906136]
        );
        for _ in 0..200 {
            let rates = random_rates(&mut s);
            for (rate, bound) in [
                (rates.input, 50_000_000),
                (rates.cache_write_short, 50_000_000),
                (rates.cache_write_long, 50_000_000),
                (rates.cache_read, 50_000_000),
                (rates.output, 200_000_000),
            ] {
                assert!(rate < bound);
            }
        }
    }

    /// Any usage within the bound the reservation assumes (prompt tokens no
    /// more than encoded bytes plus overhead, output no more than the cap)
    /// costs no more than the reservation, whatever the price shape.
    #[test]
    fn no_usage_within_the_bound_prices_above_the_reservation() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..5_000 {
            let mut request = request();
            request.max_output_tokens = (xorshift(&mut s) % 100_000) as u32;
            request.cache_retention = match xorshift(&mut s) % 3 {
                0 => None,
                1 => Some(CacheRetention::Short),
                _ => Some(CacheRetention::Long),
            };
            request.instructions = "x".repeat((xorshift(&mut s) % 3000) as usize);
            let overhead = xorshift(&mut s) % 5_000;
            let bound = wire_encode(&request).unwrap().len() as u64 + overhead;
            let long_context = (xorshift(&mut s).is_multiple_of(2)).then(|| LongContext {
                above_prompt_tokens: xorshift(&mut s) % (2 * bound + 1),
                rates: random_rates(&mut s),
            });
            let price = ModelPrice {
                rates: random_rates(&mut s),
                long_context,
                overhead_tokens: overhead,
            };
            let reserved = reservation_micro_usd(&price, &request).unwrap().unwrap();
            let prompt = if xorshift(&mut s).is_multiple_of(4) {
                bound
            } else {
                xorshift(&mut s) % (bound + 1)
            };
            let a = xorshift(&mut s) % (prompt + 1);
            let b = xorshift(&mut s) % (prompt - a + 1);
            let max_output = u64::from(request.max_output_tokens);
            let output = if xorshift(&mut s).is_multiple_of(4) {
                max_output
            } else {
                xorshift(&mut s) % (max_output + 1)
            };
            let cost = cost_micro_usd(
                &price,
                &usage(a, b, prompt - a - b, output),
                request.cache_retention,
            );
            assert!(
                cost <= reserved,
                "{price:?} {a} {b} {output}: {cost} > {reserved}"
            );
        }
    }

    #[test]
    fn another_callers_live_request_does_not_keep_this_callers_old_window() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        // Ghostlight holds a request live in window 0 throughout.
        let other = invocation_for("ghostlight-yggdrasil", "request-1");
        let envelope =
            encrypt_invocation(&other, &security("ghostlight-distinct-test-key")).unwrap();
        let TransportAdmission::Execute(_held) = service.begin(&envelope, 1_000, FRAME).unwrap()
        else {
            panic!("ghostlight should have executed");
        };
        for (id, now) in [("first", 1_000), ("second", WINDOW_MS + 1_000)] {
            let claim = claim_at(&mut service, id, now);
            let result = text_result(claim.call(), "done");
            service.complete(*claim, result, FRAME).unwrap();
        }
        assert_eq!(service.window_spend(CALLER, 0), 0);
        assert_eq!(service.window_spend(CALLER, 1), FIXTURE_USAGE_COST);
        assert_eq!(
            service.window_spend("ghostlight-yggdrasil", 0),
            reservation()
        );
    }

    #[test]
    fn a_result_bound_to_another_request_is_charged_the_reservation() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let one = claim_at(&mut service, "request-1", 1_000);
        let two = claim_at(&mut service, "request-2", 1_000);
        // request-2's result reports no usage at all; request-1 must not be
        // billed what another request's backend claims to have spent.
        let foreign = two.call().transported(
            Vec::new(),
            TransportOutcome::Failed {
                kind: FailureKind::Provider,
                message: String::new(),
                usage: Some(usage(0, 0, 0, 0)),
            },
        );
        let invocation = invocation_at("request-1", 1_000, MAX_COST);
        let response = service.complete(*one, foreign, FRAME).unwrap();
        assert_eq!(
            receipt_of(&response, &invocation).provider,
            STAND_IN_PROVIDER
        );
        assert_eq!(charged_of(&service, "request-1"), reservation());
        // request-1 is charged the reservation; request-2 still holds its own.
        assert_eq!(service.window_spend(CALLER, 0), 2 * reservation());
        drop(two);
    }

    #[test]
    fn a_result_that_is_not_transported_is_charged_the_reservation() {
        let store = TestStore::new();
        let mut service = open_service(&store, 4);
        let claim = claim_at(&mut service, "request-1", 1_000);
        let invocation = invocation_at("request-1", 1_000, MAX_COST);
        let refused = TransportResult::refused(&invocation, Refusal::Capacity);
        service.complete(*claim, refused, FRAME).unwrap();
        assert_eq!(charged_of(&service, "request-1"), reservation());
        assert_eq!(service.window_spend(CALLER, 0), reservation());
    }

    #[test]
    fn a_stepped_back_clock_admits_into_the_newest_window_not_an_older_live_one() {
        let window = 10_000;
        // Two live reservations fill window 9 (the newest); one live
        // reservation leaves window 2 (older, still held) room for another.
        // Request ids share a length, so every reservation is the same size.
        let ceiling = reservation() + reservation() + reservation() / 2;
        let store = TestStore::new();
        let mut service = open_limited(&store, ceiling, window);
        let old = claim_at(&mut service, "request-a", 20_000);
        let newest = [
            claim_at(&mut service, "request-b", 90_000),
            claim_at(&mut service, "request-c", 90_000),
        ];
        assert_eq!(service.window_spend(CALLER, 2), reservation());
        assert_eq!(service.window_spend(CALLER, 9), 2 * reservation());
        // The clock reads window 2 again. Window 2 would hold the request;
        // the caller's window is the newest, which cannot.
        assert_eq!(
            refusal_at(&mut service, "request-d", 20_500, MAX_COST),
            Refusal::ClockBehindAdmissionWindow
        );
        assert_eq!(service.window_spend(CALLER, 2), reservation());
        assert_eq!(service.window_spend(CALLER, 9), 2 * reservation());
        drop((old, newest));
    }

    #[test]
    fn a_clock_behind_the_callers_window_is_refused_by_name_until_it_catches_up() {
        let window = 10_000;
        let ceiling = reservation() + 2 * FIXTURE_USAGE_COST;
        let store = TestStore::new();
        let mut service = open_limited(&store, ceiling, window);
        assert_eq!(service.admission_window_start_unix_ms(CALLER), None);
        assert_eq!(run_window(&mut service, "fill", 50_000), 3);
        assert_eq!(
            service.admission_window_start_unix_ms(CALLER),
            Some(50_000)
        );
        // Behind the full window: the cause is named, no slot is taken and
        // nothing is reserved.
        assert_eq!(
            refusal_at(&mut service, "behind", 20_000, MAX_COST),
            Refusal::ClockBehindAdmissionWindow
        );
        assert!(service.live.is_empty());
        assert_eq!(service.window_spend(CALLER, 5), 3 * FIXTURE_USAGE_COST);
        // Inside the full window the clock is not behind: an honest ceiling.
        assert_eq!(
            refusal_at(&mut service, "inside", 50_500, MAX_COST),
            Refusal::SpendCeiling
        );
        // Once the clock reaches the next window the caller is admitted.
        assert_eq!(run_window(&mut service, "later", 60_000), 3);
    }

    #[test]
    fn the_clock_behind_refusal_is_no_wider_than_the_widest_other_refusal() {
        let invocation = invocation_at("request-1", 1_000, MAX_COST);
        let sized = |refusal| {
            wire_encode(&TransportResult::refused(&invocation, refusal))
                .unwrap()
                .len()
        };
        assert!(
            sized(Refusal::ClockBehindAdmissionWindow)
                <= sized(Refusal::ProviderDigestSubstitution)
        );
    }
}
