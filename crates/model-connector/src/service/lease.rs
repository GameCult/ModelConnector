//! A credential lease: a Self run's or a Persona turn's reservation in the caller's spend window.
//! The lease is one record of the same ledger a provider call reserves in, not
//! a second ledger: it is claimed before anything is lent, counts against the
//! window's ceiling while open, and settles to the true cost of what the run
//! reports it used, per model and uncapped: a charge above the reservation is
//! kept as the lease's overrun, and still counts against the window. A lease
//! nothing settled is billed the whole reservation, as a call a crash left
//! behind is.

use super::*;

/// The request-id namespace of leases in a caller's replay records.
const LEASE_PREFIX: &str = "lease:";

/// The most leases one Persona invocation may take in its life.
const MAX_PERSONA_LEASES: u32 = 1024;

/// Room kept in an identity for `:<n>`, `n` at most `MAX_PERSONA_LEASES`.
const SEQUENCE_SUFFIX_BYTES: usize = 5;

/// Which kind of turn a lease serves. It is a property of the lease caller's
/// configured row, never of a request. A Self run leases once per unit
/// invocation; a Persona turn leases once per turn, so one live invocation
/// leases in sequence, one open lease at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseTurn {
    SelfRun,
    PersonaTurn,
}

/// What an admitted lease holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGrant {
    pub lease_id: String,
    pub reserved_micro_usd: u64,
}

/// What a run used of one model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelUsage {
    pub model: String,
    pub usage: Usage,
}

/// What a settled lease was billed. `overrun_micro_usd` is how far the charge
/// passed the reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseSettlement {
    pub billed_micro_usd: u64,
    pub overrun_micro_usd: u64,
}

/// What a lease's settlement is billed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseUse<'a> {
    /// No report: the whole reservation. A run that cannot say what it used
    /// pays what was set aside for it.
    Reservation,
    /// The run's report. A report that names no use (an empty list) is no
    /// report, and bills the reservation.
    Reported(&'a [ModelUsage]),
    /// The token was never lent, so nothing was used and nothing is billed.
    NeverLent,
}

/// What `usage` costs at the table's prices: each entry at its model's price,
/// and a model with no price at the dearest price the table holds, so an
/// unknown name never bills less than any known one. `None` when the table
/// prices nothing.
fn lease_cost(prices: &PriceTable, usage: &[ModelUsage]) -> Option<u64> {
    let dearest = |usage: &Usage| {
        prices
            .values()
            .map(|price| cost_micro_usd(price, usage, None))
            .max()
    };
    usage
        .iter()
        .map(|entry| match prices.get(&entry.model) {
            Some(price) => Some(cost_micro_usd(price, &entry.usage, None)),
            None => dearest(&entry.usage),
        })
        .try_fold(0_u64, |total, cost| Some(total.saturating_add(cost?)))
}

/// Why no lease was reserved. Nothing was written to the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRefusal {
    /// The window's spend plus open reservations plus this one passes the
    /// caller's ceiling.
    SpendCeiling,
    /// The reservation asked for is zero: a lease that bills nothing is a
    /// free pass.
    CostBound,
    UnknownCaller,
    /// A Self run: the caller holds a Self lease already, or this invocation
    /// leased before. A Persona turn: this invocation holds a lease now.
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseAdmission {
    Granted(LeaseGrant),
    Refused(LeaseRefusal),
}

impl TransportService {
    /// Reserves `max_cost_micro_usd` in `caller_runtime_id`'s current window
    /// for the unit invocation `invocation_id`. A Self run leases once per
    /// invocation, as `lease:<invocation>`, and one Self lease is open per
    /// caller. A Persona turn takes the next free sequence of its invocation
    /// as `lease:<invocation>:<n>`, one open at a time; a Persona lease never
    /// blocks or is blocked by the caller's Self lease. A ledger that cannot
    /// be written answers `Err` and reserves nothing. A lease takes no
    /// request slot.
    pub fn begin_lease(
        &mut self,
        caller_runtime_id: &str,
        turn: LeaseTurn,
        invocation_id: &str,
        max_cost_micro_usd: u64,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<LeaseAdmission, ServiceError> {
        let Some(caller) = self.callers.get(caller_runtime_id) else {
            return Ok(LeaseAdmission::Refused(LeaseRefusal::UnknownCaller));
        };
        let spend_ceiling = caller.spend_ceiling_micro_usd;
        let spend_window_ms = caller.spend_window_ms;
        let connection_key_epoch = caller.connection_key_epoch;
        require_id(invocation_id, "invocation_id")?;
        if invocation_id.len() + LEASE_PREFIX.len() + SEQUENCE_SUFFIX_BYTES > MAX_IDENTITY_BYTES {
            return Err(ContractError::Invalid("invocation_id").into());
        }
        if max_cost_micro_usd == 0 {
            return Ok(LeaseAdmission::Refused(LeaseRefusal::CostBound));
        }
        let identity = match turn {
            LeaseTurn::SelfRun => {
                let identity = RequestIdentity {
                    caller_runtime_id: caller_runtime_id.to_string(),
                    request_id: format!("{LEASE_PREFIX}{invocation_id}"),
                };
                let holding = self.live.iter().any(|(held, request)| {
                    request.lease == Some(LeaseTurn::SelfRun)
                        && held.caller_runtime_id == caller_runtime_id
                });
                if holding
                    || self
                        .replay_store
                        .get::<ReplayRecord>(&replay_key(&identity))
                        .map_err(replay_store_error)?
                        .is_some()
                {
                    return Ok(LeaseAdmission::Refused(LeaseRefusal::Busy));
                }
                identity
            }
            LeaseTurn::PersonaTurn => {
                let mut free = None;
                for sequence in 1..=MAX_PERSONA_LEASES {
                    let identity = RequestIdentity {
                        caller_runtime_id: caller_runtime_id.to_string(),
                        request_id: format!("{LEASE_PREFIX}{invocation_id}:{sequence}"),
                    };
                    if self.live.contains_key(&identity) {
                        return Ok(LeaseAdmission::Refused(LeaseRefusal::Busy));
                    }
                    if self
                        .replay_store
                        .get::<ReplayRecord>(&replay_key(&identity))
                        .map_err(replay_store_error)?
                        .is_none()
                    {
                        free = Some(identity);
                        break;
                    }
                }
                let Some(identity) = free else {
                    return Ok(LeaseAdmission::Refused(LeaseRefusal::Busy));
                };
                identity
            }
        };
        let key = replay_key(&identity);
        let admitted_at_unix_ms = admission_clock(
            &self.window_spend,
            caller_runtime_id,
            now_unix_ms,
            spend_window_ms,
        );
        let window = admitted_at_unix_ms / spend_window_ms;
        prune_windows(
            &mut self.window_spend,
            &self.live,
            caller_runtime_id,
            window,
        );
        if self
            .window_spend(caller_runtime_id, window)
            .saturating_add(max_cost_micro_usd)
            > spend_ceiling
        {
            return Ok(LeaseAdmission::Refused(LeaseRefusal::SpendCeiling));
        }
        let mut digest = Sha256::new();
        digest.update(b"claude_lease_request");
        digest.update((invocation_id.len() as u64).to_be_bytes());
        digest.update(invocation_id.as_bytes());
        digest.update(max_cost_micro_usd.to_be_bytes());
        digest.update(expires_at_unix_ms.to_be_bytes());
        let record = ReplayRecord {
            caller_runtime_id: caller_runtime_id.to_string(),
            request_id: identity.request_id.clone(),
            connection_key_epoch,
            invocation_sha256: digest.finalize().into(),
            expires_at_unix_ms,
            state: ReplayState::Active {
                reserved_micro_usd: max_cost_micro_usd,
            },
            admitted_at_unix_ms,
        };
        // Reserving and claiming are one write, as for a call: a ledger that
        // cannot be written lends nothing.
        self.replay_store
            .put(key, &record)
            .map_err(replay_store_error)?;
        add_spend(
            &mut self.window_spend,
            caller_runtime_id,
            window,
            0,
            max_cost_micro_usd,
        );
        let lease_id = identity.request_id.clone();
        self.live.insert(
            identity,
            LiveRequest {
                window,
                reserved_micro_usd: max_cost_micro_usd,
                lease: Some(turn),
            },
        );
        Ok(LeaseAdmission::Granted(LeaseGrant {
            lease_id,
            reserved_micro_usd: max_cost_micro_usd,
        }))
    }

    /// Settles an open lease and returns what it was billed. A report bills
    /// the true cost of every model's reported use, uncapped (the overrun is
    /// recorded); no report, or an empty one, bills the whole reservation;
    /// only a token never lent bills nothing. A failed ledger
    /// write frees the caller's lease and keeps the reservation counted, as a
    /// call's does.
    pub fn settle_lease(
        &mut self,
        caller_runtime_id: &str,
        lease_id: &str,
        usage: LeaseUse<'_>,
    ) -> Result<LeaseSettlement, ServiceError> {
        let identity = RequestIdentity {
            caller_runtime_id: caller_runtime_id.to_string(),
            request_id: lease_id.to_string(),
        };
        if self
            .live
            .get(&identity)
            .is_none_or(|request| request.lease.is_none())
        {
            return Err(ServiceError::NoActiveRequest);
        }
        let key = replay_key(&identity);
        let active = self
            .replay_store
            .get::<ReplayRecord>(&key)
            .map_err(replay_store_error)?
            .ok_or(ServiceError::NoActiveRequest)?;
        let ReplayState::Active { reserved_micro_usd } = active.state else {
            return Err(ServiceError::ActiveRequestMismatch);
        };
        let caller = self
            .callers
            .get(caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        let spend_window_ms = caller.spend_window_ms;
        let charged_micro_usd = match usage {
            LeaseUse::Reservation | LeaseUse::Reported([]) => reserved_micro_usd,
            LeaseUse::NeverLent => 0,
            LeaseUse::Reported(usage) => {
                lease_cost(&self.prices, usage).unwrap_or(reserved_micro_usd)
            }
        };
        let overrun_micro_usd = charged_micro_usd.saturating_sub(reserved_micro_usd);
        let settled = ReplayRecord {
            state: ReplayState::LeaseSettled {
                charged_micro_usd,
                overrun_micro_usd,
            },
            ..active.clone()
        };
        self.replay_store
            .put(key, &settled)
            .map_err(replay_store_error)
            .inspect_err(|_| {
                self.live.remove(&identity);
            })?;
        add_spend(
            &mut self.window_spend,
            caller_runtime_id,
            active.admitted_at_unix_ms / spend_window_ms,
            reserved_micro_usd,
            charged_micro_usd,
        );
        self.live.remove(&identity);
        prune_to_latest(&mut self.window_spend, &self.live, caller_runtime_id);
        Ok(LeaseSettlement {
            billed_micro_usd: charged_micro_usd,
            overrun_micro_usd,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::fixtures::*;

    const CALLER: &str = "eureka";
    const KEY: &str = "lease-distinct-test-key";
    const NOW: u64 = 7_200_500;

    fn open_with(store: impl CacheBackingStore + 'static, ceiling: u64) -> TransportService {
        TransportService::with_store(
            store,
            "fixture-sse",
            fixture_prices(),
            [CallerAdmission::new(
                CALLER,
                KEY,
                1,
                ["gpt-5.4".to_string()],
                1,
                65_536,
                32_768,
                SpendCeiling(ceiling),
                SpendWindowMs(WINDOW_MS),
            )
            .unwrap()],
            5_000,
        )
        .unwrap()
    }

    fn open(store: &TestStore, ceiling: u64) -> TransportService {
        TransportService::open(
            &store.path,
            "fixture-sse",
            fixture_prices(),
            [CallerAdmission::new(
                CALLER,
                KEY,
                1,
                ["gpt-5.4".to_string()],
                1,
                65_536,
                32_768,
                SpendCeiling(ceiling),
                SpendWindowMs(WINDOW_MS),
            )
            .unwrap()],
            5_000,
        )
        .unwrap()
    }

    fn lease(service: &mut TransportService, run: &str, cost: u64) -> LeaseAdmission {
        service
            .begin_lease(CALLER, LeaseTurn::SelfRun, run, cost, NOW + 60_000, NOW)
            .unwrap()
    }

    fn granted(admission: LeaseAdmission) -> LeaseGrant {
        match admission {
            LeaseAdmission::Granted(grant) => grant,
            LeaseAdmission::Refused(why) => panic!("refused {why:?}"),
        }
    }

    fn held(service: &TransportService) -> u64 {
        service.window_spend(CALLER, NOW / WINDOW_MS)
    }

    fn output(tokens: u64) -> Vec<ModelUsage> {
        used("gpt-5.4", tokens)
    }

    fn used(model: &str, tokens: u64) -> Vec<ModelUsage> {
        vec![ModelUsage {
            model: model.to_string(),
            usage: Usage {
                input_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                output_tokens: tokens,
                reasoning_tokens: None,
            },
        }]
    }

    fn billed(settlement: LeaseSettlement) -> u64 {
        settlement.billed_micro_usd
    }

    #[test]
    fn a_lease_reserves_in_the_callers_window_and_names_what_it_holds() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000);
        let grant = granted(lease(&mut service, "run-1", 600));
        assert_eq!(grant.reserved_micro_usd, 600);
        assert_eq!(held(&service), 600);
        assert_eq!(
            billed(
                service
                    .settle_lease(CALLER, &grant.lease_id, LeaseUse::Reservation)
                    .unwrap()
            ),
            600
        );
    }

    #[test]
    fn the_window_ceiling_counts_open_and_settled_reservations_inclusively() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000);
        let first = granted(lease(&mut service, "run-1", 600));
        service
            .settle_lease(CALLER, &first.lease_id, LeaseUse::Reservation)
            .unwrap();
        assert_eq!(
            lease(&mut service, "run-2", 401),
            LeaseAdmission::Refused(LeaseRefusal::SpendCeiling)
        );
        assert_eq!(held(&service), 600);
        granted(lease(&mut service, "run-3", 400));
        assert_eq!(held(&service), 1_000);
    }

    #[test]
    fn a_caller_holds_one_lease_at_a_time_and_an_invocation_id_is_leased_once() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000_000);
        let first = granted(lease(&mut service, "run-1", 100));
        assert_eq!(
            lease(&mut service, "run-2", 100),
            LeaseAdmission::Refused(LeaseRefusal::Busy)
        );
        service
            .settle_lease(CALLER, &first.lease_id, LeaseUse::Reservation)
            .unwrap();
        assert_eq!(
            lease(&mut service, "run-1", 100),
            LeaseAdmission::Refused(LeaseRefusal::Busy)
        );
        granted(lease(&mut service, "run-2", 100));
    }

    #[test]
    fn a_stranger_and_a_free_lease_are_refused_without_a_ledger_write() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000);
        assert_eq!(
            service
                .begin_lease("stranger", LeaseTurn::SelfRun, "run-1", 100, NOW + 1, NOW)
                .unwrap(),
            LeaseAdmission::Refused(LeaseRefusal::UnknownCaller)
        );
        assert_eq!(
            lease(&mut service, "run-1", 0),
            LeaseAdmission::Refused(LeaseRefusal::CostBound)
        );
        assert_eq!(held(&service), 0);
        // Nothing was claimed: the same run id leases once it asks sensibly.
        granted(lease(&mut service, "run-1", 100));
    }

    #[test]
    fn settlement_bills_the_true_cost_uncapped_and_records_the_overrun() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000_000);
        // Output at 15 USD per million tokens: 10 tokens bill 150 micro-USD.
        let small = granted(lease(&mut service, "run-1", 10_000));
        let settled = service
            .settle_lease(CALLER, &small.lease_id, LeaseUse::Reported(&output(10)[..]))
            .unwrap();
        assert_eq!(
            (settled.billed_micro_usd, settled.overrun_micro_usd),
            (150, 0)
        );
        assert_eq!(held(&service), 150);
        // 1000 tokens bill 15_000: the reservation does not cap it, and the
        // 5_000 past it is recorded as the overrun.
        let big = granted(lease(&mut service, "run-2", 10_000));
        let settled = service
            .settle_lease(
                CALLER,
                &big.lease_id,
                LeaseUse::Reported(&output(1_000)[..]),
            )
            .unwrap();
        assert_eq!(
            (settled.billed_micro_usd, settled.overrun_micro_usd),
            (15_000, 5_000)
        );
        assert_eq!(held(&service), 15_150);
    }

    #[test]
    fn settlement_prices_each_model_at_its_own_rate_and_an_unknown_model_at_the_dearest() {
        let store = TestStore::new();
        let cheap = ModelPrice {
            rates: Rates {
                input: 1_000_000,
                cache_write_short: 1_000_000,
                cache_write_long: 1_000_000,
                cache_read: 1_000_000,
                output: 2_000_000,
            },
            ..fixture_price()
        };
        let prices = PriceTable::from([
            ("gpt-5.4".to_string(), fixture_price()),
            ("cheap".to_string(), cheap),
        ]);
        let mut service = TransportService::open(
            &store.path,
            "fixture-sse",
            prices,
            [CallerAdmission::new(
                CALLER,
                KEY,
                1,
                ["gpt-5.4".to_string()],
                1,
                65_536,
                32_768,
                SpendCeiling(1_000_000),
                SpendWindowMs(WINDOW_MS),
            )
            .unwrap()],
            5_000,
        )
        .unwrap();
        let mixed: Vec<ModelUsage> = [("gpt-5.4", 10), ("cheap", 10), ("unheard-of", 10)]
            .into_iter()
            .flat_map(|(model, tokens)| used(model, tokens))
            .collect();
        let grant = granted(lease(&mut service, "run-1", 10_000));
        // 10 tokens at 15, 10 at 2, and 10 at the dearest (15) per million.
        assert_eq!(
            billed(
                service
                    .settle_lease(CALLER, &grant.lease_id, LeaseUse::Reported(&mixed[..]))
                    .unwrap()
            ),
            150 + 20 + 150
        );
        // A run that reports no use pays the reservation, not nothing.
        let grant = granted(lease(&mut service, "run-2", 10_000));
        assert_eq!(
            billed(
                service
                    .settle_lease(CALLER, &grant.lease_id, LeaseUse::Reported(&[]))
                    .unwrap()
            ),
            10_000
        );
    }

    #[test]
    fn settling_an_empty_report_cannot_free_the_reservation() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000);
        let grant = granted(lease(&mut service, "run-1", 600));
        assert_eq!(
            billed(
                service
                    .settle_lease(CALLER, &grant.lease_id, LeaseUse::Reported(&[]))
                    .unwrap()
            ),
            600
        );
        assert_eq!(held(&service), 600);
        assert!(matches!(
            lease(&mut service, "run-2", 1_000),
            LeaseAdmission::Refused(LeaseRefusal::SpendCeiling)
        ));
    }

    #[test]
    fn a_token_never_lent_bills_nothing_and_frees_the_window() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000);
        let grant = granted(lease(&mut service, "run-1", 600));
        let settled = service
            .settle_lease(CALLER, &grant.lease_id, LeaseUse::NeverLent)
            .unwrap();
        assert_eq!(
            (settled.billed_micro_usd, settled.overrun_micro_usd),
            (0, 0)
        );
        assert_eq!(held(&service), 0);
        granted(lease(&mut service, "run-2", 1_000));
    }

    #[test]
    fn a_lease_settles_once() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000_000);
        let grant = granted(lease(&mut service, "run-1", 100));
        service
            .settle_lease(CALLER, &grant.lease_id, LeaseUse::Reservation)
            .unwrap();
        assert!(matches!(
            service.settle_lease(CALLER, &grant.lease_id, LeaseUse::Reservation),
            Err(ServiceError::NoActiveRequest)
        ));
        assert_eq!(held(&service), 100);
    }

    #[test]
    fn a_lease_left_open_by_a_crash_counts_at_its_reservation_after_restart() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000_000);
        granted(lease(&mut service, "run-1", 700));
        drop(service);
        let service = open(&store, 1_000_000);
        assert_eq!(held(&service), 700);
    }

    #[test]
    fn a_ledger_that_cannot_be_written_lends_nothing() {
        let flaky = FlakyStore::new(1_000);
        let allowance = flaky.allowance();
        let mut service = open_with(flaky, 1_000_000);
        allowance.store(0, Ordering::SeqCst);
        assert!(
            service
                .begin_lease(CALLER, LeaseTurn::SelfRun, "run-1", 100, NOW + 1, NOW)
                .is_err()
        );
        assert_eq!(held(&service), 0);
        allowance.store(1_000, Ordering::SeqCst);
        granted(lease(&mut service, "run-1", 100));
    }

    #[test]
    fn a_failed_settle_write_frees_the_lease_and_keeps_the_reservation_counted() {
        let flaky = FlakyStore::new(1_000);
        let allowance = flaky.allowance();
        let mut service = open_with(flaky, 1_000_000);
        let grant = granted(lease(&mut service, "run-1", 100));
        allowance.store(0, Ordering::SeqCst);
        assert!(
            service
                .settle_lease(CALLER, &grant.lease_id, LeaseUse::Reported(&output(1)[..]))
                .is_err()
        );
        assert_eq!(held(&service), 100);
        allowance.store(1_000, Ordering::SeqCst);
        granted(lease(&mut service, "run-2", 100));
    }

    fn begin_call(service: &mut TransportService, id: &str) -> TransportAdmission {
        let mut call = request();
        call.request_id = id.to_string();
        let invocation =
            TransportInvocation::new(CALLER, NOW + 1_000, [7; 32], MAX_COST, call).unwrap();
        let sealed = crate::envelope::encrypt_message(
            CALLER,
            id,
            crate::envelope::EnvelopeKind::Invocation,
            &crate::contract::wire_encode(&invocation).unwrap(),
            &security(KEY),
        )
        .unwrap();
        service.begin(&sealed, NOW, 1 << 20).unwrap()
    }

    #[test]
    fn a_lease_takes_no_request_slot_from_the_callers_calls() {
        // The caller admits one concurrent call; an open lease must not use it.
        let store = TestStore::new();
        let mut service = open(&store, 1 << 40);
        granted(lease(&mut service, "run-1", 100));
        match begin_call(&mut service, "call-1") {
            TransportAdmission::Execute(_) => {}
            TransportAdmission::Reply(_) => panic!("the lease held the call's slot"),
        }
    }

    #[test]
    fn a_call_in_flight_does_not_make_the_caller_busy_for_a_lease() {
        let store = TestStore::new();
        let mut service = open(&store, 1 << 40);
        assert!(matches!(
            begin_call(&mut service, "call-1"),
            TransportAdmission::Execute(_)
        ));
        granted(lease(&mut service, "run-1", 100));
    }

    #[test]
    fn an_invocation_id_is_bounded_so_its_lease_id_fits_an_identity() {
        let store = TestStore::new();
        let mut service = open(&store, 1 << 40);
        let longest = "r".repeat(MAX_IDENTITY_BYTES - LEASE_PREFIX.len());
        let grant = granted(lease(&mut service, &longest, 100));
        assert_eq!(grant.lease_id.len(), MAX_IDENTITY_BYTES);
        service
            .settle_lease(CALLER, &grant.lease_id, LeaseUse::Reservation)
            .unwrap();
        assert!(
            service
                .begin_lease(CALLER, LeaseTurn::SelfRun, &format!("{longest}r"), 100, NOW + 1, NOW)
                .is_err()
        );
    }

    #[test]
    fn a_settled_lease_leaves_its_charge_not_its_reservation_across_a_restart() {
        let store = TestStore::new();
        let mut service = open(&store, 1_000_000);
        let grant = granted(lease(&mut service, "run-1", 10_000));
        service
            .settle_lease(CALLER, &grant.lease_id, LeaseUse::Reported(&output(10)[..]))
            .unwrap();
        drop(service);
        let service = open(&store, 1_000_000);
        assert_eq!(held(&service), 150);
    }
}
