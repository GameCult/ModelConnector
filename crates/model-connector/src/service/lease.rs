//! A credential lease: a Self run's or a Persona turn's hold on the token the
//! connector lends. The lease is memory bound to its holder's open connection,
//! not a record and not a charge: it decides `Busy` while it is held and
//! nothing else. It ends when its holder lets go (`end_lease`), when the unit
//! invocation it served ends, or when its expiry passes. Nothing is billed and
//! nothing is reserved. The only usage-derived refusal is the provider's own
//! (`ProviderRejected`), repeated with the provider's own expiry.

use super::*;

/// The request-id namespace of leases.
const LEASE_PREFIX: &str = "lease:";

/// What a Persona turn's lease id adds to its invocation id, so a Persona
/// lease and a Self lease of one caller and one invocation never share an id.
const PERSONA_SUFFIX: &str = ":persona";

/// Which kind of turn a lease serves. It is a property of the lease caller's
/// configured row, never of a request. A caller holds one Self lease at a
/// time; a Persona turn holds one lease per live invocation, one at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseTurn {
    SelfRun,
    PersonaTurn,
}

/// What an admitted lease holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGrant {
    pub lease_id: String,
}

/// Why no lease was granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRefusal {
    UnknownCaller,
    /// A Self run: the caller holds a Self lease now. A Persona turn: this
    /// invocation holds a lease now.
    Busy,
    /// The provider is refusing right now and has said until when.
    ProviderRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseAdmission {
    Granted(LeaseGrant),
    Refused(LeaseRefusal),
}

impl TransportService {
    /// Grants `caller_runtime_id` a lease for the unit invocation
    /// `invocation_id` until `expires_at_unix_ms`. A Self run's lease is
    /// `lease:<invocation>` and one is open per caller; a Persona turn's is
    /// `lease:<invocation>:persona`, one open per invocation; neither blocks
    /// the other. A lease takes no request slot. `plan` is the backend's plan
    /// quota as it stands: a provider that is refusing right now refuses the
    /// lease. A lease past its expiry no longer holds anything.
    pub fn begin_lease(
        &mut self,
        caller_runtime_id: &str,
        turn: LeaseTurn,
        invocation_id: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
        plan: &PlanQuotaSnapshot,
    ) -> Result<LeaseAdmission, ServiceError> {
        if !self.callers.contains_key(caller_runtime_id) {
            return Ok(LeaseAdmission::Refused(LeaseRefusal::UnknownCaller));
        }
        require_id(invocation_id, "invocation_id")?;
        let suffix = match turn {
            LeaseTurn::SelfRun => "",
            LeaseTurn::PersonaTurn => PERSONA_SUFFIX,
        };
        let lease_id = format!("{LEASE_PREFIX}{invocation_id}{suffix}");
        if lease_id.len() > MAX_IDENTITY_BYTES {
            return Err(ContractError::Invalid("invocation_id").into());
        }
        self.leases
            .retain(|_, lease| lease.expires_at_unix_ms > now_unix_ms);
        let identity = RequestIdentity {
            caller_runtime_id: caller_runtime_id.to_string(),
            request_id: lease_id.clone(),
        };
        let busy = match turn {
            LeaseTurn::SelfRun => self.leases.iter().any(|(held, lease)| {
                lease.turn == LeaseTurn::SelfRun && held.caller_runtime_id == caller_runtime_id
            }),
            LeaseTurn::PersonaTurn => self.leases.contains_key(&identity),
        };
        if busy {
            return Ok(LeaseAdmission::Refused(LeaseRefusal::Busy));
        }
        if provider_rejects(plan, now_unix_ms) {
            return Ok(LeaseAdmission::Refused(LeaseRefusal::ProviderRejected));
        }
        self.leases.insert(
            identity,
            LiveLease {
                turn,
                expires_at_unix_ms,
            },
        );
        Ok(LeaseAdmission::Granted(LeaseGrant { lease_id }))
    }

    /// Ends a lease its holder let go of. Ending one that is not held is a
    /// no-op: a holder may close after its expiry already freed the lease.
    pub fn end_lease(&mut self, caller_runtime_id: &str, lease_id: &str) {
        self.leases.remove(&RequestIdentity {
            caller_runtime_id: caller_runtime_id.to_string(),
            request_id: lease_id.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::*;
    use crate::readout::PlanQuota;

    const CALLER: &str = "eureka";
    const KEY: &str = "lease-distinct-test-key";
    const NOW: u64 = 7_200_500;

    fn open(store: &TestStore) -> TransportService {
        TransportService::open(
            &store.path,
            "fixture-sse",
            [
                CallerAdmission::new(CALLER, KEY, 1, ["gpt-5.4".to_string()], 1, 65_536, 32_768)
                    .unwrap(),
            ],
            5_000,
        )
        .unwrap()
    }

    fn none() -> PlanQuotaSnapshot {
        PlanQuotaSnapshot::default()
    }

    fn window(permille: u32, status: &str, resets_at: u64) -> PlanQuotaSnapshot {
        PlanQuotaSnapshot {
            windows: vec![PlanQuota {
                window: "five_hour".to_string(),
                utilization_permille: Some(permille),
                resets_at_unix_ms: resets_at,
                status: status.to_string(),
                observed_at_unix_ms: NOW,
            }],
        }
    }

    fn lease_in(
        service: &mut TransportService,
        turn: LeaseTurn,
        run: &str,
        plan: &PlanQuotaSnapshot,
    ) -> LeaseAdmission {
        service
            .begin_lease(CALLER, turn, run, NOW + 60_000, NOW, plan)
            .unwrap()
    }

    fn lease(service: &mut TransportService, run: &str) -> LeaseAdmission {
        lease_in(service, LeaseTurn::SelfRun, run, &none())
    }

    fn granted(admission: LeaseAdmission) -> LeaseGrant {
        match admission {
            LeaseAdmission::Granted(grant) => grant,
            LeaseAdmission::Refused(why) => panic!("refused {why:?}"),
        }
    }

    #[test]
    fn a_lease_is_named_by_its_invocation() {
        let store = TestStore::new();
        let mut service = open(&store);
        assert_eq!(
            granted(lease(&mut service, "run-1")).lease_id,
            "lease:run-1"
        );
    }

    #[test]
    fn a_caller_holds_one_self_lease_at_a_time() {
        let store = TestStore::new();
        let mut service = open(&store);
        granted(lease(&mut service, "run-1"));
        assert_eq!(
            lease(&mut service, "run-2"),
            LeaseAdmission::Refused(LeaseRefusal::Busy)
        );
        assert_eq!(
            lease(&mut service, "run-1"),
            LeaseAdmission::Refused(LeaseRefusal::Busy)
        );
    }

    #[test]
    fn a_lease_ends_when_its_holder_closes() {
        let store = TestStore::new();
        let mut service = open(&store);
        let grant = granted(lease(&mut service, "run-1"));
        service.end_lease(CALLER, &grant.lease_id);
        // The same invocation may lease again: nothing remembers a closed
        // lease, and nothing was billed for it.
        granted(lease(&mut service, "run-1"));
        service.end_lease(CALLER, "lease:not-held");
        assert_eq!(
            lease(&mut service, "run-2"),
            LeaseAdmission::Refused(LeaseRefusal::Busy),
            "ending a lease that is not held frees nothing else"
        );
    }

    #[test]
    fn a_lease_ends_at_its_expiry_without_its_holder() {
        let store = TestStore::new();
        let mut service = open(&store);
        granted(
            service
                .begin_lease(CALLER, LeaseTurn::SelfRun, "run-1", NOW + 10, NOW, &none())
                .unwrap(),
        );
        assert_eq!(
            service
                .begin_lease(
                    CALLER,
                    LeaseTurn::SelfRun,
                    "run-2",
                    NOW + 99,
                    NOW + 9,
                    &none()
                )
                .unwrap(),
            LeaseAdmission::Refused(LeaseRefusal::Busy),
            "one millisecond before its expiry the lease still holds"
        );
        granted(
            service
                .begin_lease(
                    CALLER,
                    LeaseTurn::SelfRun,
                    "run-2",
                    NOW + 99,
                    NOW + 10,
                    &none(),
                )
                .unwrap(),
        );
    }

    #[test]
    fn a_stranger_is_refused() {
        let store = TestStore::new();
        let mut service = open(&store);
        assert_eq!(
            service
                .begin_lease(
                    "stranger",
                    LeaseTurn::SelfRun,
                    "run-1",
                    NOW + 1,
                    NOW,
                    &none()
                )
                .unwrap(),
            LeaseAdmission::Refused(LeaseRefusal::UnknownCaller)
        );
    }

    #[test]
    fn a_persona_holds_one_lease_per_invocation_and_never_blocks_the_self_lease() {
        let store = TestStore::new();
        let mut service = open(&store);
        let persona = |service: &mut TransportService, run: &str| {
            lease_in(service, LeaseTurn::PersonaTurn, run, &none())
        };
        let first = granted(persona(&mut service, "turn-1"));
        assert_eq!(first.lease_id, "lease:turn-1:persona");
        assert_eq!(
            persona(&mut service, "turn-1"),
            LeaseAdmission::Refused(LeaseRefusal::Busy)
        );
        granted(persona(&mut service, "turn-2"));
        granted(lease(&mut service, "turn-1"));
        service.end_lease(CALLER, &first.lease_id);
        granted(persona(&mut service, "turn-1"));
    }

    #[test]
    fn a_rejected_window_refuses_invoke_and_lease_until_its_reset() {
        let store = TestStore::new();
        let mut service = open(&store);
        let rejected = window(1_000, "rejected", NOW + 5_000);
        assert_eq!(
            lease_in(&mut service, LeaseTurn::SelfRun, "run-1", &rejected),
            LeaseAdmission::Refused(LeaseRefusal::ProviderRejected)
        );
        let call = |service: &mut TransportService, now: u64, plan: &PlanQuotaSnapshot| {
            let mut asked = request();
            asked.request_id = format!("call-{now}");
            let invocation = TransportInvocation::new(CALLER, now + 1_000, [7; 32], asked).unwrap();
            let sealed = crate::envelope::encrypt_message(
                CALLER,
                invocation.request_id(),
                crate::envelope::EnvelopeKind::Invocation,
                &crate::contract::wire_encode(&invocation).unwrap(),
                &security(KEY),
            )
            .unwrap();
            let TransportAdmission::Reply(reply) =
                service.begin(&sealed, now, plan, 1 << 20).unwrap()
            else {
                return None;
            };
            let result =
                crate::envelope::decrypt_result(&reply, &security(KEY), &invocation).unwrap();
            match result.disposition {
                TransportDisposition::Refused(refusal) => Some(refusal),
                other => panic!("unexpected {other:?}"),
            }
        };
        assert_eq!(
            call(&mut service, NOW, &rejected),
            Some(Refusal::ProviderRejected)
        );
        assert_eq!(
            call(&mut service, NOW + 4_999, &rejected),
            Some(Refusal::ProviderRejected)
        );
        assert_eq!(call(&mut service, NOW + 5_000, &rejected), None);
        assert!(matches!(
            service
                .begin_lease(
                    CALLER,
                    LeaseTurn::SelfRun,
                    "run-1",
                    NOW + 9_000,
                    NOW + 5_000,
                    &rejected
                )
                .unwrap(),
            LeaseAdmission::Granted(_)
        ));
    }

    #[test]
    fn high_utilization_refuses_nothing() {
        let store = TestStore::new();
        let mut service = open(&store);
        let full = window(999, "allowed", NOW + 5_000);
        granted(lease_in(&mut service, LeaseTurn::SelfRun, "run-1", &full));
        let warned = window(1_000, "allowed_warning", NOW + 5_000);
        granted(lease_in(
            &mut service,
            LeaseTurn::PersonaTurn,
            "turn-1",
            &warned,
        ));
    }

    #[test]
    fn an_invocation_id_is_bounded_so_its_lease_id_fits_an_identity() {
        let store = TestStore::new();
        let mut service = open(&store);
        let longest = "r".repeat(MAX_IDENTITY_BYTES - LEASE_PREFIX.len());
        let grant = granted(lease(&mut service, &longest));
        assert_eq!(grant.lease_id.len(), MAX_IDENTITY_BYTES);
        assert!(lease_try(&mut service, LeaseTurn::SelfRun, &format!("{longest}r")).is_err());
    }

    #[test]
    fn a_persona_invocation_id_leaves_room_for_its_suffix() {
        let store = TestStore::new();
        let mut service = open(&store);
        let longest = "r".repeat(MAX_IDENTITY_BYTES - LEASE_PREFIX.len() - PERSONA_SUFFIX.len());
        let grant = granted(lease_in(
            &mut service,
            LeaseTurn::PersonaTurn,
            &longest,
            &none(),
        ));
        assert_eq!(grant.lease_id.len(), MAX_IDENTITY_BYTES);
        assert!(lease_try(&mut service, LeaseTurn::PersonaTurn, &format!("{longest}r")).is_err());
    }

    fn lease_try(
        service: &mut TransportService,
        turn: LeaseTurn,
        run: &str,
    ) -> Result<LeaseAdmission, ServiceError> {
        service.begin_lease(CALLER, turn, run, NOW + 60_000, NOW, &none())
    }

    #[test]
    fn a_lease_takes_no_request_slot_from_the_callers_calls() {
        // The caller admits one concurrent call; an open lease must not use it.
        let store = TestStore::new();
        let mut service = open(&store);
        granted(lease(&mut service, "run-1"));
        let mut call = request();
        call.request_id = "call-1".to_string();
        let invocation = TransportInvocation::new(CALLER, NOW + 1_000, [7; 32], call).unwrap();
        let sealed = crate::envelope::encrypt_message(
            CALLER,
            "call-1",
            crate::envelope::EnvelopeKind::Invocation,
            &crate::contract::wire_encode(&invocation).unwrap(),
            &security(KEY),
        )
        .unwrap();
        assert!(matches!(
            service.begin(&sealed, NOW, &none(), 1 << 20).unwrap(),
            TransportAdmission::Execute(_)
        ));
        // And a call in flight does not make the caller busy for a lease.
        granted(lease_in(
            &mut service,
            LeaseTurn::PersonaTurn,
            "turn-1",
            &none(),
        ));
    }
}
