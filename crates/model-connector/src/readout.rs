//! The spend readout: what each caller has spent and holds in its current
//! window, and the plan's own usage as the backend last saw it. The ledger is
//! the replay store's; a readout only reads it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::contract::ContractError;

pub const SPEND_READOUT_SCHEMA_ID: &str = "gamecult.model.spend_readout.v1";

/// One window of the subscription plan, as the provider reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanQuota {
    pub window: String,
    /// How much of the window is used, in thousandths.
    pub utilization_permille: u32,
    pub resets_at_unix_ms: u64,
    pub status: String,
}

/// What a backend last saw of the plan's windows and when it saw them. A
/// backend with no plan to report returns the default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanQuotaSnapshot {
    pub windows: Vec<PlanQuota>,
    pub observed_at_unix_ms: Option<u64>,
}

/// One caller's current spend window in micro-USD. `spent` is settled charges
/// plus what a crash left counted at its full reservation; `reserved` is what
/// calls in flight hold, and both count against the ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallerSpend {
    pub caller_id: String,
    pub window_ms: u64,
    pub ceiling_micro_usd: u64,
    pub spent_micro_usd: u64,
    pub reserved_micro_usd: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpendReadout {
    pub schema_id: String,
    pub at_unix_ms: u64,
    pub callers: Vec<CallerSpend>,
    pub plan_quota: Vec<PlanQuota>,
    pub plan_quota_observed_at_unix_ms: Option<u64>,
}

impl SpendReadout {
    pub fn new(at_unix_ms: u64, callers: Vec<CallerSpend>, plan: PlanQuotaSnapshot) -> Self {
        Self {
            schema_id: SPEND_READOUT_SCHEMA_ID.to_string(),
            at_unix_ms,
            callers,
            plan_quota: plan.windows,
            plan_quota_observed_at_unix_ms: plan.observed_at_unix_ms,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        if self.schema_id != SPEND_READOUT_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{wire_decode, wire_encode};

    fn readout() -> SpendReadout {
        SpendReadout::new(
            1_000,
            vec![CallerSpend {
                caller_id: "eureka".into(),
                window_ms: 3_600_000,
                ceiling_micro_usd: 50_000_000,
                spent_micro_usd: 7,
                reserved_micro_usd: 3,
            }],
            PlanQuotaSnapshot {
                windows: vec![PlanQuota {
                    window: "five_hour".into(),
                    utilization_permille: 80,
                    resets_at_unix_ms: 1_793_307_000_000,
                    status: "allowed".into(),
                }],
                observed_at_unix_ms: Some(999),
            },
        )
    }

    #[test]
    fn a_readout_is_a_named_map_that_decodes_to_itself() {
        let bytes = wire_encode(&readout()).unwrap();
        let value: rmpv::Value = rmp_serde::from_slice(&bytes).unwrap();
        let rmpv::Value::Map(fields) = value else {
            panic!("a readout is a map, not a positional array");
        };
        let names: Vec<&str> = fields.iter().filter_map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "schema_id",
                "at_unix_ms",
                "callers",
                "plan_quota",
                "plan_quota_observed_at_unix_ms"
            ]
        );
        assert_eq!(wire_decode::<SpendReadout>(&bytes).unwrap(), readout());
    }

    #[test]
    fn an_unobserved_plan_is_none_not_zero() {
        let bare = SpendReadout::new(1, Vec::new(), PlanQuotaSnapshot::default());
        let decoded: SpendReadout = wire_decode(&wire_encode(&bare).unwrap()).unwrap();
        assert!(decoded.plan_quota.is_empty());
        assert_eq!(decoded.plan_quota_observed_at_unix_ms, None);
    }

    #[test]
    fn a_readout_of_another_schema_is_refused() {
        let mut other = readout();
        other.schema_id = "gamecult.model.spend_readout.v2".into();
        assert!(other.validate().is_err());
        assert!(readout().validate().is_ok());
    }
}
