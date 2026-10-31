//! The usage readout: the subscription plan's own usage windows as the backend
//! last saw them. The connector meters nothing in dollars; it publishes what
//! the provider reports, and the minds read it and decide their own burn.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::contract::ContractError;

pub const USAGE_READOUT_SCHEMA_ID: &str = "gamecult.model.usage_readout.v1";

/// One window of the subscription plan, as the provider reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanQuota {
    pub window: String,
    /// How much of the window was used when it was observed, in thousandths;
    /// `None` once the window has reset (`status` is then `expired`), because
    /// the old reading says nothing about the new window.
    pub utilization_permille: Option<u32>,
    pub resets_at_unix_ms: u64,
    pub status: String,
    /// When this window was last reported. Its age in a readout is the
    /// readout's `at_unix_ms` minus this.
    pub observed_at_unix_ms: u64,
}

/// What a backend last saw of the plan's windows, each stamped with its own
/// observation time. A backend with no plan to report returns the default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanQuotaSnapshot {
    pub windows: Vec<PlanQuota>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageReadout {
    pub schema_id: String,
    pub at_unix_ms: u64,
    pub plan_quota: Vec<PlanQuota>,
}

impl UsageReadout {
    pub fn new(at_unix_ms: u64, plan: PlanQuotaSnapshot) -> Self {
        Self {
            schema_id: USAGE_READOUT_SCHEMA_ID.to_string(),
            at_unix_ms,
            plan_quota: plan.windows,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        if self.schema_id != USAGE_READOUT_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{wire_decode, wire_encode};

    fn readout() -> UsageReadout {
        UsageReadout::new(
            1_000,
            PlanQuotaSnapshot {
                windows: vec![PlanQuota {
                    window: "five_hour".into(),
                    utilization_permille: Some(80),
                    resets_at_unix_ms: 1_793_307_000_000,
                    status: "allowed".into(),
                    observed_at_unix_ms: 999,
                }],
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
        assert_eq!(names, ["schema_id", "at_unix_ms", "plan_quota"]);
        assert_eq!(wire_decode::<UsageReadout>(&bytes).unwrap(), readout());
    }

    #[test]
    fn an_unobserved_plan_is_none_not_zero() {
        let bare = UsageReadout::new(1, PlanQuotaSnapshot::default());
        let decoded: UsageReadout = wire_decode(&wire_encode(&bare).unwrap()).unwrap();
        assert!(decoded.plan_quota.is_empty());
    }

    #[test]
    fn a_readout_of_another_schema_is_refused() {
        let mut other = readout();
        other.schema_id = "gamecult.model.usage_readout.v2".into();
        assert!(other.validate().is_err());
        assert!(readout().validate().is_ok());
    }
}
