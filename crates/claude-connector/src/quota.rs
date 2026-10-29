//! The plan's own usage windows, as the CLI reports them. The subscription
//! decides how much a plan may burn; the CLI's `rate_limit_event` is the only
//! place that number appears, so the latest one seen is kept here and read out
//! beside the connector's own spend ledger.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use model_connector::{PlanQuota, PlanQuotaSnapshot};

/// The latest observation of each plan window, shared by the backend that
/// feeds it and whatever reads it out.
#[derive(Default)]
pub struct QuotaCell(Mutex<Observed>);

#[derive(Default)]
struct Observed {
    windows: BTreeMap<String, PlanQuota>,
    observed_at_unix_ms: Option<u64>,
}

impl QuotaCell {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the windows one event reported: each replaces that window's
    /// earlier observation, and windows the event did not mention stay. An
    /// event that reported none changes nothing, not even the time.
    pub fn observe(&self, windows: impl IntoIterator<Item = PlanQuota>) {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut any = false;
        for quota in windows {
            held.windows.insert(quota.window.clone(), quota);
            any = true;
        }
        if any {
            held.observed_at_unix_ms = Some(unix_ms());
        }
    }

    pub fn snapshot(&self) -> PlanQuotaSnapshot {
        let held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        PlanQuotaSnapshot {
            windows: held.windows.values().cloned().collect(),
            observed_at_unix_ms: held.observed_at_unix_ms,
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quota(window: &str, permille: u32) -> PlanQuota {
        PlanQuota {
            window: window.to_string(),
            utilization_permille: permille,
            resets_at_unix_ms: 1_793_307_000_000,
            status: "allowed".to_string(),
        }
    }

    #[test]
    fn an_empty_cell_has_observed_nothing() {
        let snapshot = QuotaCell::new().snapshot();
        assert!(snapshot.windows.is_empty());
        assert_eq!(snapshot.observed_at_unix_ms, None);
    }

    #[test]
    fn a_window_keeps_only_its_latest_observation_and_others_stay() {
        let cell = QuotaCell::new();
        let before = unix_ms();
        cell.observe([quota("five_hour", 80), quota("seven_day", 300)]);
        cell.observe([quota("five_hour", 120)]);
        let after = unix_ms();
        let snapshot = cell.snapshot();
        assert_eq!(
            snapshot.windows,
            vec![quota("five_hour", 120), quota("seven_day", 300)]
        );
        let at = snapshot.observed_at_unix_ms.expect("stamped");
        assert!((before..=after).contains(&at));
    }

    #[test]
    fn an_event_with_no_windows_does_not_move_the_stamp() {
        let cell = QuotaCell::new();
        cell.observe(Vec::new());
        assert_eq!(cell.snapshot().observed_at_unix_ms, None);
        cell.observe([quota("five_hour", 80)]);
        let first = cell.snapshot().observed_at_unix_ms;
        std::thread::sleep(std::time::Duration::from_millis(3));
        cell.observe(Vec::new());
        assert_eq!(cell.snapshot().observed_at_unix_ms, first);
    }
}
