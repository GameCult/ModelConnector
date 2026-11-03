//! The plan's own usage windows, as the subscription reports them. The
//! subscription decides how much a plan may burn, and one sensor observes it:
//! the CLI's `rate_limit_event` on the connector's own calls, which the
//! `meter` makes when the week's reading goes stale. The latest observation of
//! each window is kept here and published as the usage readout and lent with
//! each lease.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use model_connector::{PlanQuota, PlanQuotaSnapshot};

/// The latest observation of each plan window, shared by the backend that
/// feeds it and whatever reads it out. Each window carries the time of its
/// own observation: an event that names one window says nothing about the
/// others.
#[derive(Default)]
pub struct QuotaCell(Mutex<BTreeMap<String, PlanQuota>>);

impl QuotaCell {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the windows one event reported, stamping each with now. See
    /// [`QuotaCell::observe_at`] for how a reading combines with what is held.
    pub fn observe(&self, windows: impl IntoIterator<Item = PlanQuota>) {
        self.observe_at(unix_ms(), windows);
    }

    /// Records readings taken at `at` (unix ms). A reading older than the
    /// held one is dropped, so a slow call cannot replace what a faster one
    /// saw meanwhile. Windows the readings did not mention stay as they were,
    /// stamp included.
(&self, at: u64, windows: impl IntoIterator<Item = PlanQuota>) {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for mut quota in windows {
            quota.observed_at_unix_ms = at;
            if held
                .get(&quota.window)
                .is_none_or(|current| quota.observed_at_unix_ms >= current.observed_at_unix_ms)
            {
                held.insert(quota.window.clone(), quota);
            }
        }
    }

    pub fn snapshot(&self) -> PlanQuotaSnapshot {
        self.snapshot_at(unix_ms())
    }

    /// The windows as of `now`. One whose reset time has passed is reported
    /// `expired` with no utilization: the reading described a window that no
    /// longer exists.
    fn snapshot_at(&self, now: u64) -> PlanQuotaSnapshot {
        let held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        PlanQuotaSnapshot {
            windows: held
                .values()
                .cloned()
                .map(|mut quota| {
                    if now >= quota.resets_at_unix_ms {
                        quota.utilization_permille = None;
                        quota.status = EXPIRED.to_string();
                    }
                    quota
                })
                .collect(),
        }
    }
}

/// The status of a window whose reset has passed since it was observed.
pub(crate) const EXPIRED: &str = "expired";

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

    const RESET: u64 = 4_102_444_800_000;

    fn quota(window: &str, permille: u32, observed_at: u64) -> PlanQuota {
        PlanQuota {
            window: window.to_string(),
            utilization_permille: Some(permille),
            resets_at_unix_ms: RESET,
            status: "allowed".to_string(),
            observed_at_unix_ms: observed_at,
        }
    }

    #[test]
    fn an_empty_cell_has_observed_nothing() {
        assert!(QuotaCell::new().snapshot().windows.is_empty());
    }

    #[test]
    fn each_window_keeps_its_own_latest_observation_and_its_own_time() {
        let cell = QuotaCell::new();
        cell.observe_at(100, [quota("five_hour", 80, 0), quota("seven_day", 300, 0)]);
        cell.observe_at(200, [quota("five_hour", 120, 0)]);
        assert_eq!(
            cell.snapshot_at(250).windows,
            vec![quota("five_hour", 120, 200), quota("seven_day", 300, 100)],
            "the window the later event did not name keeps its older stamp"
        );
    }

    #[test]
    fn an_event_with_no_windows_changes_nothing() {
        let cell = QuotaCell::new();
        cell.observe_at(100, [quota("five_hour", 80, 0)]);
        cell.observe_at(900, Vec::new());
        assert_eq!(
            cell.snapshot_at(950).windows,
            vec![quota("five_hour", 80, 100)]
        );
    }

    #[test]
    fn a_window_past_its_reset_is_expired_not_old_utilization() {
        let cell = QuotaCell::new();
        cell.observe_at(100, [quota("five_hour", 80, 0)]);
        let live = cell.snapshot_at(RESET - 1).windows;
        assert_eq!(live, vec![quota("five_hour", 80, 100)]);
        let expired = cell.snapshot_at(RESET).windows;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].status, "expired");
        assert_eq!(expired[0].utilization_permille, None);
        assert_eq!(
            expired[0].observed_at_unix_ms, 100,
            "its age stays readable"
        );
        assert_eq!(expired[0].resets_at_unix_ms, RESET);
    }

    fn with_status(mut quota: PlanQuota, status: &str) -> PlanQuota {
        quota.status = status.to_string();
        quota
    }

    fn held(cell: &QuotaCell) -> (String, Option<u32>, u64) {
        let window = cell.snapshot_at(250).windows.remove(0);
        (
            window.status,
            window.utilization_permille,
            window.observed_at_unix_ms,
        )
    }

    #[test]
    fn a_reading_older_than_the_held_one_is_dropped_and_an_equal_one_replaces() {
        let cell = QuotaCell::new();
        cell.observe_at(200, [quota("five_hour", 80, 0)]);
        cell.observe_at(100, [quota("five_hour", 10, 0)]);
        assert_eq!(held(&cell), ("allowed".to_string(), Some(80), 200));
        cell.observe_at(200, [quota("five_hour", 90, 0)]);
        assert_eq!(held(&cell), ("allowed".to_string(), Some(90), 200));
    }

    #[test]
    fn a_newer_reading_lifts_a_rejection() {
        let cell = QuotaCell::new();
        cell.observe_at(100, [with_status(quota("five_hour", 1000, 0), "rejected")]);
        cell.observe_at(200, [quota("five_hour", 300, 0)]);
        assert_eq!(held(&cell), ("allowed".to_string(), Some(300), 200));
    }

    #[test]
    fn the_live_clock_stamps_and_expires() {
        let cell = QuotaCell::new();
        let before = unix_ms();
        let mut past = quota("old", 10, 0);
        past.resets_at_unix_ms = 1;
        cell.observe([past, quota("five_hour", 80, 0)]);
        let after = unix_ms();
        let windows = cell.snapshot().windows;
        let stamp = windows[0].observed_at_unix_ms;
        assert!((before..=after).contains(&stamp));
        assert_eq!(windows[0].window, "five_hour");
        assert_eq!(windows[0].utilization_permille, Some(80));
        assert_eq!(windows[1].status, "expired");
    }
}
