//! The plan's own usage windows, as the subscription reports them. The
//! subscription decides how much a plan may burn, and one sensor observes it:
//! the CLI's `rate_limit_event` on the connector's own calls, which the
//! `meter` makes when the week's reading goes stale. The latest observation of
//! each window is kept here and published as the usage readout and lent with
//! each lease.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use model_connector::{PlanQuota, PlanQuotaSnapshot};

/// The window the weekly pacing reads, and the one the meter keeps fresh.
pub(crate) const WEEK: &str = "seven_day";
/// The windows the pacing reads, and so the only ones the cell keeps.
pub(crate) const PACED: [&str; 2] = ["five_hour", WEEK];

/// How often a lease waiting for its first reading looks at the cell again.
const FIRST_READ_POLL: Duration = Duration::from_millis(50);

/// The latest observation of each plan window, shared by the backend that
/// feeds it and whatever reads it out. Each window carries the time of its
/// own observation: an event that names one window says nothing about the
/// others.
///
/// It also keeps who is asking: a lease request is the swarm's only sign of
/// life the connector sees, and the meter reads the plan only while someone
/// asks.
#[derive(Default)]
pub struct QuotaCell {
    windows: Mutex<BTreeMap<String, PlanQuota>>,
    asks: Mutex<Asks>,
    asked: Condvar,
    metered: AtomicBool,
}

#[derive(Default)]
struct Asks {
    /// Lease requests in flight or held.
    live: usize,
    /// Requests ever made; the meter sleeps until it changes.
    count: u64,
    /// When the latest request came, unix ms.
    last_ms: Option<u64>,
}

/// A lease request while it is in flight or held. Dropping it is the lease
/// ending, by whatever road.
pub(crate) struct Asking(Arc<QuotaCell>);

impl Drop for Asking {
    fn drop(&mut self) {
        let mut asks = self.0.asks.lock().unwrap_or_else(|e| e.into_inner());
        asks.live = asks.live.saturating_sub(1);
    }
}

impl QuotaCell {
    pub fn new() -> Self {
        Self::default()
    }

    /// Notes a lease request, now, and wakes the meter.
    pub(crate) fn asking(self: &Arc<Self>) -> Asking {
        self.asking_at(unix_ms())
    }

    fn asking_at(self: &Arc<Self>, now: u64) -> Asking {
        {
            let mut asks = self.asks.lock().unwrap_or_else(|e| e.into_inner());
            asks.live += 1;
            asks.count += 1;
            asks.last_ms = Some(now);
        }
        self.asked.notify_all();
        Asking(self.clone())
    }

    /// Whether a lease is held, or one was asked for less than `within` ago.
    pub(crate) fn wanted_at(&self, now: u64, within: Duration) -> bool {
        let asks = self.asks.lock().unwrap_or_else(|e| e.into_inner());
        asks.live > 0
            || asks.last_ms.is_some_and(|last| {
                now < last.saturating_add(u64::try_from(within.as_millis()).unwrap_or(u64::MAX))
            })
    }

    pub(crate) fn asks_so_far(&self) -> u64 {
        self.asks.lock().unwrap_or_else(|e| e.into_inner()).count
    }

    /// Sleeps up to `limit`, or until a request beyond the first `seen` comes.
    pub(crate) fn sleep_until_asked(&self, seen: u64, limit: Duration) {
        let asks = self.asks.lock().unwrap_or_else(|e| e.into_inner());
        drop(
            self.asked
                .wait_timeout_while(asks, limit, |asks| asks.count == seen)
                .unwrap_or_else(|e| e.into_inner()),
        );
    }

    /// Declares that a meter reads this cell, so a first lease may wait for it.
    pub(crate) fn attach_meter(&self) {
        self.metered.store(true, Ordering::SeqCst);
    }

    /// The windows as they stand, but with no weekly reading yet (a restart
    /// leaves the cell empty) a metered cell is given up to `within` to get
    /// one, so a lease is not lent "unobserved" for want of a few seconds.
    pub(crate) fn snapshot_with_week(&self, within: Duration) -> PlanQuotaSnapshot {
        let deadline = Instant::now() + within;
        loop {
            let snapshot = self.snapshot();
            let read = snapshot
                .windows
                .iter()
                .any(|quota| quota.window == WEEK && quota.status != EXPIRED);
            let now = Instant::now();
            if read || !self.metered.load(Ordering::SeqCst) || now >= deadline {
                return snapshot;
            }
            std::thread::sleep(FIRST_READ_POLL.min(deadline - now));
        }
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
    pub fn observe_at(&self, at: u64, windows: impl IntoIterator<Item = PlanQuota>) {
        let mut held = self.windows.lock().unwrap_or_else(|e| e.into_inner());
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
        let held = self.windows.lock().unwrap_or_else(|e| e.into_inner());
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

    const HOUR: u64 = 3_600_000;

    #[test]
    fn nobody_wants_the_plan_before_anyone_asks() {
        let cell = Arc::new(QuotaCell::new());
        assert!(!cell.wanted_at(0, Duration::from_secs(900)));
    }

    #[test]
    fn a_lease_in_flight_or_held_is_wanted_for_as_long_as_it_lives() {
        let cell = Arc::new(QuotaCell::new());
        let lease = cell.asking_at(1_000);
        let other = cell.asking_at(2_000);
        let day = Duration::from_secs(86_400);
        assert!(cell.wanted_at(1_000 + 4 * HOUR, Duration::from_secs(1)));
        drop(lease);
        assert!(cell.wanted_at(1_000 + 4 * HOUR, Duration::from_secs(1)), "one lease still lives");
        drop(other);
        assert!(!cell.wanted_at(1_000 + 4 * HOUR, Duration::from_secs(1)));
        assert!(cell.wanted_at(2_000 + 4 * HOUR, day), "within the window of the last ask");
    }

    #[test]
    fn a_lease_let_go_is_wanted_until_exactly_the_period_after_its_ask() {
        let cell = Arc::new(QuotaCell::new());
        drop(cell.asking_at(10_000));
        let period = Duration::from_millis(900);
        assert!(cell.wanted_at(10_899, period));
        assert!(!cell.wanted_at(10_900, period));
    }

    #[test]
    fn each_ask_is_counted_and_wakes_a_sleeper_at_once() {
        let cell = Arc::new(QuotaCell::new());
        assert_eq!(cell.asks_so_far(), 0);
        let sleeper = {
            let cell = cell.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                cell.sleep_until_asked(0, Duration::from_secs(30));
                started.elapsed()
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        drop(cell.asking());
        assert!(sleeper.join().unwrap() < Duration::from_secs(10), "woken, not timed out");
        assert_eq!(cell.asks_so_far(), 1);
        // An ask that came after `seen` was read ends the sleep before it starts.
        let started = Instant::now();
        cell.sleep_until_asked(0, Duration::from_secs(30));
        assert!(started.elapsed() < Duration::from_secs(10));
        // Nothing new: the sleep is the whole limit.
        let started = Instant::now();
        cell.sleep_until_asked(1, Duration::from_millis(200));
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn a_metered_cell_with_no_week_gives_a_first_lease_the_reading_when_it_lands() {
        let cell = Arc::new(QuotaCell::new());
        cell.attach_meter();
        let feeder = {
            let cell = cell.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                cell.observe([quota(WEEK, 60, 0)]);
            })
        };
        let plan = cell.snapshot_with_week(Duration::from_secs(20));
        feeder.join().unwrap();
        assert_eq!(plan.windows.len(), 1, "the lease waited for the week");
        assert_eq!(plan.windows[0].window, WEEK);
    }

    #[test]
    fn the_wait_for_the_first_reading_is_bounded() {
        let cell = Arc::new(QuotaCell::new());
        cell.attach_meter();
        let started = Instant::now();
        let plan = cell.snapshot_with_week(Duration::from_millis(300));
        let waited = started.elapsed();
        assert!(plan.windows.is_empty(), "no reading came: unobserved, not hung");
        assert!(waited >= Duration::from_millis(300), "{waited:?}");
        assert!(waited < Duration::from_secs(10), "{waited:?}");
    }

    #[test]
    fn a_cell_nobody_meters_or_that_holds_the_week_is_never_waited_on() {
        let bare = QuotaCell::new();
        let started = Instant::now();
        assert!(bare.snapshot_with_week(Duration::from_secs(20)).windows.is_empty());
        let held = QuotaCell::new();
        held.attach_meter();
        held.observe([quota(WEEK, 60, 0)]);
        assert_eq!(held.snapshot_with_week(Duration::from_secs(20)).windows.len(), 1);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_week_past_its_reset_is_waited_on_like_no_week() {
        let cell = QuotaCell::new();
        cell.attach_meter();
        let mut over = quota(WEEK, 60, 0);
        over.resets_at_unix_ms = 1;
        cell.observe([over]);
        let started = Instant::now();
        cell.snapshot_with_week(Duration::from_millis(300));
        assert!(started.elapsed() >= Duration::from_millis(300));
    }
}
