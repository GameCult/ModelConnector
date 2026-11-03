//! The meter: keeps the plan's weekly reading fresh while the swarm is
//! working. The subscription reports its windows only inside the CLI's
//! `rate_limit_event`, on a call the CLI makes, and Personas make theirs under
//! leases that report nothing back. So when the `seven_day` reading in the
//! [`QuotaCell`] is `STALE` old, the meter makes the smallest real call
//! through the backend's own path (one `claude -p` on the cheapest model with
//! a trivial prompt) and the stream fills the cell exactly as it does for any
//! call. The meter holds no credential, speaks no protocol and writes nothing
//! itself.
//!
//! The meter is driven by the connector's own lease state. It reads only
//! while a lease is held or one was asked for less than `STALE` ago: a held
//! swarm brake stops the units, they ask for nothing, and a braked or quiet
//! swarm spends nothing. A call that fails, or completes without refreshing
//! the reading, is not retried at the staleness period: the wait doubles per
//! consecutive miss, up to `CEILING`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use model_connector::Usage;

use crate::backend::ClaudeCodeBackend;
use crate::quota::{EXPIRED, QuotaCell, WEEK};

/// A reading this old, or older, is stale; also the least gap between calls.
const STALE: Duration = Duration::from_secs(15 * 60);
/// The longest any backoff may wait; also how long an idle meter sleeps
/// before looking again, since a lease request wakes it.
const CEILING: Duration = Duration::from_secs(6 * 60 * 60);

/// The smallest real call, as the backend makes it.
pub(crate) trait Probe: Send {
    /// What the call billed, or the failure's kind. Never a message: a
    /// provider's words do not enter the meter's log.
    fn call(&self) -> Result<Usage, String>;
}

impl Probe for Arc<ClaudeCodeBackend> {
    fn call(&self) -> Result<Usage, String> {
        self.read_meter()
    }
}

/// Why the meter is waiting; logged once per change.
#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Read,
    Idle,
    /// The call failed; the kind is the failure's kind, never its message.
    Failed(String),
    Unread,
}

impl State {
    fn line(&self) -> String {
        match self {
            Self::Read => "meter: weekly reading refreshed".to_string(),
            Self::Idle => "meter: no lease asked lately, making no call".to_string(),
            Self::Failed(kind) => format!("meter: the call failed ({kind}), backing off"),
            Self::Unread => {
                "meter: the call completed without a weekly reading, backing off".to_string()
            }
        }
    }
}

struct Meter {
    cell: Arc<QuotaCell>,
    probe: Box<dyn Probe>,
    log: Box<dyn FnMut(&str) + Send>,
    /// No call before this instant, unix ms.
    not_before_ms: u64,
    /// Consecutive calls that left the reading unrefreshed.
    misses: u32,
    last_state: Option<State>,
}

impl Meter {
    fn new(cell: Arc<QuotaCell>, probe: Box<dyn Probe>, log: Box<dyn FnMut(&str) + Send>) -> Self {
        Self {
            cell,
            probe,
            log,
            not_before_ms: 0,
            misses: 0,
            last_state: None,
        }
    }

    /// Makes the call if one is due at `now_ms`; returns how long to wait
    /// before looking again. Nothing is due while no lease is held or lately
    /// asked for, nor before the last miss's backoff has passed, nor while the
    /// weekly reading is younger than `STALE`.
    fn tick(&mut self, now_ms: u64) -> Duration {
        if !self.cell.wanted_at(now_ms, STALE) {
            self.report(State::Idle);
            return CEILING;
        }
        let due_at = self.due_at_ms();
        if now_ms < due_at {
            return Duration::from_millis(due_at - now_ms);
        }
        // A failed call may still have refreshed the reading: a rejected turn
        // reports its windows and then errors. Only the cell says whether the
        // week was read.
        let called = self.probe.call();
        let state = if self.refreshed_since(now_ms) {
            self.misses = 0;
            State::Read
        } else {
            self.misses = self.misses.saturating_add(1);
            match called {
                Ok(_) => State::Unread,
                Err(kind) => State::Failed(kind),
            }
        };
        self.report(state);
        self.not_before_ms = now_ms.saturating_add(duration_ms(backoff(self.misses)));
        Duration::from_millis(self.due_at_ms().saturating_sub(now_ms))
    }

    /// The earliest instant the next call may happen. A window past its reset
    /// described a week that is over, so it is due at once.
    fn due_at_ms(&self) -> u64 {
        let stale_at = self
            .cell
            .snapshot()
            .windows
            .iter()
            .find(|quota| quota.window == WEEK)
            .map_or(0, |quota| {
                if quota.status == EXPIRED {
                    0
                } else {
                    quota.observed_at_unix_ms.saturating_add(duration_ms(STALE))
                }
            });
        stale_at.max(self.not_before_ms)
    }

    fn refreshed_since(&self, since_ms: u64) -> bool {
        self.cell
            .snapshot()
            .windows
            .iter()
            .any(|quota| quota.window == WEEK && quota.observed_at_unix_ms >= since_ms)
    }

    fn report(&mut self, state: State) {
        if self.last_state.as_ref() != Some(&state) {
            (self.log)(&state.line());
            self.last_state = Some(state);
        }
    }

    fn run(mut self) {
        loop {
            let seen = self.cell.asks_so_far();
            let wait = self.tick(unix_ms());
            self.cell.sleep_until_asked(seen, wait);
        }
    }
}

/// The wait after `misses` consecutive unrefreshed calls: the staleness
/// period, doubling per miss beyond the first, up to the ceiling.
fn backoff(misses: u32) -> Duration {
    let doublings = misses.saturating_sub(1).min(16);
    STALE.saturating_mul(1 << doublings).min(CEILING)
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_ms)
}

/// Starts the meter thread. It writes only through the calls it makes, and
/// logs one line to stderr when its state changes. From here a lease asked of
/// a cell with no weekly reading waits for the meter's first read.
pub(crate) fn start(
    cell: Arc<QuotaCell>,
    probe: Box<dyn Probe>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    cell.attach_meter();
    let meter = Meter::new(
        cell,
        probe,
        Box::new(|line| eprintln!("claude-connector: {line}")),
    );
    std::thread::Builder::new()
        .name("claude-meter".to_string())
        .spawn(move || meter.run())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota::Asking;
    use model_connector::PlanQuota;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MIN: u64 = 60_000;
    const NOW: u64 = 1_800_000_000_000;
    const RESET: u64 = 4_102_444_800_000;

    fn reading(status: &str) -> Vec<PlanQuota> {
        vec![PlanQuota {
            window: WEEK.to_string(),
            utilization_permille: Some(60),
            resets_at_unix_ms: RESET,
            status: status.to_string(),
            observed_at_unix_ms: 0,
        }]
    }

    /// What the next call does: the instant its stream stamps a weekly
    /// reading (if any) and the kind it then fails with (if any).
    #[derive(Clone, Default)]
    struct Script {
        reading_at: Option<u64>,
        status: String,
        fails_with: Option<String>,
    }

    /// A call that answers as scripted and feeds the cell the way the stream
    /// does, before it fails, as a rejected turn does.
    struct Calls {
        cell: Arc<QuotaCell>,
        made: Arc<AtomicUsize>,
        script: Arc<Mutex<Script>>,
    }

    impl Probe for Calls {
        fn call(&self) -> Result<Usage, String> {
            self.made.fetch_add(1, Ordering::SeqCst);
            let script = self.script.lock().unwrap().clone();
            if let Some(at) = script.reading_at {
                self.cell.observe_at(at, reading(&script.status));
            }
            if let Some(kind) = script.fails_with {
                return Err(kind);
            }
            Ok(Usage {
                input_tokens: 385,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                output_tokens: 4,
                reasoning_tokens: None,
            })
        }
    }

    struct Rig {
        meter: Meter,
        cell: Arc<QuotaCell>,
        made: Arc<AtomicUsize>,
        script: Arc<Mutex<Script>>,
        log: Arc<Mutex<Vec<String>>>,
        /// The lease the swarm holds until a test lets go of it.
        lease: Option<Asking>,
    }

    fn rig() -> Rig {
        let cell = Arc::new(QuotaCell::new());
        let made = Arc::new(AtomicUsize::new(0));
        let script = Arc::new(Mutex::new(Script::default()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        let meter = Meter::new(
            cell.clone(),
            Box::new(Calls {
                cell: cell.clone(),
                made: made.clone(),
                script: script.clone(),
            }),
            Box::new(move |line| sink.lock().unwrap().push(line.to_string())),
        );
        let lease = Some(cell.asking_at(NOW));
        Rig {
            meter,
            cell,
            made,
            script,
            log,
            lease,
        }
    }

    impl Rig {
        fn reads(&self, at: u64) {
            *self.script.lock().unwrap() = Script {
                reading_at: Some(at),
                status: "allowed".to_string(),
                fails_with: None,
            };
        }
        fn reads_nothing(&self) {
            *self.script.lock().unwrap() = Script::default();
        }
        fn fails(&self, kind: &str) {
            *self.script.lock().unwrap() = Script {
                fails_with: Some(kind.to_string()),
                ..Script::default()
            };
        }
        fn calls(&self) -> usize {
            self.made.load(Ordering::SeqCst)
        }
        fn lines(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    #[test]
    fn an_unread_week_triggers_one_call_and_the_fresh_reading_ends_the_asking() {
        let mut rig = rig();
        rig.reads(NOW);
        assert_eq!(rig.meter.tick(NOW), STALE, "fresh for the staleness period");
        assert_eq!(rig.calls(), 1);
        assert_eq!(
            rig.meter.tick(NOW + 5 * MIN),
            Duration::from_millis(10 * MIN)
        );
        assert_eq!(rig.calls(), 1, "a fresh reading makes no call");
    }

    #[test]
    fn a_stale_reading_triggers_a_call_at_the_period_and_not_before() {
        let mut rig = rig();
        rig.cell.observe_at(NOW, reading("allowed"));
        rig.reads(NOW + 15 * MIN);
        rig.meter.tick(NOW + 15 * MIN - 1);
        assert_eq!(rig.calls(), 0, "one millisecond short of stale");
        rig.meter.tick(NOW + 15 * MIN);
        assert_eq!(rig.calls(), 1);
    }

    #[test]
    fn a_window_past_its_reset_is_read_at_once_not_after_the_period() {
        let mut rig = rig();
        let now = unix_ms();
        let mut over = reading("allowed").remove(0);
        over.resets_at_unix_ms = 1;
        rig.cell.observe_at(now, vec![over]);
        rig.reads(now);
        rig.meter.tick(now);
        assert_eq!(rig.calls(), 1);
    }

    #[test]
    fn a_swarm_that_asks_for_nothing_spends_nothing_however_stale_the_reading() {
        let mut rig = rig();
        drop(rig.lease.take());
        for step in 0..10 {
            let at = NOW + 15 * MIN + step * 60 * MIN;
            assert_eq!(rig.meter.tick(at), CEILING);
        }
        assert_eq!(rig.calls(), 0);
        assert_eq!(rig.lines(), vec![State::Idle.line()]);
    }

    #[test]
    fn a_lease_asked_for_wakes_the_meter_and_the_empty_cell_is_read() {
        let mut rig = rig();
        drop(rig.lease.take());
        rig.reads(NOW + 180 * MIN);
        rig.meter.tick(NOW + 180 * MIN);
        assert_eq!(rig.calls(), 0, "asked three hours ago and let go");
        let _later = rig.cell.asking_at(NOW + 180 * MIN);
        rig.meter.tick(NOW + 180 * MIN);
        assert_eq!(rig.calls(), 1);
    }

    #[test]
    fn a_lease_let_go_is_still_wanted_for_exactly_one_staleness_period() {
        let mut rig = rig();
        drop(rig.lease.take());
        rig.reads(NOW + 15 * MIN - 1);
        rig.meter.tick(NOW + 15 * MIN - 1);
        assert_eq!(rig.calls(), 1, "one millisecond inside the period");
        rig.reads(NOW + 30 * MIN);
        rig.meter.tick(NOW + 30 * MIN);
        assert_eq!(rig.calls(), 1, "a period after the last ask: unwanted");
    }

    #[test]
    fn a_lease_held_for_four_hours_keeps_the_week_read_throughout() {
        let mut rig = rig();
        for step in 0..=16 {
            let at = NOW + step * 15 * MIN;
            rig.reads(at);
            rig.meter.tick(at);
        }
        assert_eq!(rig.calls(), 17, "one read per period, the lease never lapsing");
    }

    #[test]
    fn a_failed_call_leaves_the_cell_and_backs_off_instead_of_hammering() {
        let mut rig = rig();
        rig.cell.observe_at(NOW, reading("allowed"));
        let before = rig.cell.snapshot();
        rig.fails("Provider");
        let mut at = NOW + 15 * MIN;
        let mut waits = Vec::new();
        for _ in 0..4 {
            waits.push(rig.meter.tick(at));
            at += duration_ms(*waits.last().unwrap());
        }
        assert_eq!(rig.calls(), 4);
        assert_eq!(rig.cell.snapshot(), before, "the cell is untouched");
        assert_eq!(
            waits,
            [15, 30, 60, 120].map(|m| Duration::from_secs(m * 60)),
            "the wait doubles per consecutive miss"
        );
        rig.meter.tick(at - MIN);
        assert_eq!(rig.calls(), 4, "nothing is asked before the backoff ends");
        assert_eq!(
            rig.lines(),
            vec!["meter: the call failed (Provider), backing off"]
        );
    }

    #[test]
    fn the_failure_kind_is_logged_again_when_it_changes_and_not_when_it_repeats() {
        let mut rig = rig();
        rig.fails("Authentication");
        rig.meter.tick(NOW);
        rig.meter.tick(NOW + 15 * MIN);
        rig.fails("InvalidRequest");
        rig.meter.tick(NOW + 45 * MIN);
        assert_eq!(
            rig.lines(),
            vec![
                "meter: the call failed (Authentication), backing off",
                "meter: the call failed (InvalidRequest), backing off",
            ]
        );
    }

    #[test]
    fn the_backoff_stops_at_the_ceiling_and_one_good_reading_resets_it() {
        assert_eq!(backoff(0), STALE);
        assert_eq!(backoff(1), STALE);
        assert_eq!(backoff(u32::MAX), CEILING);
        let mut rig = rig();
        rig.fails("Provider");
        rig.meter.tick(NOW);
        rig.meter.tick(NOW + 15 * MIN);
        assert_eq!(rig.meter.misses, 2);
        rig.reads(NOW + 45 * MIN);
        rig.meter.tick(NOW + 45 * MIN);
        assert_eq!(rig.meter.misses, 0);
    }

    #[test]
    fn a_call_that_completes_without_a_weekly_reading_is_a_miss_too() {
        let mut rig = rig();
        rig.reads_nothing();
        assert_eq!(rig.meter.tick(NOW), STALE);
        assert_eq!(rig.meter.tick(NOW + 15 * MIN), 2 * STALE);
        assert_eq!(rig.calls(), 2);
        assert_eq!(rig.lines(), vec![State::Unread.line()]);
    }

    #[test]
    fn a_rejected_turn_that_refreshed_the_reading_and_then_errored_is_no_miss() {
        let mut rig = rig();
        *rig.script.lock().unwrap() = Script {
            reading_at: Some(NOW),
            status: "rejected".to_string(),
            fails_with: Some("RateLimited".to_string()),
        };
        assert_eq!(rig.meter.tick(NOW), STALE, "the next read is a period away");
        assert_eq!(rig.meter.misses, 0);
        assert_eq!(rig.lines(), vec![State::Read.line()]);
        rig.reads(NOW + 15 * MIN);
        rig.meter.tick(NOW + 15 * MIN);
        assert_eq!(rig.calls(), 2, "a rejected reading is kept fresh");
    }

    #[test]
    fn a_reading_from_before_the_call_does_not_count_as_its_answer() {
        let mut rig = rig();
        // A slow concurrent sensor stamped earlier than this call began.
        rig.reads(NOW - 1);
        rig.meter.tick(NOW);
        assert_eq!(rig.meter.misses, 1);
    }

    #[test]
    fn the_log_says_what_the_meter_is_doing_in_words() {
        assert_eq!(
            State::Idle.line(),
            "meter: no lease asked lately, making no call"
        );
        assert_eq!(State::Read.line(), "meter: weekly reading refreshed");
        assert_eq!(
            State::Unread.line(),
            "meter: the call completed without a weekly reading, backing off"
        );
    }

    #[test]
    fn the_clock_is_the_system_clock_in_unix_milliseconds() {
        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let read = unix_ms();
        let after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert!((before.as_millis() as u64..=after.as_millis() as u64).contains(&read));
    }

    #[test]
    fn a_started_meter_sleeps_until_a_lease_asks_and_then_reads() {
        let cell = Arc::new(QuotaCell::new());
        let made = Arc::new(AtomicUsize::new(0));
        let probe = Calls {
            cell: cell.clone(),
            made: made.clone(),
            script: Arc::new(Mutex::new(Script {
                reading_at: Some(unix_ms() + 60 * MIN),
                status: "allowed".to_string(),
                fails_with: None,
            })),
        };
        start(cell.clone(), Box::new(probe)).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(made.load(Ordering::SeqCst), 0, "no lease, no call");
        let _lease = cell.asking();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while made.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < deadline, "the ask woke nobody");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(cell.snapshot_with_week(Duration::ZERO).windows.len(), 1);
    }
}
