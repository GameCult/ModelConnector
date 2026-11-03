//! The meter: keeps the plan's weekly reading fresh. The subscription reports
//! its windows only inside the CLI's `rate_limit_event`, on a call the CLI
//! makes, and Personas make theirs under leases that report nothing back. So
//! when the `seven_day` reading in the [`QuotaCell`] is `STALE` old, the
//! meter makes the smallest real call through the backend's own path (one
//! `claude -p` on the cheapest model with a trivial prompt) and the stream
//! fills the cell exactly as it does for any call. The meter holds no
//! credential, speaks no protocol and writes nothing itself.
//!
//! A held swarm brake spends nothing: the meter reads the swarm's brake store
//! before every call and, like every other organ that acts, treats anything
//! but a decodable released brake as held. A call that fails, or completes
//! without refreshing the reading, is not retried at the staleness period: the
//! wait doubles per consecutive miss, up to `CEILING`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use cultcache_rs::{CultCache, DatabaseEntry, SingleFileMessagePackBackingStore};
use model_connector::Usage;

use crate::backend::ClaudeCodeBackend;
use crate::quota::{EXPIRED, QuotaCell};

/// Where the swarm's brake is kept: the operator's root-owned, world-readable
/// store, the same file the Minds' organs read before they act.
pub(crate) const SWARM_BRAKE_STORE: &str = "/etc/gamecult/minds/swarm.cc";
/// The one key the brake document has in its store.
const BRAKE_KEY: &str = "brake";
/// The window the meter keeps fresh.
const WINDOW: &str = "seven_day";
/// A reading this old, or older, is stale; also the least gap between calls.
const STALE: Duration = Duration::from_secs(15 * 60);
/// The longest any backoff may wait.
const CEILING: Duration = Duration::from_secs(6 * 60 * 60);
/// How often a held brake is looked at again.
const BRAKE_RECHECK: Duration = Duration::from_secs(60);

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

/// Whether the operator's swarm brake holds.
pub(crate) trait Brake: Send {
    fn held(&self) -> bool;
}

/// The brake document of the operator's control stores. Declared here with the
/// type name and field order the stores are written with; the connector reads
/// it and never writes it.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "eureka.control.brake.v1")]
struct SwarmBrake {
    #[cultcache(key = 0)]
    released: bool,
    #[cultcache(key = 1)]
    set_at: DateTime<Utc>,
    #[cultcache(key = 2)]
    set_by: String,
}

/// The swarm brake read from its store, read-only and without locks. Absent,
/// unreadable, undecodable or unreleased is held.
pub(crate) struct SwarmBrakeStore(PathBuf);

impl SwarmBrakeStore {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    fn released(&self) -> Option<bool> {
        let mut cache = CultCache::new();
        cache.register_entry_type::<SwarmBrake>().ok()?;
        for envelope in SingleFileMessagePackBackingStore::new(&self.0)
            .pull_all_read_only_snapshot()
            .ok()?
        {
            cache.put_raw_envelope(envelope).ok()?;
        }
        Some(cache.get::<SwarmBrake>(BRAKE_KEY).ok()??.released)
    }
}

impl Brake for SwarmBrakeStore {
    fn held(&self) -> bool {
        self.released() != Some(true)
    }
}

/// Why the meter is waiting; logged once per change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Read,
    Braked,
    Failed,
    Unread,
}

impl State {
    fn line(self) -> &'static str {
        match self {
            Self::Read => "meter: weekly reading refreshed",
            Self::Braked => "meter: swarm brake held, making no call",
            Self::Failed => "meter: the call failed, backing off",
            Self::Unread => "meter: the call completed without a weekly reading, backing off",
        }
    }
}

struct Meter {
    cell: Arc<QuotaCell>,
    probe: Box<dyn Probe>,
    brake: Box<dyn Brake>,
    log: Box<dyn FnMut(&str) + Send>,
    /// No call before this instant, unix ms.
    not_before_ms: u64,
    /// Consecutive calls that left the reading unrefreshed.
    misses: u32,
    last_state: Option<State>,
}

impl Meter {
    fn new(
        cell: Arc<QuotaCell>,
        probe: Box<dyn Probe>,
        brake: Box<dyn Brake>,
        log: Box<dyn FnMut(&str) + Send>,
    ) -> Self {
        Self {
            cell,
            probe,
            brake,
            log,
            not_before_ms: 0,
            misses: 0,
            last_state: None,
        }
    }

    /// Makes the call if one is due at `now_ms`; returns how long to wait
    /// before looking again. Nothing is due while the brake is held, nor
    /// before the last miss's backoff has passed, nor while the weekly reading
    /// is younger than `STALE`.
    fn tick(&mut self, now_ms: u64) -> Duration {
        if self.brake.held() {
            self.report(State::Braked);
            return BRAKE_RECHECK;
        }
        let due_at = self.due_at_ms();
        if now_ms < due_at {
            return Duration::from_millis(due_at - now_ms);
        }
        let called = self.probe.call();
        let state = if called.is_ok() && self.refreshed_since(now_ms) {
            self.misses = 0;
            State::Read
        } else {
            self.misses = self.misses.saturating_add(1);
            if called.is_ok() {
                State::Unread
            } else {
                State::Failed
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
            .find(|quota| quota.window == WINDOW)
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
            .any(|quota| quota.window == WINDOW && quota.observed_at_unix_ms >= since_ms)
    }

    fn report(&mut self, state: State) {
        if self.last_state != Some(state) {
            (self.log)(state.line());
            self.last_state = Some(state);
        }
    }

    fn run(mut self) {
        loop {
            let wait = self.tick(unix_ms());
            std::thread::sleep(wait);
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
/// logs one line to stderr when its state changes.
pub(crate) fn start(
    cell: Arc<QuotaCell>,
    probe: Box<dyn Probe>,
    brake: Box<dyn Brake>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let meter = Meter::new(
        cell,
        probe,
        brake,
        Box::new(|line| eprintln!("claude-connector: {line}")),
    );
    std::thread::Builder::new()
        .name("claude-meter".to_string())
        .spawn(move || meter.run())
}

#[cfg(test)]
mod tests {
    use super::*;
    use model_connector::PlanQuota;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const MIN: u64 = 60_000;
    const NOW: u64 = 1_800_000_000_000;
    const RESET: u64 = 4_102_444_800_000;

    fn reading() -> Vec<PlanQuota> {
        vec![PlanQuota {
            window: WINDOW.to_string(),
            utilization_permille: Some(60),
            resets_at_unix_ms: RESET,
            status: "allowed".to_string(),
            observed_at_unix_ms: 0,
        }]
    }

    /// A call that answers as scripted and, when it succeeds with a reading,
    /// feeds the cell the way the stream does.
    struct Calls {
        cell: Arc<QuotaCell>,
        made: Arc<AtomicUsize>,
        outcome: Arc<Mutex<Result<Option<u64>, String>>>,
    }

    impl Probe for Calls {
        fn call(&self) -> Result<Usage, String> {
            self.made.fetch_add(1, Ordering::SeqCst);
            match &*self.outcome.lock().unwrap() {
                Ok(Some(at)) => self.cell.observe_at(*at, reading()),
                Ok(None) => {}
                Err(kind) => return Err(kind.clone()),
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

    struct Held(Arc<AtomicBool>);

    impl Brake for Held {
        fn held(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct Rig {
        meter: Meter,
        cell: Arc<QuotaCell>,
        made: Arc<AtomicUsize>,
        outcome: Arc<Mutex<Result<Option<u64>, String>>>,
        braked: Arc<AtomicBool>,
        log: Arc<Mutex<Vec<String>>>,
    }

    fn rig() -> Rig {
        let cell = Arc::new(QuotaCell::new());
        let made = Arc::new(AtomicUsize::new(0));
        let outcome = Arc::new(Mutex::new(Ok(None)));
        let braked = Arc::new(AtomicBool::new(false));
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        let meter = Meter::new(
            cell.clone(),
            Box::new(Calls {
                cell: cell.clone(),
                made: made.clone(),
                outcome: outcome.clone(),
            }),
            Box::new(Held(braked.clone())),
            Box::new(move |line| sink.lock().unwrap().push(line.to_string())),
        );
        Rig {
            meter,
            cell,
            made,
            outcome,
            braked,
            log,
        }
    }

    impl Rig {
        fn answers(&self, outcome: Result<Option<u64>, &str>) {
            *self.outcome.lock().unwrap() = outcome.map_err(str::to_string);
        }
        fn calls(&self) -> usize {
            self.made.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn an_unread_week_triggers_one_call_and_the_fresh_reading_ends_the_asking() {
        let mut rig = rig();
        rig.answers(Ok(Some(NOW)));
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
        rig.cell.observe_at(NOW, reading());
        rig.answers(Ok(Some(NOW + 15 * MIN)));
        rig.meter.tick(NOW + 15 * MIN - 1);
        assert_eq!(rig.calls(), 0, "one millisecond short of stale");
        rig.meter.tick(NOW + 15 * MIN);
        assert_eq!(rig.calls(), 1);
    }

    #[test]
    fn a_window_past_its_reset_is_read_at_once_not_after_the_period() {
        let mut rig = rig();
        let now = unix_ms();
        let mut over = reading().remove(0);
        over.resets_at_unix_ms = 1;
        rig.cell.observe_at(now, vec![over]);
        rig.answers(Ok(Some(now)));
        rig.meter.tick(now);
        assert_eq!(rig.calls(), 1);
    }

    #[test]
    fn a_held_brake_makes_no_call_however_stale_the_reading() {
        let mut rig = rig();
        rig.braked.store(true, Ordering::SeqCst);
        for step in 0..10 {
            assert_eq!(rig.meter.tick(NOW + step * 60 * MIN), BRAKE_RECHECK);
        }
        assert_eq!(rig.calls(), 0);
        assert_eq!(*rig.log.lock().unwrap(), vec![State::Braked.line()]);
        rig.braked.store(false, Ordering::SeqCst);
        rig.answers(Ok(Some(NOW + 600 * MIN)));
        rig.meter.tick(NOW + 600 * MIN);
        assert_eq!(rig.calls(), 1, "released, the stale week is read at once");
    }

    #[test]
    fn a_failed_call_leaves_the_cell_and_backs_off_instead_of_hammering() {
        let mut rig = rig();
        rig.cell.observe_at(NOW, reading());
        let before = rig.cell.snapshot();
        rig.answers(Err("Provider"));
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
        assert_eq!(*rig.log.lock().unwrap(), vec![State::Failed.line()]);
    }

    #[test]
    fn the_backoff_stops_at_the_ceiling_and_one_good_reading_resets_it() {
        assert_eq!(backoff(0), STALE);
        assert_eq!(backoff(1), STALE);
        assert_eq!(backoff(u32::MAX), CEILING);
        let mut rig = rig();
        rig.answers(Err("Provider"));
        rig.meter.tick(NOW);
        rig.meter.tick(NOW + 15 * MIN);
        assert_eq!(rig.meter.misses, 2);
        rig.answers(Ok(Some(NOW + 45 * MIN)));
        rig.meter.tick(NOW + 45 * MIN);
        assert_eq!(rig.meter.misses, 0);
    }

    #[test]
    fn a_call_that_completes_without_a_weekly_reading_is_a_miss_too() {
        let mut rig = rig();
        rig.answers(Ok(None));
        assert_eq!(rig.meter.tick(NOW), STALE);
        assert_eq!(rig.meter.tick(NOW + 15 * MIN), 2 * STALE);
        assert_eq!(rig.calls(), 2);
        assert_eq!(*rig.log.lock().unwrap(), vec![State::Unread.line()]);
    }

    #[test]
    fn a_reading_from_before_the_call_does_not_count_as_its_answer() {
        let mut rig = rig();
        // A slow concurrent sensor stamped earlier than this call began.
        rig.answers(Ok(Some(NOW - 1)));
        rig.meter.tick(NOW);
        assert_eq!(rig.meter.misses, 1);
    }

    // ---- the brake store, read as the operator's tool writes it ----

    /// The swarm store as it stood on Yggdrasil on 2026-11-03 (released),
    /// copied byte for byte.
    const LIVE_STORE: &[u8] = include_bytes!("../tests/fixtures/swarm-brake-live-2026-11-03.cc");

    fn store_with(bytes: &[u8]) -> (PathBuf, SwarmBrakeStore) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "claude-meter-brake-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("swarm.cc");
        std::fs::write(&path, bytes).unwrap();
        (dir, SwarmBrakeStore::new(path))
    }

    /// The live store with `released` flipped to false: the msgpack `true`
    /// byte that precedes the timestamp string.
    fn held_store() -> Vec<u8> {
        let mut bytes = LIVE_STORE.to_vec();
        let at = bytes
            .windows(5)
            .position(|w| w == b"\xc3\xbe202")
            .expect("the live store holds released=true before its timestamp");
        bytes[at] = 0xc2;
        bytes
    }

    #[test]
    fn the_live_released_store_reads_as_released() {
        let (dir, store) = store_with(LIVE_STORE);
        assert_eq!(store.released(), Some(true));
        assert!(!store.held());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_same_store_with_the_brake_held_reads_as_held() {
        let (dir, store) = store_with(&held_store());
        assert_eq!(store.released(), Some(false));
        assert!(store.held());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_garbled_or_truncated_store_is_held() {
        assert!(SwarmBrakeStore::new("/nonexistent-claude-meter/swarm.cc").held());
        for bytes in [&b""[..], b"not a store at all", &LIVE_STORE[..40]] {
            let (dir, store) = store_with(bytes);
            assert!(store.held(), "{bytes:?}");
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
