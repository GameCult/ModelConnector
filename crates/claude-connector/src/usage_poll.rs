//! The second sensor of the plan's usage windows. The CLI's `rate_limit_event`
//! only arrives when the connector's own calls run, so while the swarm is
//! quiet the weekly reading goes stale; this thread asks the subscription's
//! usage endpoint when the `seven_day` reading is `STALE` or older, and
//! records the answer in the same [`QuotaCell`] the stream feeds. Neither
//! sensor owns the reading: the newest observation of a window wins. A failed
//! poll never touches the cell; only the cell's own reset rule retires a
//! window.
//!
//! The endpoint is undocumented (the shape is the one Claude Code 2.1.312
//! parses), so every answer it can give is handled and none is trusted to
//! change the schedule beyond the rules below.

use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use model_connector::PlanQuota;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::backend::TokenSource;
use crate::quota::QuotaCell;

/// The usage endpoint.
const ENDPOINT: &str = "https://api.anthropic.com/api/oauth/usage";
/// A reading this old, or older, is stale; also the least gap between polls.
const STALE: Duration = Duration::from_secs(15 * 60);
/// The longest any backoff may wait.
const CEILING: Duration = Duration::from_secs(6 * 60 * 60);
const TIMEOUT: Duration = Duration::from_secs(10);
/// A usage body is a few hundred bytes; this is a ceiling, not an expectation.
const MAX_BODY: u64 = 1 << 20;
/// The status every polled window carries.
const POLLED: &str = "polled";

/// What the endpoint said, reduced to what the schedule needs. It never holds
/// the token.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Body(String),
    Status(u16, Option<Duration>),
    Unreachable,
}

/// Why the poller is waiting; logged once per change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Polled,
    NoToken,
    RateLimited,
    Refused,
    NotFound,
    Unreadable,
    Unexpected,
    Unreachable,
}

impl State {
    fn line(self) -> &'static str {
        match self {
            Self::Polled => "usage poll: reading recorded",
            Self::NoToken => "usage poll: no token to ask with",
            Self::RateLimited => "usage poll: rate limited, waiting",
            Self::Refused => {
                "usage poll: refused (401/403), the token likely lacks the user:profile scope; polling stopped until restart"
            }
            Self::NotFound => "usage poll: endpoint not found, backing off",
            Self::Unreadable => "usage poll: answer not readable, backing off",
            Self::Unexpected => "usage poll: unexpected status, retrying later",
            Self::Unreachable => "usage poll: endpoint unreachable, retrying later",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Next {
    Wait(Duration),
    Stop,
}

#[derive(Debug, PartialEq)]
struct Verdict {
    windows: Vec<PlanQuota>,
    next: Next,
    state: State,
}

/// What one answer means: the windows to record (only a readable body has
/// any), how long to wait, and the state to report.
fn judge(answer: &Answer) -> Verdict {
    let (windows, next, state) = match answer {
        Answer::Body(body) => match parse_usage(body) {
            Some(windows) => (windows, Next::Wait(STALE), State::Polled),
            None => (Vec::new(), Next::Wait(CEILING), State::Unreadable),
        },
        Answer::Status(429, retry_after) => (
            Vec::new(),
            Next::Wait(retry_after.unwrap_or_default().clamp(STALE, CEILING)),
            State::RateLimited,
        ),
        Answer::Status(401 | 403, _) => (Vec::new(), Next::Stop, State::Refused),
        Answer::Status(404, _) => (Vec::new(), Next::Wait(CEILING), State::NotFound),
        Answer::Status(..) => (Vec::new(), Next::Wait(STALE), State::Unexpected),
        Answer::Unreachable => (Vec::new(), Next::Wait(STALE), State::Unreachable),
    };
    Verdict {
        windows,
        next,
        state,
    }
}

/// The plan windows a usage body reports: `five_hour` and `seven_day`, each
/// `{utilization: percent 0-100, resets_at: ISO 8601}`. A window missing
/// either field, or reporting nonsense, is skipped, and an unknown reading is
/// never zero. Other keys are ignored. `None` when the body is not a JSON
/// object at all.
fn parse_usage(body: &str) -> Option<Vec<PlanQuota>> {
    let usage: Value = serde_json::from_str(body).ok()?;
    let usage = usage.as_object()?;
    Some(
        ["five_hour", "seven_day"]
            .into_iter()
            .filter_map(|window| {
                let reading = usage.get(window)?;
                let percent = reading.get("utilization")?.as_f64()?;
                let resets_at = reading.get("resets_at")?.as_str()?;
                if !percent.is_finite() || percent < 0.0 {
                    return None;
                }
                let resets_at = chrono::DateTime::parse_from_rfc3339(resets_at).ok()?;
                Some(PlanQuota {
                    window: window.to_string(),
                    // `as` saturates a float at the integer's bounds.
                    utilization_permille: Some((percent * 10.0).round() as u32),
                    resets_at_unix_ms: u64::try_from(resets_at.timestamp_millis()).ok()?,
                    status: POLLED.to_string(),
                    // Stamped by the cell that keeps it.
                    observed_at_unix_ms: 0,
                })
            })
            .collect(),
    )
}

/// The blocking HTTPS client: 10 s end to end, no redirects (the token must
/// not follow one anywhere).
struct UsageClient {
    agent: ureq::Agent,
    url: String,
}

impl UsageClient {
    fn new(url: impl Into<String>) -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(TIMEOUT)
                .redirects(0)
                .build(),
            url: url.into(),
        }
    }

    fn ask(&self, token: &Zeroizing<String>) -> Answer {
        let bearer = Zeroizing::new(format!("Bearer {}", token.as_str()));
        let sent = self
            .agent
            .get(&self.url)
            .set("Authorization", bearer.as_str())
            .set("anthropic-beta", "oauth-2025-04-20")
            .call();
        match sent {
            Ok(response) if response.status() == 200 => {
                let mut body = String::new();
                match response
                    .into_reader()
                    .take(MAX_BODY)
                    .read_to_string(&mut body)
                {
                    Ok(_) => Answer::Body(body),
                    Err(_) => Answer::Unreachable,
                }
            }
            Ok(response) => Answer::Status(response.status(), None),
            Err(ureq::Error::Status(code, response)) => {
                // Whole seconds only; the HTTP-date form counts as absent.
                let retry_after = response
                    .header("retry-after")
                    .and_then(|seconds| seconds.trim().parse::<u64>().ok())
                    .map(Duration::from_secs);
                Answer::Status(code, retry_after)
            }
            Err(ureq::Error::Transport(_)) => Answer::Unreachable,
        }
    }
}

/// The schedule and the thing it drives. Time comes in as an argument so the
/// schedule is testable without waiting.
struct Poller {
    cell: Arc<QuotaCell>,
    tokens: Box<dyn TokenSource>,
    client: UsageClient,
    log: Box<dyn FnMut(&str) + Send>,
    /// No poll before this instant, unix ms: the last answer's own wait.
    not_before_ms: u64,
    started: bool,
    stopped: bool,
    last_state: Option<State>,
}

impl Poller {
    fn new(
        cell: Arc<QuotaCell>,
        tokens: Box<dyn TokenSource>,
        client: UsageClient,
        log: Box<dyn FnMut(&str) + Send>,
    ) -> Self {
        Self {
            cell,
            tokens,
            client,
            log,
            not_before_ms: 0,
            started: false,
            stopped: false,
            last_state: None,
        }
    }

    /// Polls if a poll is due at `now_ms`; returns how long to wait before
    /// asking again, or `None` once polling has stopped for good.
    ///
    /// The first call polls. After that a poll is due only when the cell's
    /// `seven_day` observation is `STALE` old or older (or absent), and never
    /// before the last answer's own wait has passed.
    fn tick(&mut self, now_ms: u64) -> Option<Duration> {
        if self.stopped {
            return None;
        }
        let due_at = self.due_at_ms();
        if now_ms < due_at {
            return Some(Duration::from_millis(due_at - now_ms));
        }
        self.started = true;
        let verdict = match self.tokens.read() {
            Some(token) => judge(&self.client.ask(&token)),
            None => Verdict {
                windows: Vec::new(),
                next: Next::Wait(STALE),
                state: State::NoToken,
            },
        };
        self.cell.observe(verdict.windows);
        if self.last_state != Some(verdict.state) {
            (self.log)(verdict.state.line());
            self.last_state = Some(verdict.state);
        }
        match verdict.next {
            Next::Stop => {
                self.stopped = true;
                None
            }
            Next::Wait(wait) => {
                self.not_before_ms = now_ms.saturating_add(duration_ms(wait));
                Some(Duration::from_millis(
                    self.due_at_ms().saturating_sub(now_ms),
                ))
            }
        }
    }

    /// The earliest instant the next poll may happen.
    fn due_at_ms(&self) -> u64 {
        if !self.started {
            return 0;
        }
        let stale_at = self
            .cell
            .snapshot()
            .windows
            .iter()
            .find(|quota| quota.window == "seven_day")
            .map_or(0, |quota| {
                quota.observed_at_unix_ms.saturating_add(duration_ms(STALE))
            });
        stale_at.max(self.not_before_ms)
    }

    fn run(mut self) {
        while let Some(wait) = self.tick(unix_ms()) {
            std::thread::sleep(wait);
        }
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_ms)
}

/// Starts the poll thread. It reads the token afresh at each poll, writes
/// only to `cell`, and logs one line to stderr when its state changes.
pub fn start(
    cell: Arc<QuotaCell>,
    tokens: Box<dyn TokenSource>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let poller = Poller::new(
        cell,
        tokens,
        UsageClient::new(ENDPOINT),
        Box::new(|line| eprintln!("claude-connector: {line}")),
    );
    std::thread::Builder::new()
        .name("claude-usage-poll".to_string())
        .spawn(move || poller.run())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::Mutex;

    const MIN: u64 = 60_000;
    const CANARY: &str = "sk-ant-oat01-CANARY-must-never-surface";
    const FAR: &str = "2100-01-01T00:00:00+00:00";
    const FAR_MS: u64 = 4_102_444_800_000;

    fn body(five: &str, seven: &str) -> String {
        format!(
            r#"{{"five_hour":{five},"seven_day":{seven},"seven_day_opus":null,"extra_usage":{{"x":1}}}}"#
        )
    }

    fn reading(percent: f64) -> String {
        format!(r#"{{"utilization":{percent},"resets_at":"{FAR}"}}"#)
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    // ---- mapping ----

    #[test]
    fn usage_body_maps_percent_to_permille() {
        let windows = parse_usage(&body(&reading(6.0), &reading(35.0))).unwrap();
        let expect = |window: &str, permille| PlanQuota {
            window: window.to_string(),
            utilization_permille: Some(permille),
            resets_at_unix_ms: FAR_MS,
            status: "polled".to_string(),
            observed_at_unix_ms: 0,
        };
        assert_eq!(
            windows,
            vec![expect("five_hour", 60), expect("seven_day", 350)]
        );
    }

    #[test]
    fn usage_percent_rounds_to_the_nearest_permille() {
        let windows = parse_usage(&body(&reading(12.34), &reading(0.06))).unwrap();
        assert_eq!(windows[0].utilization_permille, Some(123));
        assert_eq!(windows[1].utilization_permille, Some(1));
        let zero = parse_usage(&body(&reading(0.0), "null")).unwrap();
        assert_eq!(zero[0].utilization_permille, Some(0), "a real zero stays");
    }

    #[test]
    fn resets_at_is_parsed_with_its_offset_to_unix_ms() {
        let seven = r#"{"utilization":1.0,"resets_at":"2026-11-07T12:30:15.250+02:00"}"#;
        let windows = parse_usage(&body("null", seven)).unwrap();
        // 2026-11-07T10:30:15.250Z
        assert_eq!(windows[0].resets_at_unix_ms, 1_794_047_415_250);
    }

    #[test]
    fn a_window_missing_a_field_or_reading_nonsense_is_skipped_not_zero() {
        let no_percent = format!(r#"{{"utilization":null,"resets_at":"{FAR}"}}"#);
        let no_reset = r#"{"utilization":50.0,"resets_at":null}"#;
        assert_eq!(parse_usage(&body(&no_percent, no_reset)).unwrap(), vec![]);
        let junk = r#"{"utilization":5.0,"resets_at":"soon"}"#;
        assert_eq!(parse_usage(&body(&reading(-1.0), junk)).unwrap(), vec![]);
        let before_epoch = r#"{"utilization":5.0,"resets_at":"1969-01-01T00:00:00Z"}"#;
        assert_eq!(parse_usage(&body(before_epoch, "null")).unwrap(), vec![]);
        // One good window survives its neighbour's null.
        let one = parse_usage(&body(&no_percent, &reading(35.0))).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].window, "seven_day");
    }

    #[test]
    fn a_body_that_is_not_an_object_is_unreadable() {
        for bad in ["", "not json", "[1,2]", "42", "null"] {
            assert_eq!(parse_usage(bad), None, "{bad:?}");
        }
        assert_eq!(parse_usage("{}"), Some(vec![]));
    }

    // ---- judgement ----

    fn wait_of(answer: &Answer) -> Next {
        judge(answer).next
    }

    #[test]
    fn rate_limit_waits_the_longer_of_retry_after_and_the_floor_capped() {
        let limited = |after| wait_of(&Answer::Status(429, after));
        assert_eq!(limited(Some(secs(3600))), Next::Wait(secs(3600)));
        assert_eq!(limited(Some(secs(20 * 60))), Next::Wait(secs(20 * 60)));
        assert_eq!(limited(Some(secs(10))), Next::Wait(STALE));
        assert_eq!(limited(None), Next::Wait(STALE));
        assert_eq!(limited(Some(secs(100_000))), Next::Wait(CEILING));
        assert_eq!(limited(Some(secs(6 * 3600))), Next::Wait(CEILING));
        assert_eq!(judge(&Answer::Status(429, None)).state, State::RateLimited);
    }

    #[test]
    fn refusal_stops_polling_and_the_rest_back_off() {
        assert_eq!(wait_of(&Answer::Status(401, None)), Next::Stop);
        assert_eq!(wait_of(&Answer::Status(403, Some(secs(5)))), Next::Stop);
        assert_eq!(judge(&Answer::Status(403, None)).state, State::Refused);
        assert_eq!(wait_of(&Answer::Status(404, None)), Next::Wait(CEILING));
        assert_eq!(
            wait_of(&Answer::Body("<html>".to_string())),
            Next::Wait(CEILING)
        );
        assert_eq!(wait_of(&Answer::Unreachable), Next::Wait(STALE));
        assert_eq!(wait_of(&Answer::Status(503, None)), Next::Wait(STALE));
        assert_eq!(
            wait_of(&Answer::Body(body(&reading(1.0), "null"))),
            Next::Wait(STALE)
        );
    }

    // ---- a fake server, a poller, and the cell ----

    /// Serves each canned reply to one connection in turn and remembers the
    /// requests.
    fn serve(replies: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/api/oauth/usage", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        std::thread::spawn(move || {
            for reply in replies {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = vec![0u8; 4096];
                let n = stream.read(&mut request).unwrap_or(0);
                record
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request[..n]).into_owned());
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        (url, seen)
    }

    fn http(status: &str, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    struct Fixed(Option<&'static str>);
    impl TokenSource for Fixed {
        fn read(&self) -> Option<Zeroizing<String>> {
            self.0.map(|t| Zeroizing::new(t.to_string()))
        }
    }

    type Lines = Arc<Mutex<Vec<String>>>;

    fn poller(cell: &Arc<QuotaCell>, url: &str, token: Option<&'static str>) -> (Poller, Lines) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        let poller = Poller::new(
            cell.clone(),
            Box::new(Fixed(token)),
            UsageClient::new(url),
            Box::new(move |line| sink.lock().unwrap().push(line.to_string())),
        );
        (poller, lines)
    }

    fn window(cell: &QuotaCell, name: &str) -> Option<PlanQuota> {
        cell.snapshot()
            .windows
            .into_iter()
            .find(|q| q.window == name)
    }

    fn stream_reading(window: &str, permille: u32) -> PlanQuota {
        PlanQuota {
            window: window.to_string(),
            utilization_permille: Some(permille),
            resets_at_unix_ms: FAR_MS,
            status: "allowed".to_string(),
            observed_at_unix_ms: 0,
        }
    }

    fn requests(seen: &Arc<Mutex<Vec<String>>>) -> usize {
        seen.lock().unwrap().len()
    }

    #[test]
    fn the_first_tick_polls_and_records_what_the_endpoint_said() {
        let (url, seen) = serve(vec![http(
            "200 OK",
            "Content-Type: application/json\r\n",
            &body(&reading(6.0), &reading(35.0)),
        )]);
        let cell = Arc::new(QuotaCell::new());
        let (mut poller, lines) = poller(&cell, &url, Some(CANARY));
        let wait = poller.tick(unix_ms()).unwrap();
        let windows = cell.snapshot().windows;
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].status, "polled");
        assert_eq!(windows[1].utilization_permille, Some(350));
        assert!(
            (STALE..STALE + secs(5)).contains(&wait),
            "a fresh reading waits until it is stale: {wait:?}"
        );
        let request = seen.lock().unwrap()[0].to_lowercase();
        assert!(request.contains(&format!("authorization: bearer {}", CANARY.to_lowercase())));
        assert!(request.contains("anthropic-beta: oauth-2025-04-20"));
        assert_eq!(lines.lock().unwrap().len(), 1);
    }

    #[test]
    fn stale_only_polls() {
        let (url, seen) = serve(vec![http("200 OK", "", &body("null", &reading(35.0))); 3]);
        let cell = Arc::new(QuotaCell::new());
        let (mut poller, _) = poller(&cell, &url, Some(CANARY));
        poller.tick(unix_ms());
        assert_eq!(requests(&seen), 1, "the startup poll");
        let observed = window(&cell, "seven_day").unwrap().observed_at_unix_ms;

        // 5 min old: no request, and the wait is the time left.
        let wait = poller.tick(observed + 5 * MIN).unwrap();
        assert_eq!(requests(&seen), 1);
        assert_eq!(wait, Duration::from_millis(10 * MIN));
        // One millisecond short of 15 min: still none.
        poller.tick(observed + 15 * MIN - 1);
        assert_eq!(requests(&seen), 1);
        // 16 min old: one request.
        poller.tick(observed + 16 * MIN);
        assert_eq!(requests(&seen), 2);
        // That poll's answer holds its own 15 min, whatever the stamp says.
        poller.tick(observed + 16 * MIN + 1);
        assert_eq!(requests(&seen), 2);
    }

    #[test]
    fn a_reading_is_stale_at_exactly_fifteen_minutes() {
        let (url, seen) = serve(vec![http("200 OK", "", &body("null", &reading(35.0))); 2]);
        let cell = Arc::new(QuotaCell::new());
        let (mut poller, _) = poller(&cell, &url, Some(CANARY));
        poller.tick(unix_ms());
        let observed = window(&cell, "seven_day").unwrap().observed_at_unix_ms;
        poller.tick(observed + 15 * MIN);
        assert_eq!(requests(&seen), 2);
    }

    #[test]
    fn a_stream_observation_keeps_the_poll_quiet() {
        let (url, seen) = serve(vec![http("200 OK", "", &body("null", &reading(35.0)))]);
        let cell = Arc::new(QuotaCell::new());
        let (mut poller, _) = poller(&cell, &url, Some(CANARY));
        poller.tick(unix_ms());
        std::thread::sleep(Duration::from_millis(20));
        // The stream reports seven_day afresh, after the poll.
        cell.observe([stream_reading("seven_day", 400)]);
        let observed = window(&cell, "seven_day").unwrap().observed_at_unix_ms;
        let wait = poller.tick(observed + 14 * MIN).unwrap();
        assert_eq!(requests(&seen), 1);
        assert_eq!(wait, Duration::from_millis(MIN));
    }

    #[test]
    fn failures_never_touch_the_cell() {
        let limited = |headers: &str| http("429 Too Many Requests", headers, "{}");
        let cases = [
            (limited("Retry-After: 3600\r\n"), Some(60)),
            (limited(""), Some(15)),
            (
                limited("Retry-After: Wed, 21 Oct 2026 07:28:00 GMT\r\n"),
                Some(15),
            ),
            (http("403 Forbidden", "", "{}"), None),
            (http("401 Unauthorized", "", "{}"), None),
            (http("404 Not Found", "", "{}"), Some(360)),
            (http("200 OK", "", "<html>not json</html>"), Some(360)),
            (
                http("302 Found", "Location: http://127.0.0.1:9/\r\n", ""),
                Some(15),
            ),
        ];
        for (reply, minutes) in cases {
            let (url, _) = serve(vec![reply.clone()]);
            let cell = Arc::new(QuotaCell::new());
            cell.observe([
                stream_reading("five_hour", 120),
                stream_reading("seven_day", 300),
            ]);
            let before = cell.snapshot();
            let (mut poller, lines) = poller(&cell, &url, Some(CANARY));
            let wait = poller.tick(unix_ms());
            assert_eq!(cell.snapshot(), before, "{reply}");
            assert_eq!(wait.map(|w| w.as_secs() / 60), minutes, "{reply}");
            assert_eq!(lines.lock().unwrap().len(), 1, "{reply}");
            assert_eq!(poller.tick(unix_ms()).is_none(), minutes.is_none());
        }
    }

    #[test]
    fn an_unreachable_endpoint_waits_the_floor_and_a_missing_token_never_asks() {
        // Nothing listens here: bind, learn the port, drop.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let cell = Arc::new(QuotaCell::new());
        let (mut poller, lines) =
            poller(&cell, &format!("http://127.0.0.1:{port}/u"), Some(CANARY));
        assert_eq!(poller.tick(unix_ms()), Some(STALE));
        assert!(cell.snapshot().windows.is_empty());
        assert_eq!(lines.lock().unwrap().len(), 1);

        let (url, seen) = serve(vec![http("200 OK", "", "{}")]);
        let (mut poller, lines) = poller(&cell, &url, None);
        assert_eq!(poller.tick(unix_ms()), Some(STALE));
        assert_eq!(requests(&seen), 0);
        assert_eq!(lines.lock().unwrap()[0], State::NoToken.line());
    }

    #[test]
    fn a_state_is_logged_once_until_it_changes() {
        let limited = http("429 Too Many Requests", "", "{}");
        let (url, _) = serve(vec![
            limited.clone(),
            limited,
            http("200 OK", "", &body("null", &reading(35.0))),
        ]);
        let cell = Arc::new(QuotaCell::new());
        let (mut poller, lines) = poller(&cell, &url, Some(CANARY));
        let t = unix_ms();
        poller.tick(t);
        poller.tick(t + 16 * MIN);
        assert_eq!(lines.lock().unwrap().len(), 1, "same state, one line");
        poller.tick(t + 32 * MIN);
        let lines = lines.lock().unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1], State::Polled.line());
    }

    #[test]
    fn nothing_logged_or_stored_holds_the_token() {
        let echo = format!(r#"{{"echo":"{CANARY}"}}"#);
        let (url, _) = serve(vec![
            http("429 Too Many Requests", "Retry-After: 60\r\n", &echo),
            http(
                "200 OK",
                "",
                &format!(r#"{{"five_hour":{},"note":"{CANARY}"}}"#, reading(1.0)),
            ),
            http("403 Forbidden", "", CANARY),
        ]);
        let cell = Arc::new(QuotaCell::new());
        let (mut poller, lines) = poller(&cell, &url, Some(CANARY));
        let t = unix_ms();
        poller.tick(t);
        poller.tick(t + 16 * MIN);
        assert!(poller.tick(t + 32 * MIN).is_none());
        let lines = lines.lock().unwrap();
        assert_eq!(lines.len(), 3, "one line per change of state");
        let seen = format!("{lines:?} {:?}", cell.snapshot());
        assert!(!seen.contains("CANARY"), "{seen}");
    }

    #[test]
    fn stream_and_poll_share_one_cell() {
        let (url, _) = serve(vec![http(
            "200 OK",
            "",
            &body(&reading(6.0), &reading(35.0)),
        )]);
        let cell = Arc::new(QuotaCell::new());
        let (mut poller, _) = poller(&cell, &url, Some(CANARY));
        poller.tick(unix_ms());
        assert_eq!(window(&cell, "five_hour").unwrap().status, "polled");
        // A later stream reading of one window replaces the poll's; the other
        // window keeps the poll's.
        cell.observe([stream_reading("five_hour", 90)]);
        let five = window(&cell, "five_hour").unwrap();
        assert_eq!(
            (five.status.as_str(), five.utilization_permille),
            ("allowed", Some(90))
        );
        assert_eq!(window(&cell, "seven_day").unwrap().status, "polled");
        // And a later poll replaces the stream's.
        let (url, _) = serve(vec![http("200 OK", "", &body(&reading(7.0), "null"))]);
        let (mut again, _) = poller_at(&cell, &url);
        again.tick(unix_ms());
        assert_eq!(
            window(&cell, "five_hour").unwrap().utilization_permille,
            Some(70)
        );
    }

    fn poller_at(cell: &Arc<QuotaCell>, url: &str) -> (Poller, Lines) {
        poller(cell, url, Some(CANARY))
    }
}
