//! The Self-run credential lease over a real unix socket: who may lease, what
//! is reserved before anything is lent, where the token goes, and what each
//! way of ending a lease bills. The ledger is the kit's own; the tests read
//! it only through what the next reservation is allowed to claim. The unit a
//! peer runs in is the `PeerUnits` port, answered here by a fake; one test
//! asks a real systemd where that is available.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use claude_connector::{
    LeaseCaller, LeaseGranted, LeaseLimits, LeaseMessage, LeaseRefusalKind, LeaseRefused,
    LeaseRequest, LeaseSettle, LeaseSettled, PeerUnit, PeerUnits, SystemdUnits, TokenSource,
    decode_frame, encode_frame, serve_leases,
};
use model_connector::{
    CallerAdmission, LeaseAdmission, LeaseRefusal, LeaseTurn, LeaseUse, ModelPrice, ModelUsage,
    Rates, SpendCeiling, SpendWindowMs, TransportService, Usage,
};
use zeroize::Zeroizing;

const CALLER: &str = "eureka";
const MODEL: &str = "claude-opus-5-1";
const TOKEN: &str = "sk-canary-lease-4c1f9a";
const FAR: u64 = 3_000_000_000_000;
const INSTANCE: &str = "eureka";
const UNIT: &str = "mind-self@eureka.service";

static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The 32-digit invocation id of the test's `n`th unit invocation.
fn invocation(n: u64) -> String {
    format!("{n:032x}")
}

type Probe = Box<dyn Fn() + Send + Sync>;

/// A token source that counts its reads and can run a probe at the moment of
/// each one.
struct FakeTokens {
    token: Option<&'static str>,
    reads: AtomicUsize,
    probe: Mutex<Option<Probe>>,
}

impl TokenSource for FakeTokens {
    fn read(&self) -> Option<Zeroizing<String>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(probe) = self.probe.lock().unwrap().as_ref() {
            probe();
        }
        self.token.map(|token| Zeroizing::new(token.to_string()))
    }
}

/// The system's record of where every peer runs, as the test sets it, and the
/// pid each handle it was asked about names (by the kernel's own record).
struct FakeUnits {
    peer: Mutex<Option<PeerUnit>>,
    asked_about: Mutex<Vec<(String, String)>>,
}

impl PeerUnits for FakeUnits {
    fn invocation_in(&self, process: BorrowedFd<'_>, unit: &str) -> Option<PeerUnit> {
        let info =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", process.as_raw_fd())).unwrap();
        let pid = info
            .lines()
            .find_map(|line| line.strip_prefix("Pid:"))
            .unwrap()
            .trim()
            .to_string();
        self.asked_about
            .lock()
            .unwrap()
            .push((pid, unit.to_string()));
        self.peer.lock().unwrap().clone()
    }
}

struct Harness {
    dir: PathBuf,
    socket: PathBuf,
    service: Arc<Mutex<TransportService>>,
    tokens: Arc<FakeTokens>,
    /// The fake behind the listener, when it has one.
    units: Option<Arc<FakeUnits>>,
}

impl Harness {
    /// The peers connect from invocation `n` of the Self unit.
    fn enter(&self, n: u64) {
        self.run_in(UNIT, n);
    }

    fn run_in(&self, unit: &str, n: u64) {
        *self.units.as_ref().unwrap().peer.lock().unwrap() = Some(PeerUnit {
            unit: unit.to_string(),
            invocation_id: invocation(n),
        });
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn price() -> ModelPrice {
    // One micro-USD per token in every class.
    ModelPrice {
        rates: Rates {
            input: 1_000_000,
            cache_write_short: 1_000_000,
            cache_write_long: 1_000_000,
            cache_read: 1_000_000,
            output: 1_000_000,
        },
        long_context: None,
        overhead_tokens: 0,
    }
}

/// What a harness is built from.
struct Setup {
    ceiling: u64,
    reservation: u64,
    uid: u32,
    turn: LeaseTurn,
    token: Option<&'static str>,
    max_connections: usize,
}

fn setup(ceiling: u64, reservation: u64) -> Setup {
    Setup {
        ceiling,
        reservation,
        uid: own_uid(),
        turn: LeaseTurn::SelfRun,
        token: Some(TOKEN),
        max_connections: 8,
    }
}

/// A listener serving `uid` as the caller `eureka`, each of whose leases
/// reserves `reservation`, with a spend window so long that it never rolls
/// over during a test. Peers start in invocation 1 of the Self unit.
fn start(setup: Setup) -> Harness {
    let units = Arc::new(FakeUnits {
        peer: Mutex::new(None),
        asked_about: Mutex::new(Vec::new()),
    });
    let harness = start_with(setup, units.clone(), Some(units), INSTANCE);
    harness.enter(1);
    harness
}

fn start_with(
    setup: Setup,
    units: Arc<dyn PeerUnits>,
    fake: Option<Arc<FakeUnits>>,
    instance: &str,
) -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "claude-lease-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("lease.sock");
    let service = Arc::new(Mutex::new(
        TransportService::open(
            &dir.join("replay.cc"),
            "claude-code",
            BTreeMap::from([(MODEL.to_string(), price())]),
            [CallerAdmission::new(
                CALLER,
                "lease-test-connection-key",
                1,
                [MODEL.to_string()],
                1,
                65_536,
                32_768,
                SpendCeiling(setup.ceiling),
                SpendWindowMs(1 << 50),
            )
            .unwrap()],
            300_000,
        )
        .unwrap(),
    ));
    let tokens = Arc::new(FakeTokens {
        token: setup.token,
        reads: AtomicUsize::new(0),
        probe: Mutex::new(None),
    });
    let listener = UnixListener::bind(&socket).unwrap();
    let serving = (service.clone(), tokens.clone(), units);
    let caller = LeaseCaller {
        uid: setup.uid,
        caller_id: CALLER.to_string(),
        turn: setup.turn,
        unit_instance: instance.to_string(),
        reservation_micro_usd: setup.reservation,
    };
    std::thread::spawn(move || {
        let _ = serve_leases(
            &listener,
            vec![caller],
            LeaseLimits {
                socket_timeout: Duration::from_secs(2),
                max_lease_ms: 3_600_000,
                max_connections: setup.max_connections,
            },
            serving.0,
            serving.1,
            serving.2,
        );
    });
    Harness {
        dir,
        socket,
        service,
        tokens,
        units: fake,
    }
}

/// One frame, and the descriptors that arrived with it. An empty frame is end
/// of file.
fn receive(stream: &UnixStream) -> (Vec<u8>, Vec<OwnedFd>) {
    use std::os::fd::AsRawFd;
    let mut buffer = vec![0_u8; 70_000];
    let mut control = vec![0_u64; 32];
    let mut vector = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    // SAFETY: the buffers outlive the call and the lengths describe them; the
    // descriptors read out of the control messages were just installed in this
    // process by the kernel and are owned by nothing else.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = (control.len() * 8) as _;
        let received = libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC);
        if received < 0 {
            // A listener that drops a connection with our request unread
            // resets it: that is end of file for this test's purposes.
            let error = std::io::Error::last_os_error();
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset, "{error}");
            return (Vec::new(), Vec::new());
        }
        let mut fds = Vec::new();
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = libc::CMSG_DATA(header).cast::<RawFd>();
                for index in 0..bytes / std::mem::size_of::<RawFd>() {
                    fds.push(OwnedFd::from_raw_fd(data.add(index).read_unaligned()));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
        buffer.truncate(received as usize);
        (buffer, fds)
    }
}

fn connect(harness: &Harness) -> UnixStream {
    let stream = UnixStream::connect(&harness.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

fn send(stream: &mut UnixStream, message: &LeaseMessage) {
    stream.write_all(&encode_frame(message)).unwrap();
}

fn request(ttl_ms: u64) -> LeaseMessage {
    LeaseMessage::ClaudeLeaseRequest(LeaseRequest {
        expires_at_unix_ms: now_ms() + ttl_ms,
    })
}

/// What one request to the listener came back with.
struct Answer {
    stream: UnixStream,
    raw: Vec<u8>,
    message: Option<LeaseMessage>,
    fds: Vec<OwnedFd>,
}

fn ask(harness: &Harness, ttl_ms: u64) -> Answer {
    ask_at(&harness.socket, ttl_ms)
}

fn ask_at(socket: &std::path::Path, ttl_ms: u64) -> Answer {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // A listener at its limit has already dropped us: the write may fail.
    let _ = stream.write_all(&encode_frame(&request(ttl_ms)));
    let (raw, fds) = receive(&stream);
    let message = decode_frame(&raw);
    Answer {
        stream,
        raw,
        message,
        fds,
    }
}

fn refusal_of(answer: &Answer) -> Option<LeaseRefusalKind> {
    match &answer.message {
        Some(LeaseMessage::ClaudeLeaseRefusal(LeaseRefused { kind, .. })) => Some(*kind),
        _ => None,
    }
}

fn granted(answer: &Answer) -> LeaseGranted {
    match &answer.message {
        Some(LeaseMessage::ClaudeLeaseGrant(grant)) => grant.clone(),
        other => panic!("expected a grant, got {other:?}"),
    }
}

fn granted_ok(answer: &Answer) -> bool {
    matches!(answer.message, Some(LeaseMessage::ClaudeLeaseGrant(_))) && answer.fds.len() == 1
}

/// Asks, as a fresh unit invocation each time, until the caller's previous
/// lease has been settled by the listener.
fn ask_after_busy(harness: &Harness, first_invocation: u64) -> Answer {
    let deadline = Instant::now() + Duration::from_secs(5);
    for attempt in 0.. {
        harness.enter(first_invocation + attempt);
        let answer = ask(harness, 60_000);
        if refusal_of(&answer) != Some(LeaseRefusalKind::Busy) || Instant::now() > deadline {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    unreachable!()
}

fn used(model: &str, tokens: u64) -> ModelUsage {
    ModelUsage {
        model: model.to_string(),
        usage: Usage {
            input_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            output_tokens: tokens,
            reasoning_tokens: None,
        },
    }
}

fn settle_frame(answer: &Answer, usage: Vec<ModelUsage>) -> Vec<u8> {
    encode_frame(&LeaseMessage::ClaudeLeaseSettle(LeaseSettle {
        lease_id: granted(answer).lease_id,
        usage,
    }))
}

fn settle(answer: &mut Answer, usage: Vec<ModelUsage>) -> LeaseSettled {
    let frame = settle_frame(answer, usage);
    answer.stream.write_all(&frame).unwrap();
    let (raw, _) = receive(&answer.stream);
    match decode_frame(&raw) {
        Some(LeaseMessage::ClaudeLeaseSettled(settled)) => settled,
        other => panic!("expected a settled reply, got {other:?}"),
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Asks the ledger directly for a reservation of `cost`, as an invocation
/// nobody else uses. A grant is left open.
fn probe_reserve(harness: &Harness, name: &str, cost: u64) -> LeaseAdmission {
    harness
        .service
        .lock()
        .unwrap()
        .begin_lease(CALLER, LeaseTurn::SelfRun, name, cost, FAR, now_ms())
        .unwrap()
}

fn ceiling_refused() -> LeaseAdmission {
    LeaseAdmission::Refused(LeaseRefusal::SpendCeiling)
}

#[test]
fn a_grant_passes_one_fd_holding_the_token_then_end_of_file() {
    let harness = start(setup(1_000, 600));
    let mut answer = ask(&harness, 60_000);
    assert_eq!(granted(&answer).reserved_micro_usd, 600);
    assert_eq!(answer.fds.len(), 1);
    // Reading to end of file proves the write end is closed: nobody holds
    // the pipe open for another write.
    let mut read = Vec::new();
    File::from(answer.fds.remove(0))
        .read_to_end(&mut read)
        .unwrap();
    assert_eq!(read, TOKEN.as_bytes());
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn the_lease_is_named_for_the_unit_invocation_not_for_anything_the_peer_says() {
    let harness = start(setup(1_000, 600));
    harness.enter(0xabc);
    let answer = ask(&harness, 60_000);
    assert_eq!(
        granted(&answer).lease_id,
        format!("lease:{}", invocation(0xabc))
    );
}

#[test]
fn the_token_is_in_the_pipe_and_nowhere_else() {
    let harness = start(setup(1_000, 600));
    let mut answer = ask(&harness, 60_000);
    let mut frames = vec![answer.raw.clone()];
    let settled = settle(&mut answer, vec![used(MODEL, 10)]);
    frames.push(encode_frame(&LeaseMessage::ClaudeLeaseSettled(settled)));
    harness.enter(2);
    let refused = ask(&harness, 1);
    frames.push(refused.raw.clone());
    for frame in &frames {
        assert!(!contains(frame, TOKEN));
    }
    assert!(std::env::vars().all(|(name, value)| !name.contains(TOKEN) && !value.contains(TOKEN)));
    assert!(std::env::args().all(|argument| !argument.contains(TOKEN)));
    // The one place it is: the pipe.
    let mut read = String::new();
    File::from(answer.fds.remove(0))
        .read_to_string(&mut read)
        .unwrap();
    assert_eq!(read, TOKEN);
}

#[test]
fn a_peer_uid_outside_the_lease_callers_is_refused_and_nothing_is_reserved_or_read() {
    let harness = start(Setup {
        uid: own_uid() + 1,
        ..setup(1_000, 600)
    });
    let answer = ask(&harness, 60_000);
    assert_eq!(refusal_of(&answer), Some(LeaseRefusalKind::UnknownCaller));
    assert!(answer.fds.is_empty());
    assert!(!contains(&answer.raw, TOKEN));
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
    // The ledger was not touched: the caller's whole ceiling is still free.
    assert!(matches!(
        probe_reserve(&harness, "probe", 1_000),
        LeaseAdmission::Granted(_)
    ));
}

#[test]
fn the_configured_uid_outside_the_self_unit_is_refused_and_nothing_is_reserved_or_read() {
    let harness = start(setup(1_000, 600));
    for (label, peer) in [
        ("another instance", Some(("mind-self@other.service", 1))),
        ("a user service", Some(("huginn.service", 1))),
        ("no unit", None),
    ] {
        *harness.units.as_ref().unwrap().peer.lock().unwrap() = peer.map(|(unit, n)| PeerUnit {
            unit: unit.to_string(),
            invocation_id: invocation(n),
        });
        let answer = ask(&harness, 60_000);
        assert_eq!(
            refusal_of(&answer),
            Some(LeaseRefusalKind::UnknownCaller),
            "{label}"
        );
        assert!(answer.fds.is_empty(), "{label}");
    }
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
    assert!(matches!(
        probe_reserve(&harness, "probe", 1_000),
        LeaseAdmission::Granted(_)
    ));
}

#[test]
fn one_invocation_of_the_self_unit_leases_once_and_the_next_invocation_leases_again() {
    let harness = start(setup(1_000_000, 600));
    let mut first = ask(&harness, 60_000);
    assert!(granted_ok(&first));
    settle(&mut first, vec![used(MODEL, 10)]);
    // Settled, the caller holds nothing; the invocation has still leased.
    let again = ask(&harness, 60_000);
    assert_eq!(refusal_of(&again), Some(LeaseRefusalKind::Busy));
    assert!(again.fds.is_empty());
    harness.enter(2);
    assert!(granted_ok(&ask(&harness, 60_000)));
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 2);
}

#[test]
fn the_reservation_is_claimed_before_the_token_is_read_or_lent() {
    let harness = start(setup(1_000, 600));
    let seen = Arc::new(Mutex::new(None));
    let (service, sink) = (harness.service.clone(), seen.clone());
    *harness.tokens.probe.lock().unwrap() = Some(Box::new(move || {
        // From inside the token read: the caller already holds a lease.
        let admission = service
            .lock()
            .unwrap()
            .begin_lease(CALLER, LeaseTurn::SelfRun, "probe", 1, FAR, now_ms())
            .unwrap();
        *sink.lock().unwrap() = Some(admission);
    }));
    let answer = ask(&harness, 60_000);
    assert_eq!(answer.fds.len(), 1);
    assert_eq!(
        *seen.lock().unwrap(),
        Some(LeaseAdmission::Refused(LeaseRefusal::Busy))
    );
}

#[test]
fn a_reservation_the_window_cannot_hold_is_refused_and_lends_nothing() {
    let harness = start(setup(1_000, 1_001));
    let answer = ask(&harness, 60_000);
    assert_eq!(refusal_of(&answer), Some(LeaseRefusalKind::SpendCeiling));
    assert!(answer.fds.is_empty());
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
    // Exactly the ceiling fits.
    let harness = start(setup(1_000, 1_000));
    assert!(granted_ok(&ask(&harness, 60_000)));
}

#[test]
fn a_free_lease_and_a_bad_expiry_are_refused() {
    let harness = start(setup(1_000, 0));
    assert_eq!(
        refusal_of(&ask(&harness, 60_000)),
        Some(LeaseRefusalKind::CostBound)
    );
    let harness = start(setup(1_000, 100));
    for ttl in [0, 3_600_001 + 1_000] {
        let mut stream = connect(&harness);
        let expires_at_unix_ms = if ttl == 0 { 1 } else { now_ms() + ttl };
        send(
            &mut stream,
            &LeaseMessage::ClaudeLeaseRequest(LeaseRequest { expires_at_unix_ms }),
        );
        let (raw, fds) = receive(&stream);
        assert!(fds.is_empty());
        assert!(matches!(
            decode_frame(&raw),
            Some(LeaseMessage::ClaudeLeaseRefusal(LeaseRefused {
                kind: LeaseRefusalKind::Expired,
                ..
            }))
        ));
    }
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn a_second_open_lease_for_the_caller_is_busy_even_from_another_invocation() {
    let harness = start(setup(1_000_000, 100));
    let first = ask(&harness, 60_000);
    assert!(granted_ok(&first));
    harness.enter(2);
    let second = ask(&harness, 60_000);
    assert_eq!(refusal_of(&second), Some(LeaseRefusalKind::Busy));
    assert!(second.fds.is_empty());
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn settlement_bills_the_true_cost_of_each_models_use_and_the_window_holds_it() {
    let harness = start(setup(1_000, 600));
    let mut first = ask(&harness, 60_000);
    // One micro-USD a token: 250 of the priced model, and 100 of a model the
    // table has never heard of, which bills at the dearest known price.
    let settled = settle(
        &mut first,
        vec![used(MODEL, 250), used("claude-new-9", 100)],
    );
    assert_eq!(
        (settled.billed_micro_usd, settled.overrun_micro_usd),
        (350, 0)
    );
    // 350 spent: 650 remain, not 651.
    assert_eq!(probe_reserve(&harness, "over", 651), ceiling_refused());
    assert!(matches!(
        probe_reserve(&harness, "fits", 650),
        LeaseAdmission::Granted(_)
    ));
}

#[test]
fn usage_above_the_reservation_is_billed_in_full_and_the_overrun_is_reported_and_counted() {
    let harness = start(setup(1_000, 100));
    let mut first = ask(&harness, 60_000);
    let settled = settle(&mut first, vec![used(MODEL, 700), used(MODEL, 5_000)]);
    assert_eq!(settled.billed_micro_usd, 5_700);
    assert_eq!(settled.overrun_micro_usd, 5_600);
    // The window is past its ceiling: nothing more reserves in it.
    assert_eq!(probe_reserve(&harness, "next", 1), ceiling_refused());
}

#[test]
fn a_plan_quota_the_run_reports_is_not_part_of_the_protocol() {
    // A settle in the shape the first protocol used, with a plan_quota the
    // run vouches for: the extra key is ignored and the usage is billed.
    let harness = start(setup(1_000, 600));
    let mut first = ask(&harness, 60_000);
    let legacy = serde_json::json!({
        "kind": "claude_lease_settle",
        "value": {
            "lease_id": granted(&first).lease_id,
            "usage": [{"model": MODEL, "usage": {
                "input_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0,
                "output_tokens": 40, "reasoning_tokens": null}}],
            "plan_quota": [{"window": "five_hour", "utilization_permille": 0,
                "resets_at_unix_ms": 1, "status": "allowed", "observed_at_unix_ms": 1}]
        }
    });
    let body = rmp_serde::to_vec_named(&legacy).unwrap();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    first.stream.write_all(&frame).unwrap();
    let (raw, _) = receive(&first.stream);
    assert!(matches!(
        decode_frame(&raw),
        Some(LeaseMessage::ClaudeLeaseSettled(LeaseSettled {
            billed_micro_usd: 40,
            overrun_micro_usd: 0
        }))
    ));
}

#[test]
fn a_connection_dropped_without_settling_is_billed_the_reservation() {
    let harness = start(setup(1_000, 600));
    let first = ask(&harness, 60_000);
    assert!(granted_ok(&first));
    drop(first);
    let over = ask_after_busy(&harness, 2);
    assert_eq!(refusal_of(&over), Some(LeaseRefusalKind::SpendCeiling));
    assert_eq!(probe_reserve(&harness, "over", 401), ceiling_refused());
    assert!(matches!(
        probe_reserve(&harness, "fits", 400),
        LeaseAdmission::Granted(_)
    ));
}

#[test]
fn a_lease_that_expires_unsettled_is_closed_and_billed_the_reservation() {
    let harness = start(setup(1_000, 600));
    let first = ask(&harness, 400);
    assert!(granted_ok(&first));
    let started = Instant::now();
    // The listener, not the client, ends the lease at its expiry.
    let (raw, fds) = receive(&first.stream);
    assert!(raw.is_empty() && fds.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(250));
    harness.enter(2);
    let over = ask(&harness, 60_000);
    assert_eq!(refusal_of(&over), Some(LeaseRefusalKind::SpendCeiling));
}

#[test]
fn a_settle_trickled_past_the_expiry_is_no_report_and_bills_the_reservation() {
    let harness = start(setup(1_000, 600));
    let mut answer = ask(&harness, 1_500);
    let frame = settle_frame(&answer, vec![used(MODEL, 10)]);
    let chunk = frame.len() / 4 + 1;
    // Each write lands inside any per-read wait; the frame does not land
    // inside the lease.
    for (i, part) in frame.chunks(chunk).enumerate() {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(1_200));
        }
        let _ = answer.stream.write_all(part);
    }
    let (raw, _) = receive(&answer.stream);
    assert!(raw.is_empty(), "{:?}", decode_frame(&raw));
    assert_eq!(probe_reserve(&harness, "over", 401), ceiling_refused());
}

#[test]
fn a_request_trickled_past_the_socket_timeout_is_dropped_without_a_reservation() {
    let harness = start(setup(1_000, 600));
    let mut stream = connect(&harness);
    let started = Instant::now();
    // Three bytes of a length, 0.9 s apart, then silence: every wait is inside
    // the 2 s socket timeout, the frame is not.
    for byte in [0_u8, 0, 0] {
        stream.write_all(&[byte]).unwrap();
        std::thread::sleep(Duration::from_millis(900));
    }
    let (raw, fds) = receive(&stream);
    assert!(raw.is_empty() && fds.is_empty());
    assert!(
        started.elapsed() < Duration::from_millis(3_300),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
    assert!(matches!(
        probe_reserve(&harness, "probe", 1_000),
        LeaseAdmission::Granted(_)
    ));
}

#[test]
fn a_settle_for_another_lease_is_no_report_and_bills_the_reservation() {
    let harness = start(setup(1_000, 600));
    let mut first = ask(&harness, 60_000);
    send(
        &mut first.stream,
        &LeaseMessage::ClaudeLeaseSettle(LeaseSettle {
            lease_id: "lease:someone-else".to_string(),
            usage: vec![used(MODEL, 1)],
        }),
    );
    let (raw, _) = receive(&first.stream);
    assert!(raw.is_empty());
    harness.enter(2);
    let over = ask(&harness, 60_000);
    assert_eq!(refusal_of(&over), Some(LeaseRefusalKind::SpendCeiling));
}

#[test]
fn a_settle_that_reports_nothing_is_billed_the_reservation() {
    let harness = start(setup(1_000, 600));
    let mut first = ask(&harness, 60_000);
    let settled = settle(&mut first, vec![]);
    assert_eq!(
        (settled.billed_micro_usd, settled.overrun_micro_usd),
        (600, 0)
    );
    // 600 spent: the whole ceiling no longer reserves.
    assert_eq!(probe_reserve(&harness, "all", 1_000), ceiling_refused());
}

#[test]
fn a_token_that_cannot_be_read_is_never_lent_and_bills_nothing() {
    let harness = start(Setup {
        token: None,
        ..setup(1_000, 1_000)
    });
    let first = ask(&harness, 60_000);
    assert!(first.raw.is_empty() && first.fds.is_empty());
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 1);
    // Nothing was billed: the whole ceiling reserves again and gets as far
    // as the token read, not a refusal.
    let again = ask_after_busy(&harness, 2);
    assert!(again.message.is_none() && again.fds.is_empty());
    assert!(harness.tokens.reads.load(Ordering::SeqCst) >= 2);
}

#[test]
fn a_malformed_or_oversized_frame_is_dropped_without_a_reservation() {
    let harness = start(setup(1_000, 1_000));
    for bytes in [
        vec![0xff, 0xff, 0xff, 0xff],
        vec![0, 0, 0, 0],
        vec![0, 0, 0, 3, 0xc1, 0xc1, 0xc1],
    ] {
        let mut stream = connect(&harness);
        stream.write_all(&bytes).unwrap();
        let started = Instant::now();
        let (raw, fds) = receive(&stream);
        assert!(raw.is_empty() && fds.is_empty());
        // Refused at once, not after the socket timeout of a read that was
        // never going to complete.
        assert!(started.elapsed() < Duration::from_millis(1_000));
    }
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
    assert!(granted_ok(&ask(&harness, 60_000)));
}

#[test]
fn every_message_kind_is_the_pinned_bytes_of_its_fixture() {
    let expires = 1_793_307_000_000;
    let lease = format!("lease:{}", "0123456789abcdef0123456789abcdef");
    let messages = [
        (
            &include_bytes!("fixtures/lease_v1/request.bin")[..],
            LeaseMessage::ClaudeLeaseRequest(LeaseRequest {
                expires_at_unix_ms: expires,
            }),
        ),
        (
            &include_bytes!("fixtures/lease_v1/grant.bin")[..],
            LeaseMessage::ClaudeLeaseGrant(LeaseGranted {
                lease_id: lease.clone(),
                reserved_micro_usd: 600_000,
            }),
        ),
        (
            &include_bytes!("fixtures/lease_v1/refusal.bin")[..],
            LeaseMessage::ClaudeLeaseRefusal(LeaseRefused {
                kind: LeaseRefusalKind::SpendCeiling,
                detail: "the window cannot hold this reservation".to_string(),
            }),
        ),
        (
            &include_bytes!("fixtures/lease_v1/settle.bin")[..],
            LeaseMessage::ClaudeLeaseSettle(LeaseSettle {
                lease_id: lease,
                usage: vec![
                    ModelUsage {
                        model: "claude-opus-5-1".to_string(),
                        usage: Usage {
                            input_tokens: 1_200,
                            cache_read_tokens: 30_000,
                            cache_write_tokens: 500,
                            output_tokens: 800,
                            reasoning_tokens: Some(100),
                        },
                    },
                    ModelUsage {
                        model: "claude-haiku-5-1".to_string(),
                        usage: Usage {
                            input_tokens: 400,
                            cache_read_tokens: 0,
                            cache_write_tokens: 0,
                            output_tokens: 60,
                            reasoning_tokens: None,
                        },
                    },
                ],
            }),
        ),
        (
            &include_bytes!("fixtures/lease_v1/settled.bin")[..],
            LeaseMessage::ClaudeLeaseSettled(LeaseSettled {
                billed_micro_usd: 123_456,
                overrun_micro_usd: 23_456,
            }),
        ),
    ];
    for (bytes, message) in messages {
        assert_eq!(encode_frame(&message), bytes, "{message:?}");
        assert_eq!(decode_frame(bytes), Some(message));
    }
}

#[test]
fn connections_past_the_limit_are_dropped_and_finished_ones_free_their_place() {
    let harness = start(Setup {
        max_connections: 2,
        ..setup(1_000, 0)
    });
    let held: Vec<UnixStream> = (0..2).map(|_| connect(&harness)).collect();
    // Let the listener take both before the third arrives.
    std::thread::sleep(Duration::from_millis(300));
    let third = ask(&harness, 60_000);
    assert!(third.raw.is_empty() && third.fds.is_empty());
    drop(held);
    // Finished connections give their places back: more refusals in a row
    // than the limit holds, each answered.
    let first = ask_until_answered(&harness);
    assert_eq!(refusal_of(&first), Some(LeaseRefusalKind::CostBound));
    for _ in 0..4 {
        let again = ask(&harness, 60_000);
        assert_eq!(refusal_of(&again), Some(LeaseRefusalKind::CostBound));
    }
}

/// A free lease, asked until the listener answers instead of dropping.
fn ask_until_answered(harness: &Harness) -> Answer {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let answer = ask(harness, 60_000);
        if !answer.raw.is_empty() || Instant::now() > deadline {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn an_account_resolves_to_its_uid_and_a_missing_one_to_none() {
    use claude_connector::user_uid;
    assert_eq!(user_uid("root"), Some(0));
    assert_eq!(user_uid("nobody"), Some(65534));
    assert_eq!(user_uid("no-such-account-4f1c"), None);
    assert_eq!(user_uid("bad name"), None);
}

#[test]
fn a_token_up_to_one_atomic_pipe_write_is_lent_and_a_longer_one_is_not() {
    let fits: &'static str = Box::leak("t".repeat(4096).into_boxed_str());
    let harness = start(Setup {
        token: Some(fits),
        ..setup(1_000, 100)
    });
    let mut answer = ask(&harness, 60_000);
    let mut read = Vec::new();
    File::from(answer.fds.remove(0))
        .read_to_end(&mut read)
        .unwrap();
    assert_eq!(read.len(), 4096);

    let too_long: &'static str = Box::leak("t".repeat(4097).into_boxed_str());
    let harness = start(Setup {
        token: Some(too_long),
        ..setup(1_000, 100)
    });
    let answer = ask(&harness, 60_000);
    assert!(answer.raw.is_empty() && answer.fds.is_empty());
}

// ---- a second real uid (Soul s1, kept as a regression) ----

fn describe(answer: &Answer) -> String {
    let kind = match &answer.message {
        Some(LeaseMessage::ClaudeLeaseGrant(_)) => "grant".to_string(),
        Some(LeaseMessage::ClaudeLeaseRefusal(r)) => format!("refusal:{:?}", r.kind),
        Some(other) => format!("other:{other:?}"),
        None => format!("none(raw={})", answer.raw.len()),
    };
    format!("kind={kind} fds={}", answer.fds.len())
}

/// The child half of the second-uid test: connects to `LEASE_SOCK` as whoever
/// it was started as and prints one line saying what came back. The fake
/// canary token is never printed, only whether it matched.
#[test]
#[ignore = "run as a child of a_second_real_uid_cannot_lease"]
fn lease_probe_client() {
    let socket = PathBuf::from(std::env::var("LEASE_SOCK").unwrap());
    let mut answer = ask_at(&socket, 60_000);
    let shown = describe(&answer);
    let mut token_matches = false;
    if !answer.fds.is_empty() {
        let mut read = Vec::new();
        File::from(answer.fds.remove(0))
            .read_to_end(&mut read)
            .unwrap();
        token_matches = read == TOKEN.as_bytes();
    }
    println!(
        "LEASEPROBE uid={} {} token_matches_canary={token_matches}",
        own_uid(),
        shown
    );
}

/// Runs the probe client as `reuid`, with primary group `regid` and
/// supplementary `groups`, and returns its LEASEPROBE line. The marker is
/// found anywhere on a line: the test harness prints it after its own prefix.
fn probe_as(socket: &std::path::Path, reuid: u32, regid: u32, groups: &str) -> String {
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new("setpriv")
        .arg(format!("--reuid={reuid}"))
        .arg(format!("--regid={regid}"))
        .arg(format!("--groups={groups}"))
        .arg(&exe)
        .args([
            "--exact",
            "lease_probe_client",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("LEASE_SOCK", socket)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    stdout
        .lines()
        .find_map(|line| line.find("LEASEPROBE").map(|at| line[at..].to_string()))
        .unwrap_or_else(|| {
            format!(
                "NO-LINE status={:?} stdout={stdout:?} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        })
}

fn have(tool: &str) -> bool {
    std::process::Command::new(tool)
        .arg("--version")
        .output()
        .is_ok()
}

#[test]
fn a_second_real_uid_cannot_lease() {
    use std::os::unix::fs::PermissionsExt;
    if own_uid() != 0 || !have("setpriv") {
        eprintln!("SKIPPED a_second_real_uid_cannot_lease: needs root and setpriv");
        return;
    }
    // Numeric uids need no account: 4242 is the configured Self user, 4243 a
    // second account that shares its groups.
    let harness = start(Setup {
        uid: 4242,
        ..setup(1_000_000, 600)
    });
    std::fs::set_permissions(&harness.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&harness.socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    // Another uid, in the caller's group and the lease group.
    let a = probe_as(&harness.socket, 4243, 4243, "4242,4244");
    // Another uid whose primary gid is the caller's.
    let b = probe_as(&harness.socket, 4243, 4242, "4242");
    // Root, which is not configured.
    let root = describe(&ask(&harness, 60_000));
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
    // The configured uid does lease.
    let c = probe_as(&harness.socket, 4242, 4242, "4242");
    assert!(a.contains("kind=refusal:UnknownCaller fds=0"), "{a}");
    assert!(b.contains("kind=refusal:UnknownCaller fds=0"), "{b}");
    assert!(root.contains("kind=refusal:UnknownCaller fds=0"), "{root}");
    assert!(
        c.contains("kind=grant fds=1") && c.contains("token_matches_canary=true"),
        "{c}"
    );
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 1);
}

// ---- a real systemd, where there is one ----

/// The child half of the systemd test, run inside a transient service: leases,
/// settles, and leases again from the same invocation.
#[test]
#[ignore = "run inside a transient unit by a_real_systemd_unit_invocation_leases_once"]
fn lease_in_unit_client() {
    let socket = PathBuf::from(std::env::var("LEASE_SOCK").unwrap());
    let mut first = ask_at(&socket, 60_000);
    let first_kind = describe(&first);
    if granted_ok(&first) {
        settle(&mut first, Vec::new());
    }
    let second = ask_at(&socket, 60_000);
    println!(
        "LEASEPROBE first[{first_kind}] second[{}]",
        describe(&second)
    );
}

fn run_in_unit(socket: &std::path::Path) -> String {
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new("systemd-run")
        .args([
            "--unit=mind-self@leasetest.service",
            "--pipe",
            "--wait",
            "--collect",
            "--quiet",
        ])
        .arg(format!("--setenv=LEASE_SOCK={}", socket.display()))
        .arg(&exe)
        .args([
            "--exact",
            "lease_in_unit_client",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    stdout
        .lines()
        .find_map(|line| line.find("LEASEPROBE").map(|at| line[at..].to_string()))
        .unwrap_or_else(|| {
            format!(
                "NO-LINE status={:?} stdout={stdout:?} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        })
}

#[test]
fn a_real_systemd_unit_invocation_leases_once() {
    if own_uid() != 0
        || !std::path::Path::new("/run/systemd/system").exists()
        || !have("systemd-run")
    {
        eprintln!(
            "SKIPPED a_real_systemd_unit_invocation_leases_once: needs root, systemd as init and systemd-run"
        );
        return;
    }
    // The listener asks the production resolver, not the fake.
    let harness = start_with(
        setup(1_000_000, 600),
        Arc::new(SystemdUnits::system()),
        None,
        "leasetest",
    );
    let leased_then_busy = "first[kind=grant fds=1] second[kind=refusal:Busy fds=0]";
    // Two invocations of the same unit: each leases once, as its own.
    let one = run_in_unit(&harness.socket);
    let two = run_in_unit(&harness.socket);
    assert!(one.contains(leased_then_busy), "{one}");
    assert!(two.contains(leased_then_busy), "{two}");
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 2);
    // A process outside any such unit is not a Self run, though its uid is
    // the configured one.
    let outside = ask(&harness, 60_000);
    assert_eq!(refusal_of(&outside), Some(LeaseRefusalKind::UnknownCaller));
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 2);
}

#[test]
fn the_peer_is_named_by_a_process_handle_not_a_pid_number() {
    let (one, _other) = UnixStream::pair().unwrap();
    let peer = claude_connector::peer_credentials(&one).unwrap();
    assert_eq!(peer.uid, own_uid());
    let process = peer.process.expect("SO_PEERPIDFD on this kernel");
    let info =
        std::fs::read_to_string(format!("/proc/self/fdinfo/{}", process.as_raw_fd())).unwrap();
    assert!(
        info.lines()
            .any(|line| line.strip_prefix("Pid:").map(str::trim)
                == Some(&std::process::id().to_string())),
        "{info}"
    );
}

#[test]
fn the_unit_is_asked_of_the_callers_unit_through_the_peers_handle() {
    let harness = start(setup(1_000, 600));
    let answer = ask(&harness, 60_000);
    assert!(refusal_of(&answer).is_none() && answer.fds.len() == 1);
    assert_eq!(
        *harness.units.as_ref().unwrap().asked_about.lock().unwrap(),
        vec![(std::process::id().to_string(), UNIT.to_string())]
    );
}

const PERSONA_UNIT: &str = "mind-persona@eureka.service";

/// A listener whose one lease caller is a Persona account; peers start in
/// invocation 1 of the Persona unit.
fn start_persona(setup: Setup) -> Harness {
    let units = Arc::new(FakeUnits {
        peer: Mutex::new(None),
        asked_about: Mutex::new(Vec::new()),
    });
    let harness = start_with(
        Setup {
            turn: LeaseTurn::PersonaTurn,
            ..setup
        },
        units.clone(),
        Some(units),
        INSTANCE,
    );
    harness.run_in(PERSONA_UNIT, 1);
    harness
}

fn lease_on(harness: &Harness, turn: LeaseTurn, invocation: &str) -> LeaseAdmission {
    harness
        .service
        .lock()
        .unwrap()
        .begin_lease(CALLER, turn, invocation, 100, FAR, now_ms())
        .unwrap()
}

fn lease_id(admission: &LeaseAdmission) -> String {
    match admission {
        LeaseAdmission::Granted(grant) => grant.lease_id.clone(),
        other => panic!("expected a grant, got {other:?}"),
    }
}

fn busy() -> LeaseAdmission {
    LeaseAdmission::Refused(LeaseRefusal::Busy)
}

#[test]
fn persona_and_self_of_one_caller_lease_together() {
    let harness = start(setup(1_000_000, 100));
    let own = lease_on(&harness, LeaseTurn::SelfRun, "self-run");
    assert_eq!(lease_id(&own), "lease:self-run");
    let persona = lease_on(&harness, LeaseTurn::PersonaTurn, "persona-run");
    assert_eq!(lease_id(&persona), "lease:persona-run:1");
    // Each turn kind still holds one: a second Self run is busy while the
    // first is open, a second Persona lease of the same invocation too.
    assert_eq!(lease_on(&harness, LeaseTurn::SelfRun, "self-run-2"), busy());
    assert_eq!(
        lease_on(&harness, LeaseTurn::PersonaTurn, "persona-run"),
        busy()
    );
    // Settling the Persona lease frees nothing of the Self lease's.
    harness
        .service
        .lock()
        .unwrap()
        .settle_lease(CALLER, "lease:persona-run:1", LeaseUse::Reservation)
        .unwrap();
    assert_eq!(lease_on(&harness, LeaseTurn::SelfRun, "self-run-2"), busy());
}

#[test]
fn persona_invocation_leases_sequentially() {
    let harness = start(setup(1_000_000, 100));
    for expected in 1..=3 {
        let granted = lease_on(&harness, LeaseTurn::PersonaTurn, "persona-run");
        let id = lease_id(&granted);
        assert_eq!(id, format!("lease:persona-run:{expected}"));
        harness
            .service
            .lock()
            .unwrap()
            .settle_lease(CALLER, &id, LeaseUse::Reservation)
            .unwrap();
    }
    // Another invocation counts from one: the sequence is per invocation.
    let other = lease_on(&harness, LeaseTurn::PersonaTurn, "persona-other");
    assert_eq!(lease_id(&other), "lease:persona-other:1");
}

#[test]
fn persona_invocation_second_open_lease_busy() {
    let harness = start_persona(setup(1_000_000, 100));
    let first = ask(&harness, 60_000);
    assert!(granted_ok(&first));
    let second = ask(&harness, 60_000);
    assert_eq!(refusal_of(&second), Some(LeaseRefusalKind::Busy));
    assert!(second.fds.is_empty());
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn persona_turns_of_a_live_invocation_each_lend_a_token_over_the_socket() {
    let harness = start_persona(setup(1_000_000, 100));
    for _ in 0..2 {
        let mut answer = ask(&harness, 60_000);
        assert!(granted_ok(&answer));
        settle(&mut answer, vec![used(MODEL, 10)]);
    }
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 2);
}

#[test]
fn self_invocation_still_leases_once() {
    let harness = start(setup(1_000_000, 100));
    let id = lease_id(&lease_on(&harness, LeaseTurn::SelfRun, "self-run"));
    harness
        .service
        .lock()
        .unwrap()
        .settle_lease(CALLER, &id, LeaseUse::Reservation)
        .unwrap();
    assert_eq!(lease_on(&harness, LeaseTurn::SelfRun, "self-run"), busy());
}

#[test]
fn persona_row_refuses_mind_self_unit() {
    let harness = start_persona(setup(1_000_000, 100));
    harness.run_in(UNIT, 1);
    let answer = ask(&harness, 60_000);
    assert_eq!(refusal_of(&answer), Some(LeaseRefusalKind::UnknownCaller));
    assert!(answer.fds.is_empty());
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
    // And a Self row refuses the Persona unit.
    let harness = start(setup(1_000_000, 100));
    harness.run_in(PERSONA_UNIT, 1);
    let answer = ask(&harness, 60_000);
    assert_eq!(refusal_of(&answer), Some(LeaseRefusalKind::UnknownCaller));
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn a_persona_lease_reserves_and_settles_in_the_callers_window() {
    let harness = start(setup(1_000, 600));
    let id = lease_id(&lease_on(&harness, LeaseTurn::PersonaTurn, "persona-run"));
    // 100 reserved by the helper; a Self probe of 901 cannot fit, 900 can.
    assert_eq!(probe_reserve(&harness, "p1", 901), ceiling_refused());
    harness
        .service
        .lock()
        .unwrap()
        .settle_lease(CALLER, &id, LeaseUse::NeverLent)
        .unwrap();
    assert!(matches!(
        probe_reserve(&harness, "p2", 1_000),
        LeaseAdmission::Granted(_)
    ));
}
