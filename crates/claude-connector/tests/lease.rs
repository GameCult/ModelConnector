//! The Self-run credential lease over a real unix socket: who may lease, where
//! the token goes, what ends a lease, and the one usage-derived refusal, the
//! provider's own. Nothing is reserved and nothing is billed. The unit a peer
//! runs in is the `PeerUnits` port, answered here by a fake.
#![cfg(target_os = "linux")]

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
    LeaseRequest, PeerUnit, PeerUnits, QuotaCell, TokenSource, decode_frame, encode_frame,
    serve_leases,
};
use model_connector::{CallerAdmission, LeaseTurn, PlanQuota, TransportService};
use zeroize::Zeroizing;

const CALLER: &str = "eureka";
const MODEL: &str = "claude-opus-5-1";
const TOKEN: &str = "sk-canary-lease-4c1f9a";
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
    _service: Arc<Mutex<TransportService>>,
    quota: Arc<QuotaCell>,
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

fn request(ttl_ms: u64) -> LeaseMessage {
    LeaseMessage::ClaudeLeaseRequest(LeaseRequest {
        expires_at_unix_ms: now_ms() + ttl_ms,
    })
}

/// What one request to the listener came back with.
struct Answer {
    _stream: UnixStream,
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
        _stream: stream,
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

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// What a harness is built from.
struct Setup {
    uid: u32,
    turn: LeaseTurn,
    token: Option<&'static str>,
    max_connections: usize,
}

fn setup() -> Setup {
    Setup {
        uid: own_uid(),
        turn: LeaseTurn::SelfRun,
        token: Some(TOKEN),
        max_connections: 8,
    }
}

/// A listener serving `uid` as the caller `eureka`. Peers start in invocation
/// 1 of the Self unit.
fn start(setup: Setup) -> Harness {
    let units = Arc::new(FakeUnits {
        peer: Mutex::new(None),
        asked_about: Mutex::new(Vec::new()),
    });
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
            [CallerAdmission::new(
                CALLER,
                "lease-test-connection-key",
                1,
                [MODEL.to_string()],
                1,
                65_536,
                32_768,
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
    let quota = Arc::new(QuotaCell::new());
    let listener = UnixListener::bind(&socket).unwrap();
    let serving = (
        service.clone(),
        quota.clone(),
        tokens.clone(),
        units.clone(),
    );
    let caller = LeaseCaller {
        uid: setup.uid,
        caller_id: CALLER.to_string(),
        turn: setup.turn,
        unit_instance: INSTANCE.to_string(),
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
            serving.3,
        );
    });
    let harness = Harness {
        dir,
        socket,
        _service: service,
        quota,
        tokens,
        units: Some(units),
    };
    harness.enter(1);
    harness
}

fn window(name: &str, permille: u32, status: &str, resets_at_unix_ms: u64) -> PlanQuota {
    PlanQuota {
        window: name.to_string(),
        utilization_permille: Some(permille),
        resets_at_unix_ms,
        status: status.to_string(),
        observed_at_unix_ms: 0,
    }
}

/// Asks as fresh unit invocations until a lease is granted, or panics.
fn ask_until_granted(harness: &Harness, first_invocation: u64) -> Answer {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut n = first_invocation;
    loop {
        harness.enter(n);
        let answer = ask(harness, 60_000);
        if granted_ok(&answer) {
            return answer;
        }
        assert!(Instant::now() < deadline, "no lease was ever granted");
        n += 1;
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_grant_passes_one_fd_holding_the_token_then_end_of_file() {
    let harness = start(setup());
    let mut answer = ask(&harness, 60_000);
    assert_eq!(
        granted(&answer).lease_id,
        format!("lease:{}", invocation(1))
    );
    assert_eq!(answer.fds.len(), 1);
    let mut read = Vec::new();
    File::from(answer.fds.remove(0))
        .read_to_end(&mut read)
        .unwrap();
    assert_eq!(read, TOKEN.as_bytes());
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 1);
    assert!(
        !contains(&answer.raw, TOKEN),
        "the token is in the pipe only"
    );
}

#[test]
fn a_grant_carries_the_plan_usage_as_the_connector_last_saw_it() {
    let harness = start(setup());
    let reset = now_ms() + 3_600_000;
    harness
        .quota
        .observe([window("five_hour", 420, "allowed", reset)]);
    let answer = ask(&harness, 60_000);
    let quota = granted(&answer).plan_quota;
    assert_eq!(quota.len(), 1);
    assert_eq!(quota[0].window, "five_hour");
    assert_eq!(quota[0].utilization_permille, Some(420));
    assert_eq!(quota[0].status, "allowed");
    assert_eq!(quota[0].resets_at_unix_ms, reset);
}

#[test]
fn a_lease_ends_when_its_holder_closes() {
    let harness = start(setup());
    let first = ask(&harness, 60_000);
    assert!(granted_ok(&first));
    harness.enter(2);
    let second = ask(&harness, 60_000);
    assert_eq!(refusal_of(&second), Some(LeaseRefusalKind::Busy));
    assert!(second.fds.is_empty());
    drop(first);
    let third = ask_until_granted(&harness, 3);
    assert!(granted_ok(&third));
}

#[test]
fn a_lease_ends_when_its_unit_invocation_ends() {
    let harness = start(setup());
    let first = ask(&harness, 60_000);
    assert!(granted_ok(&first));
    // The invocation is over: the system no longer places the peer in it. The
    // holder still has its socket open, and the lease does not outlive it.
    *harness.units.as_ref().unwrap().peer.lock().unwrap() = None;
    std::thread::sleep(Duration::from_millis(1_200));
    harness.enter(2);
    assert!(granted_ok(&ask(&harness, 60_000)));
    drop(first);
}

#[test]
fn a_lease_ends_at_its_expiry_though_its_holder_is_still_there() {
    let harness = start(setup());
    let first = ask(&harness, 700);
    assert!(granted_ok(&first));
    let next = ask_until_granted(&harness, 2);
    assert!(granted_ok(&next));
    drop(first);
}

#[test]
fn a_rejected_window_refuses_the_lease_until_its_reset() {
    let harness = start(setup());
    let reset = now_ms() + 1_500;
    harness
        .quota
        .observe([window("five_hour", 1_000, "rejected", reset)]);
    let refused = ask(&harness, 60_000);
    assert_eq!(
        refusal_of(&refused),
        Some(LeaseRefusalKind::ProviderRejected)
    );
    assert!(refused.fds.is_empty());
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
    // At the provider's own reset the refusal lifts, with no one lifting it.
    let lifted = ask_until_granted(&harness, 2);
    assert!(granted_ok(&lifted));
    assert!(now_ms() >= reset);
}

#[test]
fn high_utilization_refuses_nothing() {
    let harness = start(setup());
    let reset = now_ms() + 3_600_000;
    harness.quota.observe([
        window("five_hour", 999, "allowed", reset),
        window("seven_day", 1_000, "allowed_warning", reset),
    ]);
    assert!(granted_ok(&ask(&harness, 60_000)));
}

#[test]
fn a_peer_uid_outside_the_lease_callers_is_refused_and_nothing_is_read() {
    let harness = start(Setup {
        uid: own_uid().wrapping_add(1),
        ..setup()
    });
    let answer = ask(&harness, 60_000);
    assert_eq!(refusal_of(&answer), Some(LeaseRefusalKind::UnknownCaller));
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn the_configured_uid_outside_the_self_unit_is_refused_and_nothing_is_read() {
    let harness = start(setup());
    harness.run_in("mind-persona@eureka.service", 1);
    let answer = ask(&harness, 60_000);
    assert_eq!(refusal_of(&answer), Some(LeaseRefusalKind::UnknownCaller));
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn an_expiry_in_the_past_or_past_the_bound_is_refused() {
    let harness = start(setup());
    let past = ask(&harness, 0);
    assert_eq!(refusal_of(&past), Some(LeaseRefusalKind::Expired));
    let far = ask(&harness, 3_600_001 + 60_000);
    assert_eq!(refusal_of(&far), Some(LeaseRefusalKind::Expired));
    assert_eq!(harness.tokens.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn a_token_that_cannot_be_read_is_never_lent_and_frees_the_lease() {
    let harness = start(Setup {
        token: None,
        ..setup()
    });
    let first = ask(&harness, 60_000);
    assert!(first.raw.is_empty() && first.fds.is_empty());
    harness.enter(2);
    let again = ask(&harness, 60_000);
    assert!(again.message.is_none() && again.fds.is_empty(), "not Busy");
    assert!(harness.tokens.reads.load(Ordering::SeqCst) >= 2);
}

#[test]
fn the_protocol_has_no_settle_frame() {
    let grant = encode_frame(&LeaseMessage::ClaudeLeaseGrant(LeaseGranted {
        lease_id: "lease:x".to_string(),
        plan_quota: Vec::new(),
    }));
    let value: rmpv::Value = rmp_serde::from_slice(&grant[4..]).unwrap();
    assert_eq!(
        value,
        rmpv::Value::Map(vec![
            ("kind".into(), "claude_lease_grant".into()),
            (
                "value".into(),
                rmpv::Value::Map(vec![
                    ("lease_id".into(), "lease:x".into()),
                    ("plan_quota".into(), rmpv::Value::Array(Vec::new())),
                ])
            ),
        ])
    );
    // A frame of the old kind is no message at all.
    let old = rmpv::Value::Map(vec![
        ("kind".into(), "claude_lease_settle".into()),
        (
            "value".into(),
            rmpv::Value::Map(vec![
                ("lease_id".into(), "lease:x".into()),
                ("usage".into(), rmpv::Value::Array(Vec::new())),
            ]),
        ),
    ]);
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &old).unwrap();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend(body);
    assert_eq!(decode_frame(&frame), None);
}

#[test]
fn connections_past_the_limit_are_dropped_and_finished_ones_free_their_place() {
    let harness = start(Setup {
        max_connections: 1,
        ..setup()
    });
    let first = ask(&harness, 60_000);
    assert!(granted_ok(&first));
    let second = ask(&harness, 60_000);
    assert!(second.message.is_none() && second.fds.is_empty());
    drop(first);
    assert!(granted_ok(&ask_until_granted(&harness, 2)));
}
