//! The Self-run credential lease. The connector is the only holder of the
//! subscription token and the one owner of Self-run admission (rulings
//! self-runs-through-connector and self-run-credential-lease). A Self run asks
//! over a unix socket for a lease. The connector decides who may ask (the
//! peer's uid, and the systemd unit invocation its process runs in), and hands
//! back one pipe fd that holds the token, with the plan's usage windows. The
//! lease lasts while the holder keeps the socket open: it ends when the holder
//! closes it, when its unit invocation ends, or when its expiry passes. Nothing
//! is reserved and nothing is billed; the only usage-derived refusal is the
//! provider's own, repeated until its own reset. Nothing the run says about
//! itself decides who it is or what the plan allows.
//!
//! The token exists in this process only as the value the token source returns
//! and in the pipe. It is not in an environment, an argument, a file, a log or
//! a reply frame. The connector spawns nothing here: the Self run's `claude`
//! stays in the Self run's own unit.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use model_connector::{
    LeaseAdmission, LeaseGrant, LeaseRefusal, LeaseTurn, PlanQuota, TransportService,
};
use serde::{Deserialize, Serialize};

use crate::{QuotaCell, TokenSource};

/// The largest frame either side sends or accepts, in bytes. It is wire
/// contract: a Huginn client sizes against it, so it is pinned as a literal.
pub const MAX_LEASE_FRAME_BYTES: usize = 65_536;
const _: () = assert!(MAX_LEASE_FRAME_BYTES == 65_536);

/// One message of the lease protocol: a u32 big-endian length, then this as a
/// MessagePack named map `{kind, value}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LeaseMessage {
    ClaudeLeaseRequest(LeaseRequest),
    /// Travels with exactly one SCM_RIGHTS fd: the read end of a pipe that
    /// holds the token, its write end closed.
    ClaudeLeaseGrant(LeaseGranted),
    ClaudeLeaseRefusal(LeaseRefused),
}

/// A request names only when the lease ends. Who asks is the connector's to know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGranted {
    pub lease_id: String,
    /// The plan's usage windows as the connector last saw them, so the run
    /// can read its own burn.
    pub plan_quota: Vec<PlanQuota>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseRefusalKind {
    UnknownCaller,
    Expired,
    Busy,
    ProviderRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRefused {
    pub kind: LeaseRefusalKind,
    pub detail: String,
}

/// A frame: the length, then the named-map MessagePack of `message`.
pub fn encode_frame(message: &LeaseMessage) -> Vec<u8> {
    // Every field of the message is plain data, so encoding cannot fail.
    let body = rmp_serde::to_vec_named(message).unwrap_or_default();
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// The message in one whole frame, or `None` when the frame is not exactly one
/// well-formed message within the bound.
pub fn decode_frame(frame: &[u8]) -> Option<LeaseMessage> {
    let (length, body) = frame.split_first_chunk::<4>()?;
    let length = u32::from_be_bytes(*length) as usize;
    if length == 0 || length > MAX_LEASE_FRAME_BYTES || body.len() != length {
        return None;
    }
    rmp_serde::from_slice(body).ok()
}

/// A reader whose waiting can be bounded, so a frame has one deadline across
/// all of its reads.
trait Bounded: Read {
    fn within(&mut self, left: Duration) -> io::Result<()>;
}

impl Bounded for UnixStream {
    fn within(&mut self, left: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(left))
    }
}

impl Bounded for &[u8] {
    fn within(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}

/// Fills `buffer` or fails: when `deadline` passes, however the bytes trickle.
fn read_exact_by(
    stream: &mut impl Bounded,
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        stream.within(left)?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => filled += read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// One whole frame, complete by `deadline`.
fn read_message(stream: &mut impl Bounded, deadline: Instant) -> io::Result<LeaseMessage> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidData);
    let mut length = [0_u8; 4];
    read_exact_by(stream, &mut length, deadline)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_LEASE_FRAME_BYTES {
        return Err(invalid());
    }
    let mut body = vec![0_u8; length];
    read_exact_by(stream, &mut body, deadline)?;
    rmp_serde::from_slice(&body).map_err(|_| invalid())
}

/// The most a pipe takes in one atomic write.
const PIPE_BUF: usize = 4096;

/// A unix account allowed to lease, the unit its process must run in (the
/// Self or the Persona unit of its instance, by `turn`), and the
/// caller whose name its leases carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseCaller {
    pub uid: u32,
    pub caller_id: String,
    /// Which kind of turn this account leases for; it picks the unit.
    pub turn: LeaseTurn,
    /// The `<instance>` of `mind-self@<instance>.service` or
    /// `mind-persona@<instance>.service`.
    pub unit_instance: String,
}

impl LeaseCaller {
    /// The one unit a lease to this caller may be requested from.
    pub fn unit(&self) -> String {
        match self.turn {
            LeaseTurn::SelfRun => format!("mind-self@{}.service", self.unit_instance),
            LeaseTurn::PersonaTurn => format!("mind-persona@{}.service", self.unit_instance),
        }
    }
}

/// The systemd unit invocation a process runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerUnit {
    pub unit: String,
    pub invocation_id: String,
}

/// Which invocation of `unit` a process is running, as the system records it.
/// The lease listener asks this port; `SystemdUnits` answers it in production.
/// `None` when the process is not in `unit` or the system cannot say. The
/// process is named by the handle the kernel gave for the peer, never by a pid.
pub trait PeerUnits: Send + Sync {
    fn invocation_in(&self, process: BorrowedFd<'_>, unit: &str) -> Option<PeerUnit>;
}

/// The bounds of the lease listener.
#[derive(Debug, Clone, Copy)]
pub struct LeaseLimits {
    /// How long a peer has to send its request frame, whole.
    pub socket_timeout: Duration,
    /// The furthest an expiry may lie from now.
    pub max_lease_ms: u64,
    pub max_connections: usize,
}

/// Who is on the other end of a unix stream, as the kernel recorded them at
/// connect.
#[derive(Debug)]
pub struct PeerCredentials {
    pub uid: u32,
    /// A handle on the peer's process (SO_PEERPIDFD, Linux 6.5 and later). It
    /// pins the process's identity: a recycled pid cannot be read through it.
    /// `None` when the kernel cannot give one, and then no unit is vouched
    /// for.
    pub process: Option<OwnedFd>,
}

/// The uid and process handle of the process on the other end of `stream`.
pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    // SAFETY: `credentials` and `length` are valid for the call, and `length`
    // is the size of the buffer getsockopt writes into.
    let (result, credentials) = unsafe {
        let mut credentials: libc::ucred = zeroed();
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        let result = libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            ptr::from_mut(&mut credentials).cast(),
            &mut length,
        );
        (result, credentials)
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above, with a `c_int` the kernel fills with a new descriptor
    // that this function then owns.
    let (result, pidfd) = unsafe {
        let mut pidfd: libc::c_int = -1;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        let result = libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            ptr::from_mut(&mut pidfd).cast(),
            &mut length,
        );
        (result, pidfd)
    };
    Ok(PeerCredentials {
        uid: credentials.uid,
        // SAFETY: on success `pidfd` is a descriptor nothing else owns.
        process: (result == 0 && pidfd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(pidfd) }),
    })
}

/// The uid of the account `name`, if the system has one.
pub fn user_uid(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: every pointer is valid for the call and `buffer` is as long as
    // the length passed; `found` is read only when the call reports success.
    unsafe {
        let mut entry: libc::passwd = zeroed();
        let mut found: *mut libc::passwd = ptr::null_mut();
        let result = libc::getpwnam_r(
            name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        );
        (result == 0 && !found.is_null()).then_some(entry.pw_uid)
    }
}

/// A pipe whose read end holds `token` and whose write end is closed, so a
/// reader gets the token and then end of file. The token is smaller than
/// PIPE_BUF, so the write is whole and cannot block.
fn token_pipe(token: &[u8]) -> io::Result<OwnedFd> {
    if token.len() > PIPE_BUF {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut ends = [0 as RawFd; 2];
    // SAFETY: `ends` has room for the two descriptors pipe2 writes.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 just returned these two descriptors and nothing else owns them.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
    // SAFETY: the pointer and length describe `token`.
    let written = unsafe { libc::write(write.as_raw_fd(), token.as_ptr().cast(), token.len()) };
    if usize::try_from(written).ok() != Some(token.len()) {
        return Err(io::Error::last_os_error());
    }
    drop(write);
    Ok(read)
}

/// Writes `frame` to `stream` with `fd` attached as SCM_RIGHTS.
fn send_with_fd(stream: &UnixStream, frame: &[u8], fd: RawFd) -> io::Result<()> {
    let fd_size = size_of::<RawFd>() as u32;
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(fd_size) } as usize;
    // u64 elements align the control buffer for a cmsghdr.
    let mut control = vec![0_u64; space.div_ceil(size_of::<u64>())];
    let mut vector = libc::iovec {
        iov_base: frame.as_ptr().cast_mut().cast(),
        iov_len: frame.len(),
    };
    // SAFETY: msghdr is plain data for which all-zero is valid; the pointers
    // set below outlive the sendmsg call, and the cmsg header written lies
    // inside `control`, which CMSG_SPACE sized for one descriptor.
    let sent = unsafe {
        let mut message: libc::msghdr = zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(fd_size) as _;
        ptr::copy_nonoverlapping(
            ptr::from_ref(&fd).cast::<u8>(),
            libc::CMSG_DATA(header),
            size_of::<RawFd>(),
        );
        loop {
            let sent = libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL);
            if sent >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break sent;
            }
        }
    };
    let Ok(sent) = usize::try_from(sent) else {
        return Err(io::Error::last_os_error());
    };
    // The descriptor travels with the first byte; any rest is plain data.
    let mut stream = stream;
    stream.write_all(&frame[sent..])
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

struct Permit(Arc<AtomicUsize>);

impl Permit {
    fn acquire(active: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < limit).then_some(held + 1)
            })
            .ok()
            .map(|_| Self(active.clone()))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Lender {
    callers: Vec<LeaseCaller>,
    limits: LeaseLimits,
    service: Arc<Mutex<TransportService>>,
    quota: Arc<QuotaCell>,
    tokens: Arc<dyn TokenSource>,
    units: Arc<dyn PeerUnits>,
}

/// Serves leases on `listener` until it fails. Each connection is one lease:
/// request, then grant or refusal, then (after a grant) settle. A caller is
/// the account whose uid the kernel reports for the connection, and only a
/// process in that caller's unit may lease, once per unit invocation for a Self
/// run and once per turn for a Persona; no
/// field of any message names either.
pub fn serve_leases(
    listener: &UnixListener,
    callers: Vec<LeaseCaller>,
    limits: LeaseLimits,
    service: Arc<Mutex<TransportService>>,
    quota: Arc<QuotaCell>,
    tokens: Arc<dyn TokenSource>,
    units: Arc<dyn PeerUnits>,
) -> io::Result<()> {
    let lender = Arc::new(Lender {
        callers,
        limits,
        service,
        quota,
        tokens,
        units,
    });
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, _) = listener.accept()?;
        let Some(permit) = Permit::acquire(&active, limits.max_connections) else {
            continue;
        };
        let lender = lender.clone();
        thread::Builder::new()
            .name("claude-lease".to_string())
            .spawn(move || {
                let _permit = permit;
                // A connection that fails is dropped; the lease it may have
                // held is settled inside `lend`.
                let _ = lender.lend(stream);
            })?;
    }
}

impl Lender {
    fn lend(&self, mut stream: UnixStream) -> io::Result<()> {
        stream.set_write_timeout(Some(self.limits.socket_timeout))?;
        let peer = peer_credentials(&stream)?;
        let request_deadline = Instant::now() + self.limits.socket_timeout;
        let LeaseMessage::ClaudeLeaseRequest(request) =
            read_message(&mut stream, request_deadline)?
        else {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        };
        let Some(caller) = self.callers.iter().find(|caller| caller.uid == peer.uid) else {
            return refuse(
                &mut stream,
                LeaseRefusalKind::UnknownCaller,
                "this account may not lease",
            );
        };
        // The unit and its invocation come from the system's record of the
        // peer's process, never from the peer.
        let Some(invocation) = peer
            .process
            .as_ref()
            .and_then(|process| self.units.invocation_in(process.as_fd(), &caller.unit()))
            .filter(|found| found.unit == caller.unit())
        else {
            return refuse(
                &mut stream,
                LeaseRefusalKind::UnknownCaller,
                "this process is not in the Self unit",
            );
        };
        let now = unix_ms();
        if request.expires_at_unix_ms <= now
            || request.expires_at_unix_ms > now.saturating_add(self.limits.max_lease_ms)
        {
            return refuse(
                &mut stream,
                LeaseRefusalKind::Expired,
                "the expiry is not in the future or is past the lease bound",
            );
        }
        // The lease is claimed before the token is read, let alone lent. The
        // plan the refusal reads is the one this process last observed.
        let plan = self.quota.snapshot();
        let admission = self
            .service
            .lock()
            .map_err(|_| io::Error::other("service lock"))?
            .begin_lease(
                &caller.caller_id,
                caller.turn,
                &invocation.invocation_id,
                request.expires_at_unix_ms,
                now,
                &plan,
            )
            .map_err(|_| io::Error::other("lease"))?;
        let grant = match admission {
            LeaseAdmission::Granted(grant) => grant,
            LeaseAdmission::Refused(why) => {
                let (kind, detail) = match why {
                    LeaseRefusal::UnknownCaller => (
                        LeaseRefusalKind::UnknownCaller,
                        "this account is bound to no admitted caller",
                    ),
                    LeaseRefusal::Busy => (
                        LeaseRefusalKind::Busy,
                        "a lease is open for this caller or this unit invocation",
                    ),
                    LeaseRefusal::ProviderRejected => (
                        LeaseRefusalKind::ProviderRejected,
                        "the provider is refusing until its own reset",
                    ),
                };
                return refuse(&mut stream, kind, detail);
            }
        };
        self.hold(
            stream,
            caller,
            &grant,
            &invocation,
            peer.process,
            request.expires_at_unix_ms,
            plan.windows,
        )
    }

    /// Everything after a lease exists: lend the token, then keep the lease
    /// while its holder keeps the socket and its unit invocation, and end it
    /// exactly once whatever happens.
    // One argument per fact the held lease binds.
    #[allow(clippy::too_many_arguments)]
    fn hold(
        &self,
        mut stream: UnixStream,
        caller: &LeaseCaller,
        grant: &LeaseGrant,
        invocation: &PeerUnit,
        process: Option<OwnedFd>,
        expires_at_unix_ms: u64,
        plan_quota: Vec<PlanQuota>,
    ) -> io::Result<()> {
        let held = self.keep(
            &mut stream,
            caller,
            grant,
            invocation,
            process.as_ref(),
            expires_at_unix_ms,
            plan_quota,
        );
        self.service
            .lock()
            .map_err(|_| io::Error::other("service lock"))?
            .end_lease(&caller.caller_id, &grant.lease_id);
        held
    }

    // One argument per fact the held lease binds.
    #[allow(clippy::too_many_arguments)]
    fn keep(
        &self,
        stream: &mut UnixStream,
        caller: &LeaseCaller,
        grant: &LeaseGrant,
        invocation: &PeerUnit,
        process: Option<&OwnedFd>,
        expires_at_unix_ms: u64,
        plan_quota: Vec<PlanQuota>,
    ) -> io::Result<()> {
        // A token that cannot be read or piped was never lent: the lease ends.
        let Some(read_end) = self
            .tokens
            .read()
            .and_then(|token| token_pipe(token.as_bytes()).ok())
        else {
            return Ok(());
        };
        let frame = encode_frame(&LeaseMessage::ClaudeLeaseGrant(LeaseGranted {
            lease_id: grant.lease_id.clone(),
            plan_quota,
        }));
        let sent = send_with_fd(stream, &frame, read_end.as_raw_fd());
        drop(read_end);
        sent?;
        // The holder says nothing more. The lease ends when it closes the
        // socket, when its unit invocation is no longer the one that leased,
        // or at the expiry.
        let mut byte = [0_u8; 1];
        loop {
            let left = expires_at_unix_ms.saturating_sub(unix_ms());
            if left == 0 {
                return Ok(());
            }
            stream.set_read_timeout(Some(Duration::from_millis(left.min(HOLD_POLL_MS))))?;
            match stream.read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Ok(()),
            }
            let still = process
                .and_then(|process| self.units.invocation_in(process.as_fd(), &caller.unit()))
                .is_some_and(|found| found == *invocation);
            if !still {
                return Ok(());
            }
        }
    }
}

/// How often a held lease looks again at its holder's unit invocation.
const HOLD_POLL_MS: u64 = 500;

fn refuse(stream: &mut UnixStream, kind: LeaseRefusalKind, detail: &str) -> io::Result<()> {
    stream.write_all(&encode_frame(&LeaseMessage::ClaudeLeaseRefusal(
        LeaseRefused {
            kind,
            detail: detail.to_string(),
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal frame whose body is exactly `body_bytes` long.
    fn frame_of(body_bytes: usize) -> Vec<u8> {
        let frame_with = |pad: usize| {
            encode_frame(&LeaseMessage::ClaudeLeaseRefusal(LeaseRefused {
                kind: LeaseRefusalKind::Busy,
                detail: "x".repeat(pad),
            }))
        };
        // The string header is the same width between 256 and 65535 bytes.
        let base = frame_with(300).len() - 4 - 300;
        frame_with(body_bytes - base)
    }

    fn within(frame: &[u8]) -> io::Result<LeaseMessage> {
        read_message(&mut &frame[..], Instant::now() + Duration::from_secs(5))
    }

    #[test]
    fn the_frame_bound_is_sixty_five_thousand_five_hundred_thirty_six() {
        assert_eq!(MAX_LEASE_FRAME_BYTES, 65_536);
    }

    #[test]
    fn a_frame_is_one_whole_message_within_the_bound() {
        let at_bound = frame_of(MAX_LEASE_FRAME_BYTES);
        assert_eq!(at_bound.len(), 4 + MAX_LEASE_FRAME_BYTES);
        assert!(decode_frame(&at_bound).is_some());
        let past_bound = frame_of(MAX_LEASE_FRAME_BYTES + 1);
        assert!(decode_frame(&past_bound).is_none());
        let mut trailing = at_bound.clone();
        trailing.push(0);
        assert!(decode_frame(&trailing).is_none());
        assert!(decode_frame(&at_bound[..at_bound.len() - 1]).is_none());
        assert!(decode_frame(&[0, 0, 0, 0]).is_none());
        assert!(decode_frame(&[0, 0]).is_none());
    }

    #[test]
    fn a_stream_frame_over_the_bound_is_refused_before_it_is_read() {
        let past_bound = frame_of(MAX_LEASE_FRAME_BYTES + 1);
        assert!(within(&past_bound).is_err());
        let at_bound = frame_of(MAX_LEASE_FRAME_BYTES);
        assert!(within(&at_bound).is_ok());
        assert!(within(&[0_u8, 0, 0, 0]).is_err());
        // Short of the length it announced is end of file, not a message.
        assert!(within(&at_bound[..at_bound.len() - 1]).is_err());
    }

    #[test]
    fn a_frame_that_trickles_past_its_deadline_is_refused_however_small_each_read() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let frame = encode_frame(&LeaseMessage::ClaudeLeaseRefusal(LeaseRefused {
            kind: LeaseRefusalKind::Busy,
            detail: "lease:x".to_string(),
        }));
        let trickle = thread::spawn(move || {
            for byte in frame {
                if writer.write_all(&[byte]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(60));
            }
        });
        // Every read lands well inside any per-read timeout; the frame as a
        // whole does not.
        let started = Instant::now();
        let outcome = read_message(&mut reader, started + Duration::from_millis(400));
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(1_000));
        drop(reader);
        trickle.join().unwrap();
    }

    /// A reader that fails the way a reset connection does.
    struct Reset;

    impl Read for Reset {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }
    }

    impl Bounded for Reset {
        fn within(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_read_that_fails_ends_the_frame_at_once_not_at_the_deadline() {
        let started = Instant::now();
        let outcome = read_message(&mut Reset, started + Duration::from_secs(30));
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_frame_that_arrives_in_pieces_within_its_deadline_is_read() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let frame = encode_frame(&LeaseMessage::ClaudeLeaseRequest(LeaseRequest {
            expires_at_unix_ms: 7,
        }));
        let expected = decode_frame(&frame);
        let pieces = thread::spawn(move || {
            for part in frame.chunks(3) {
                writer.write_all(part).unwrap();
                thread::sleep(Duration::from_millis(10));
            }
        });
        let read = read_message(&mut reader, Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(Some(read), expected);
        pieces.join().unwrap();
    }
}
