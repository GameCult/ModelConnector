use std::fs;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::contract::{TransportInvocation, TransportResult};
use crate::envelope::{
    ServiceError, TransportEnvelope, TransportFrameError, read_transport_frame, worst_frame_bytes,
    write_transport_frame,
};
use crate::service::{CallerAdmission, TransportAdmission, TransportService};

/// The only provider seam of the connector kit. A connector binary implements
/// it over one model provider; the kit names no provider.
pub trait ProviderBackend: Send + Sync {
    /// Whether the provider can take work. `serve` consults it once, before it
    /// opens the replay store or accepts a connection; the request path does
    /// not consult it.
    fn ready(&self) -> bool;
    /// Executes one admitted invocation. The service has already bound the
    /// invocation to its caller and recorded its replay claim.
    fn execute(&self, invocation: &TransportInvocation) -> TransportResult;
}

/// Bounds of one serve loop. The connector binary's own document owns where
/// they come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeLimits {
    pub max_frame_bytes: usize,
    pub max_connections: usize,
    pub socket_timeout_ms: u64,
    pub max_expiry_skew_ms: u64,
}

/// The smallest caller payload bound the base daemon admitted.
const MIN_PAYLOAD_BYTES: usize = 4096;

impl ServeLimits {
    /// The bounds serve refuses before it opens anything: each limit nonzero,
    /// a frame that carries the smallest payload (which also carries the failure
    /// that stands in for an oversize result), enough connections for every caller's request
    /// slots, and every caller's payload bound between the minimum and the
    /// largest whose sealed frame, at its worst-case encoding, fits the frame.
    /// An admitted payload therefore always fits, and `complete` is given the
    /// same frame bound to fit every result in.
    fn validate(&self, admissions: &[CallerAdmission]) -> Result<(), ServeError> {
        if self.max_frame_bytes < worst_frame_bytes(MIN_PAYLOAD_BYTES)
            || self.max_frame_bytes > u32::MAX as usize
            || self.max_connections == 0
            || self.socket_timeout_ms == 0
            || self.max_expiry_skew_ms == 0
        {
            return Err(ServeError::InvalidConfig("serve limits"));
        }
        if admissions.is_empty() {
            return Err(ServeError::InvalidConfig("callers"));
        }
        let slots = admissions
            .iter()
            .try_fold(0_usize, |total, caller| {
                total.checked_add(caller.max_concurrent_requests())
            })
            .ok_or(ServeError::InvalidConfig("connection capacity"))?;
        if self.max_connections < slots.max(8) {
            return Err(ServeError::InvalidConfig("connection capacity"));
        }
        if admissions.iter().any(|caller| {
            caller.max_payload_bytes() < MIN_PAYLOAD_BYTES
                || worst_frame_bytes(caller.max_payload_bytes()) > self.max_frame_bytes
        }) {
            return Err(ServeError::InvalidConfig("caller admission"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerConfig {
    pub caller_runtime_id: String,
    pub connection_key_file: PathBuf,
    pub connection_key_epoch: u32,
    pub allowed_models: Vec<String>,
    pub max_concurrent_requests: usize,
    pub max_payload_bytes: usize,
    pub max_output_tokens: u32,
}

pub fn load_admissions(callers: &[CallerConfig]) -> Result<Vec<CallerAdmission>, ServeError> {
    let mut admissions = Vec::with_capacity(callers.len());
    for caller in callers {
        let raw = Zeroizing::new(
            fs::read(&caller.connection_key_file).map_err(ServeError::ConnectionKey)?,
        );
        let secret = std::str::from_utf8(raw.as_slice())
            .map_err(|_| ServeError::InvalidConfig("caller connection key encoding"))?
            .trim_end_matches(['\r', '\n']);
        admissions.push(
            CallerAdmission::new(
                caller.caller_runtime_id.clone(),
                secret.to_string(),
                caller.connection_key_epoch,
                caller.allowed_models.clone(),
                caller.max_concurrent_requests,
                caller.max_payload_bytes,
                caller.max_output_tokens,
            )
            .map_err(ServeError::Service)?,
        );
    }
    Ok(admissions)
}

/// Serves admitted callers on a loopback listener until the listener fails.
/// The caller binds; a listener that is not bound to loopback is refused, and
/// peers that are not loopback are dropped.
pub fn serve(
    listener: TcpListener,
    limits: ServeLimits,
    admissions: Vec<CallerAdmission>,
    replay_store: &Path,
    backend: Arc<dyn ProviderBackend>,
) -> Result<(), ServeError> {
    limits.validate(&admissions)?;
    if !listener
        .local_addr()
        .map_err(ServeError::Listen)?
        .ip()
        .is_loopback()
    {
        return Err(ServeError::InvalidConfig("listener address"));
    }
    if !backend.ready() {
        return Err(ServeError::BackendUnready);
    }
    let service = Arc::new(Mutex::new(TransportService::open(
        replay_store,
        admissions,
        limits.max_expiry_skew_ms,
    )?));
    accept_loop(|| listener.accept(), limits, service, backend)
}

/// The accept loop over any source of connections, so a test can present a
/// peer address that a loopback listener never reports.
fn accept_loop(
    accept: impl Fn() -> std::io::Result<(TcpStream, SocketAddr)>,
    limits: ServeLimits,
    service: Arc<Mutex<TransportService>>,
    backend: Arc<dyn ProviderBackend>,
) -> Result<(), ServeError> {
    let active_connections = Arc::new(AtomicUsize::new(0));
    let timeout = Duration::from_millis(limits.socket_timeout_ms);

    loop {
        let (stream, peer) = accept().map_err(ServeError::Listen)?;
        if !peer_admitted(peer.ip()) {
            continue;
        }
        let Some(permit) =
            ConnectionPermit::acquire(active_connections.clone(), limits.max_connections)
        else {
            continue;
        };
        let service = service.clone();
        let backend = backend.clone();
        thread::Builder::new()
            .name("model-connector-request".to_string())
            .spawn(move || {
                let _permit = permit;
                let _ = serve_connection(stream, &service, backend.as_ref(), &limits, timeout);
            })
            .map_err(ServeError::Thread)?;
    }
}

fn peer_admitted(peer: IpAddr) -> bool {
    peer.is_loopback()
}

fn serve_connection(
    mut stream: TcpStream,
    service: &Mutex<TransportService>,
    backend: &dyn ProviderBackend,
    limits: &ServeLimits,
    timeout: Duration,
) -> Result<(), ServeError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(ServeError::Connection)?;
    let request = read_transport_frame(&mut stream, limits.max_frame_bytes).map_err(frame_error)?;
    let response = execute_inference_frame(&request, service, backend, limits)?;
    write_transport_frame(&mut stream, &response, limits.max_frame_bytes).map_err(frame_error)
}

fn execute_inference_frame(
    request: &[u8],
    service: &Mutex<TransportService>,
    backend: &dyn ProviderBackend,
    limits: &ServeLimits,
) -> Result<Vec<u8>, ServeError> {
    let envelope: TransportEnvelope =
        rmp_serde::from_slice(request).map_err(|_| ServeError::FrameEncoding)?;
    let admission = service
        .lock()
        .map_err(|_| ServeError::ServicePoisoned)?
        .begin(&envelope, unix_ms()?)?;
    let response = match admission {
        TransportAdmission::Reply(response) => response,
        TransportAdmission::Execute(claim) => {
            let result = backend.execute(claim.invocation());
            service
                .lock()
                .map_err(|_| ServeError::ServicePoisoned)?
                .complete(*claim, result, limits.max_frame_bytes)?
        }
    };
    rmp_serde::to_vec(&response).map_err(|_| ServeError::FrameEncoding)
}

fn frame_error(error: TransportFrameError) -> ServeError {
    match error {
        TransportFrameError::Connection(error) => ServeError::Connection(error),
        TransportFrameError::Size => ServeError::FrameSize,
    }
}

fn unix_ms() -> Result<u64, ServeError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServeError::Clock)?
        .as_millis();
    u64::try_from(millis).map_err(|_| ServeError::Clock)
}

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn acquire(active: Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        let mut observed = active.load(Ordering::Acquire);
        loop {
            if observed >= limit {
                return None;
            }
            match active.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self { active }),
                Err(current) => observed = current,
            }
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Error)]
pub enum ServeError {
    #[error("invalid serve configuration field {0}")]
    InvalidConfig(&'static str),
    #[error("connector connection key is unavailable")]
    ConnectionKey(#[source] std::io::Error),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error("provider backend is not ready")]
    BackendUnready,
    #[error("connector service lock was poisoned")]
    ServicePoisoned,
    #[error("connector listener failed")]
    Listen(#[source] std::io::Error),
    #[error("connector request thread failed")]
    Thread(#[source] std::io::Error),
    #[error("connector connection failed")]
    Connection(#[source] std::io::Error),
    #[error("connector frame exceeded its bound")]
    FrameSize,
    #[error("connector frame was not valid MessagePack")]
    FrameEncoding,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::client::ConnectorClient;
    use crate::contract::{
        Refusal, TransportDisposition, TransportEvent, TransportEventPayload, TransportOutcome,
        TransportResult,
    };
    use crate::fixtures::{TestStore, caller, invocation_for, receipt, request};

    const CALLER: &str = "epiphany-yggdrasil";
    const KEY: &str = "epiphany-distinct-test-key";
    const FRAME: usize = 256 * 1024;
    /// AES-256-GCM appends a 16-byte tag to the ciphertext.
    const GCM_TAG: usize = 16;

    struct CountingBackend {
        ready: bool,
        ready_calls: AtomicUsize,
        executions: AtomicUsize,
    }

    impl CountingBackend {
        fn new(ready: bool) -> Arc<Self> {
            Arc::new(Self {
                ready,
                ready_calls: AtomicUsize::new(0),
                executions: AtomicUsize::new(0),
            })
        }
    }

    impl ProviderBackend for CountingBackend {
        fn ready(&self) -> bool {
            self.ready_calls.fetch_add(1, Ordering::SeqCst);
            self.ready
        }

        fn execute(&self, invocation: &TransportInvocation) -> TransportResult {
            self.executions.fetch_add(1, Ordering::SeqCst);
            TransportResult::transported(
                invocation,
                vec![TransportEvent {
                    sequence: 0,
                    payload: TransportEventPayload::TextDelta {
                        text: "done".to_string(),
                    },
                }],
                receipt(invocation),
            )
        }
    }

    fn limits() -> ServeLimits {
        ServeLimits {
            max_frame_bytes: FRAME,
            max_connections: 8,
            socket_timeout_ms: 5_000,
            max_expiry_skew_ms: 300_000,
        }
    }

    /// The test's own clock, so a mutated `unix_ms` cannot move the fixture with it.
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// What `serve` returned, or `None` when it is still serving after two seconds.
    fn outcome(
        listener: TcpListener,
        limits: ServeLimits,
        admissions: Vec<CallerAdmission>,
        path: &Path,
        backend: Arc<dyn ProviderBackend>,
    ) -> Option<Result<(), ServeError>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let path = path.to_path_buf();
        thread::spawn(move || {
            let _ = sender.send(serve(listener, limits, admissions, &path, backend));
        });
        receiver.recv_timeout(Duration::from_secs(2)).ok()
    }

    fn fresh(request_id: &str) -> TransportInvocation {
        let mut invocation = invocation_for(CALLER, request_id);
        invocation.expires_at_unix_ms = now_ms() + 60_000;
        invocation
    }

    fn start(
        backend: Arc<CountingBackend>,
        store: &TestStore,
    ) -> (ConnectorClient, std::net::SocketAddr) {
        start_with(backend, store, vec![caller(CALLER, KEY, 4)])
    }

    fn start_with(
        backend: Arc<dyn ProviderBackend>,
        store: &TestStore,
        admissions: Vec<CallerAdmission>,
    ) -> (ConnectorClient, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let path = store.path.clone();
        thread::spawn(move || serve(listener, limits(), admissions, &path, backend));
        let client =
            ConnectorClient::new(endpoint, KEY, FRAME, Some(Duration::from_secs(5))).unwrap();
        (client, endpoint)
    }

    fn callers(capacities: &[usize]) -> Vec<CallerConfig> {
        capacities
            .iter()
            .enumerate()
            .map(|(index, capacity)| CallerConfig {
                caller_runtime_id: format!("caller-{index}"),
                connection_key_file: PathBuf::from(format!("caller-{index}.key")),
                connection_key_epoch: 1,
                allowed_models: vec!["gpt-5.6-luna".to_string()],
                max_concurrent_requests: *capacity,
                max_payload_bytes: 1_048_576,
                max_output_tokens: 16_384,
            })
            .collect()
    }

    #[test]
    fn serve_end_to_end_replays_without_a_second_execution() {
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let (client, _) = start(backend.clone(), &store);
        let invocation = fresh("request-1");

        let first = client.execute(&invocation).unwrap();
        let second = client.execute(&invocation).unwrap();

        assert!(matches!(
            first.disposition,
            TransportDisposition::Transported { .. }
        ));
        assert_eq!(first, second);
        let TransportDisposition::Transported { events, receipt } = &first.disposition else {
            unreachable!("matched above");
        };
        assert_eq!(
            events.len(),
            1,
            "a result within the bound is delivered as the provider made it"
        );
        assert!(matches!(
            receipt.outcome,
            TransportOutcome::Completed { .. }
        ));
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);

        let mut conflicting_request = request();
        conflicting_request.request_id = "request-1".to_string();
        conflicting_request.instructions = "A different instruction.".to_string();
        let mut conflicting = TransportInvocation::new(
            CALLER,
            invocation.expires_at_unix_ms,
            [7; 32],
            conflicting_request,
        )
        .unwrap();
        conflicting.expires_at_unix_ms = invocation.expires_at_unix_ms;
        let refused = client.execute(&conflicting).unwrap();
        assert_eq!(
            refused.disposition,
            TransportDisposition::Refused(Refusal::ReplayConflict)
        );
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn serve_replay_is_byte_identical_on_the_wire() {
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let (_client, endpoint) = start(backend.clone(), &store);
        let security = crate::fixtures::security(KEY);
        let request = rmp_serde::to_vec(
            &crate::envelope::encrypt_invocation(&fresh("request-wire"), &security).unwrap(),
        )
        .unwrap();
        let mut replies = Vec::new();
        for _ in 0..2 {
            let mut stream = TcpStream::connect(endpoint).unwrap();
            write_transport_frame(&mut stream, &request, FRAME).unwrap();
            replies.push(read_transport_frame(&mut stream, FRAME).unwrap());
        }
        assert_eq!(replies[0], replies[1]);
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn serve_refuses_to_start_on_an_unready_backend() {
        let store = TestStore::new();
        let backend = CountingBackend::new(false);
        let result = outcome(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            limits(),
            vec![caller(CALLER, KEY, 4)],
            &store.path,
            backend.clone(),
        );
        assert!(matches!(result, Some(Err(ServeError::BackendUnready))));
        assert_eq!(backend.executions.load(Ordering::SeqCst), 0);
        assert!(
            !store.path.exists(),
            "an unready backend must not open replay state"
        );
    }

    #[test]
    fn serve_consults_readiness_at_start_and_never_on_the_request_path() {
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let (client, _) = start(backend.clone(), &store);
        client.execute(&fresh("request-a")).unwrap();
        client.execute(&fresh("request-b")).unwrap();
        assert_eq!(backend.executions.load(Ordering::SeqCst), 2);
        assert_eq!(backend.ready_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn serve_refuses_a_listener_that_is_not_loopback() {
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let result = outcome(
            TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap(),
            limits(),
            vec![caller(CALLER, KEY, 4)],
            &store.path,
            backend.clone(),
        );
        assert!(matches!(
            result,
            Some(Err(ServeError::InvalidConfig("listener address")))
        ));
        assert_eq!(backend.ready_calls.load(Ordering::SeqCst), 0);
    }

    /// The smallest frame serve admits: the smallest payload at its worst-case
    /// sealed encoding.
    fn smallest_frame() -> usize {
        worst_frame_bytes(MIN_PAYLOAD_BYTES)
    }

    #[test]
    fn the_smallest_frame_also_carries_the_failure_that_stands_in_for_a_result() {
        let long = "x".repeat(crate::envelope::MAX_IDENTITY_BYTES);
        let plaintext = rmp_serde::to_vec(&crate::service::result_size_failure(
            &long, &long, &long, [0xff; 32], [0xff; 32],
        ))
        .unwrap()
        .len();
        let worst = worst_frame_bytes(plaintext + GCM_TAG);
        assert!(worst <= smallest_frame(), "{worst} > {}", smallest_frame());
    }

    #[test]
    fn serve_refuses_unbounded_limits_and_admits_the_widest_frame() {
        let store = TestStore::new();
        let mutations: [fn(&mut ServeLimits); 6] = [
            |limits| limits.max_frame_bytes = 0,
            |limits| limits.max_frame_bytes = smallest_frame() - 1,
            |limits| limits.max_frame_bytes = u32::MAX as usize + 1,
            |limits| limits.max_connections = 0,
            |limits| limits.socket_timeout_ms = 0,
            |limits| limits.max_expiry_skew_ms = 0,
        ];
        for mutate in mutations {
            let mut bounded = limits();
            mutate(&mut bounded);
            let result = outcome(
                TcpListener::bind("127.0.0.1:0").unwrap(),
                bounded,
                vec![caller(CALLER, KEY, 4)],
                &store.path,
                CountingBackend::new(true),
            );
            assert!(matches!(
                result,
                Some(Err(ServeError::InvalidConfig("serve limits")))
            ));
        }
        let widest = ServeLimits {
            max_frame_bytes: u32::MAX as usize,
            ..limits()
        };
        let result = outcome(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            widest,
            vec![caller(CALLER, KEY, 4)],
            &store.path,
            CountingBackend::new(true),
        );
        assert!(
            result.is_none(),
            "the widest frame the wire can carry must serve"
        );
    }

    #[test]
    fn serve_refuses_an_empty_caller_set() {
        let store = TestStore::new();
        let result = outcome(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            limits(),
            Vec::new(),
            &store.path,
            CountingBackend::new(true),
        );
        assert!(matches!(
            result,
            Some(Err(ServeError::InvalidConfig("callers")))
        ));
    }

    #[test]
    fn only_loopback_peers_are_admitted() {
        assert!(peer_admitted(IpAddr::from([127, 0, 0, 1])));
        assert!(peer_admitted(IpAddr::from(std::net::Ipv6Addr::LOCALHOST)));
        assert!(!peer_admitted(IpAddr::from([192, 168, 1, 7])));
        assert!(!peer_admitted(IpAddr::from([172, 19, 0, 1])));
    }

    #[test]
    fn connection_permits_are_bounded_and_returned_on_drop() {
        let active = Arc::new(AtomicUsize::new(0));
        let first = ConnectionPermit::acquire(active.clone(), 2).unwrap();
        let second = ConnectionPermit::acquire(active.clone(), 2).unwrap();
        assert!(ConnectionPermit::acquire(active.clone(), 2).is_none());
        drop(first);
        let third = ConnectionPermit::acquire(active.clone(), 2).unwrap();
        assert!(ConnectionPermit::acquire(active.clone(), 2).is_none());
        drop((second, third));
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    fn admission(id: &str, key: &str, slots: usize, payload: usize) -> CallerAdmission {
        CallerAdmission::new(id, key, 1, ["gpt-5.4".to_string()], slots, payload, 32_768).unwrap()
    }

    /// `Some(field)` when serve refused the configuration, `None` while it serves.
    fn refusal(limits: ServeLimits, admissions: Vec<CallerAdmission>) -> Option<&'static str> {
        let store = TestStore::new();
        match outcome(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            limits,
            admissions,
            &store.path,
            CountingBackend::new(true),
        ) {
            None => None,
            Some(Err(ServeError::InvalidConfig(field))) => Some(field),
            Some(other) => panic!("unexpected serve outcome {other:?}"),
        }
    }

    #[test]
    fn serve_refuses_fewer_connections_than_the_callers_request_slots() {
        let two = || {
            vec![
                admission("a", "key-a-distinct", 8, 8192),
                admission("b", "key-b-distinct", 8, 8192),
            ]
        };
        let at = |connections| ServeLimits {
            max_connections: connections,
            ..limits()
        };
        assert_eq!(refusal(at(15), two()), Some("connection capacity"));
        assert_eq!(refusal(at(16), two()), None);
        let small = || vec![admission("a", "key-a-distinct", 3, 8192)];
        assert_eq!(refusal(at(7), small()), Some("connection capacity"));
        assert_eq!(refusal(at(8), small()), None);
        let overflowing = vec![
            admission("a", "key-a-distinct", usize::MAX, 8192),
            admission("b", "key-b-distinct", 1, 8192),
        ];
        assert_eq!(
            refusal(at(usize::MAX), overflowing),
            Some("connection capacity")
        );
    }

    #[test]
    fn serve_refuses_a_frame_or_payload_bound_the_other_cannot_carry() {
        let frame = |bytes| ServeLimits {
            max_frame_bytes: bytes,
            ..limits()
        };
        let payload = |bytes| vec![admission("a", "key-a-distinct", 4, bytes)];
        let tightest = smallest_frame();
        assert_eq!(
            refusal(frame(tightest - 1), payload(4096)),
            Some("serve limits")
        );
        // The tightest legal pair: the smallest payload in the smallest frame.
        assert_eq!(refusal(frame(tightest), payload(4096)), None);
        assert_eq!(
            refusal(frame(tightest), payload(4097)),
            Some("caller admission")
        );
        assert_eq!(
            refusal(frame(tightest), payload(4095)),
            Some("caller admission")
        );
        // The bound is the sealed frame at its worst encoding, not the payload:
        // a payload that is the whole frame cannot be carried.
        assert_eq!(
            refusal(frame(FRAME), payload(FRAME)),
            Some("caller admission")
        );
        for bytes in [8192, 65_535, 65_536, 100_000] {
            let widest = worst_frame_bytes(bytes);
            assert_eq!(refusal(frame(widest), payload(bytes)), None, "{bytes}");
            assert_eq!(
                refusal(frame(widest - 1), payload(bytes)),
                Some("caller admission"),
                "{bytes}"
            );
        }
        let mixed = vec![
            admission("a", "key-a-distinct", 4, 8192),
            admission("b", "key-b-distinct", 4, FRAME),
        ];
        assert_eq!(refusal(frame(FRAME), mixed), Some("caller admission"));
    }

    #[test]
    fn a_payload_at_the_widest_bound_its_frame_admits_is_carried_and_served() {
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let mut invocation = fresh(&"q".repeat(256));
        invocation.request.instructions = "x".repeat(5_000);
        invocation.provider_request_sha256 =
            crate::contract::provider_request_sha256(&invocation.request).unwrap();
        let key = crate::fixtures::security(KEY);
        let sealed = crate::envelope::encrypt_invocation(&invocation, &key).unwrap();
        let bound = sealed.ciphertext.len();
        let frame = worst_frame_bytes(bound);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let path = store.path.clone();
        let served = backend.clone();
        let tight = ServeLimits {
            max_frame_bytes: frame,
            ..limits()
        };
        let admissions = vec![admission(CALLER, KEY, 4, bound)];
        thread::spawn(move || serve(listener, tight, admissions, &path, served));
        let client =
            ConnectorClient::new(endpoint, KEY, frame, Some(Duration::from_secs(5))).unwrap();
        let reply = client.execute(&invocation).unwrap();
        assert!(matches!(
            reply.disposition,
            TransportDisposition::Transported { .. }
        ));
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_payload_over_the_caller_bound_is_refused_on_the_wire() {
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let (client, _) = start_with(
            backend.clone(),
            &store,
            vec![admission(CALLER, KEY, 4, 8192)],
        );
        let mut invocation = fresh("request-big");
        invocation.request.instructions = "x".repeat(10_000);
        invocation.provider_request_sha256 =
            crate::contract::provider_request_sha256(&invocation.request).unwrap();
        let reply = client.execute(&invocation).unwrap();
        assert_eq!(
            reply.disposition,
            TransportDisposition::Refused(Refusal::Policy)
        );
        assert_eq!(backend.executions.load(Ordering::SeqCst), 0);
    }

    /// Answers every invocation with one text event of a chosen size.
    struct SizedBackend {
        text_len: usize,
        transport: String,
        executions: AtomicUsize,
    }

    impl SizedBackend {
        fn new(text_len: usize) -> Arc<Self> {
            Self::with_transport(text_len, "fixture-sse".to_string())
        }

        fn with_transport(text_len: usize, transport: String) -> Arc<Self> {
            Arc::new(Self {
                text_len,
                transport,
                executions: AtomicUsize::new(0),
            })
        }
    }

    impl ProviderBackend for SizedBackend {
        fn ready(&self) -> bool {
            true
        }

        fn execute(&self, invocation: &TransportInvocation) -> TransportResult {
            self.executions.fetch_add(1, Ordering::SeqCst);
            sized_result(invocation, self.text_len, &self.transport)
        }
    }

    fn sized_result(
        invocation: &TransportInvocation,
        text_len: usize,
        transport: &str,
    ) -> TransportResult {
        let mut receipt = receipt(invocation);
        receipt.transport = transport.to_string();
        TransportResult::transported(
            invocation,
            vec![TransportEvent {
                sequence: 0,
                payload: TransportEventPayload::TextDelta {
                    text: "y".repeat(text_len),
                },
            }],
            receipt,
        )
    }

    fn encoded_len(result: &TransportResult) -> usize {
        rmp_serde::to_vec(result).unwrap().len()
    }

    /// Two calls with one request id, through a live serve loop.
    fn call_twice(
        backend: Arc<SizedBackend>,
        request_id: &str,
    ) -> (TransportResult, TransportResult, usize) {
        let store = TestStore::new();
        let (client, _) = start_with(backend.clone(), &store, vec![caller(CALLER, KEY, 4)]);
        let invocation = fresh(request_id);
        let first = client.execute(&invocation).expect("first call delivered");
        let second = client.execute(&invocation).expect("retry delivered");
        (first, second, backend.executions.load(Ordering::SeqCst))
    }

    fn failed_result_size(result: &TransportResult) -> bool {
        matches!(
            &result.disposition,
            TransportDisposition::Transported { events, receipt }
                if events.is_empty()
                    && receipt.transport == "model-connector"
                    && receipt.outcome == TransportOutcome::Failed {
                        failure_kind: "result_size".to_string(),
                        message: "provider result exceeded its byte bound".to_string(),
                    }
        )
    }

    fn id_cases() -> [String; 2] {
        ["request-short".to_string(), "r".repeat(256)]
    }

    /// The encoded size of a result carrying no text, for this request id.
    fn empty_result_len(request_id: &str) -> usize {
        encoded_len(&sized_result(&fresh(request_id), 0, "fixture-sse"))
    }

    #[test]
    fn a_result_whose_plaintext_fits_but_whose_sealed_frame_does_not_fails_typed_and_replays() {
        // A plaintext within the frame less its overhead seals to about one and
        // a half times its size, so it cannot be carried; measuring the
        // plaintext would record it as completed and every retry would die.
        for request_id in id_cases() {
            let base = empty_result_len(&request_id);
            let room = FRAME - 4096;
            for plaintext in [room, room - 1, FRAME * 3 / 4] {
                let backend = SizedBackend::new(plaintext - base);
                let (first, second, executions) = call_twice(backend, &request_id);
                assert!(
                    failed_result_size(&first),
                    "{} {plaintext}",
                    request_id.len()
                );
                assert_eq!(first, second, "the retry replays the deliverable failure");
                assert_eq!(executions, 1);
            }
        }
    }

    #[test]
    fn a_result_larger_than_the_frame_fails_typed_and_is_never_replayed_as_completed() {
        let (first, second, executions) = call_twice(SizedBackend::new(FRAME), "request-oversize");
        assert!(failed_result_size(&first));
        assert_eq!(first, second);
        assert_eq!(executions, 1);
    }

    #[test]
    fn a_stand_in_failure_never_carries_the_backends_transport() {
        let (first, second, executions) = call_twice(
            SizedBackend::with_transport(FRAME, "t".repeat(FRAME)),
            "request-transport",
        );
        assert!(failed_result_size(&first));
        assert_eq!(first, second);
        assert_eq!(executions, 1);
    }

    #[test]
    fn a_result_within_what_the_worst_encoding_leaves_is_delivered_intact() {
        // The largest plaintext whose sealed frame fits at the worst encoding is
        // always carried, whatever the ciphertext bytes turn out to be.
        for request_id in id_cases() {
            let base = empty_result_len(&request_id);
            let mut plaintext = base;
            while worst_frame_bytes(plaintext + 1 + GCM_TAG) <= FRAME {
                plaintext += 1;
            }
            let (first, second, _) = call_twice(SizedBackend::new(plaintext - base), &request_id);
            let TransportDisposition::Transported { events, receipt } = &first.disposition else {
                panic!("expected a transported result");
            };
            assert_eq!(events.len(), 1, "{}", request_id.len());
            assert!(matches!(
                receipt.outcome,
                TransportOutcome::Completed { .. }
            ));
            assert_eq!(first, second);
        }
    }

    #[test]
    fn a_result_just_over_the_worst_encoding_is_delivered_whatever_the_nonce_makes_of_it() {
        // Past the guaranteed size the sealed frame may or may not fit; either
        // way the caller gets an answer, and the retry gets the same one.
        for request_id in id_cases() {
            let base = empty_result_len(&request_id);
            let mut plaintext = base;
            while worst_frame_bytes(plaintext + GCM_TAG) <= FRAME {
                plaintext += 1;
            }
            for extra in [0, 1, 2] {
                let backend = SizedBackend::new(plaintext + extra - base);
                let (first, second, executions) = call_twice(backend, &request_id);
                assert_eq!(first, second);
                assert_eq!(executions, 1);
            }
        }
    }

    #[test]
    fn the_accept_loop_drops_a_peer_that_is_not_loopback() {
        let run = |reported: SocketAddr| {
            let store = TestStore::new();
            let backend = CountingBackend::new(true);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap();
            let service = Arc::new(Mutex::new(
                TransportService::open(&store.path, vec![caller(CALLER, KEY, 4)], 300_000).unwrap(),
            ));
            let served = backend.clone();
            thread::spawn(move || {
                accept_loop(
                    || listener.accept().map(|(stream, _)| (stream, reported)),
                    limits(),
                    service,
                    served,
                )
            });
            let client =
                ConnectorClient::new(endpoint, KEY, FRAME, Some(Duration::from_secs(5))).unwrap();
            let reply = client.execute(&fresh("request-peer"));
            (reply.is_ok(), backend.executions.load(Ordering::SeqCst))
        };
        assert_eq!(run("127.0.0.1:50000".parse().unwrap()), (true, 1));
        assert_eq!(run("192.168.1.7:50000".parse().unwrap()), (false, 0));
    }

    #[test]
    fn direct_pipe_frame_is_big_endian_and_refuses_oversize_before_allocation() {
        let mut encoded = Vec::new();
        write_transport_frame(&mut encoded, b"typed", 16).unwrap();
        assert_eq!(&encoded[..4], &5_u32.to_be_bytes());
        assert_eq!(
            read_transport_frame(&mut Cursor::new(encoded), 16).unwrap(),
            b"typed"
        );

        let oversized = 17_u32.to_be_bytes().to_vec();
        assert!(matches!(
            read_transport_frame(&mut Cursor::new(oversized), 16),
            Err(TransportFrameError::Size)
        ));
    }

    #[test]
    fn load_admissions_reads_the_key_file_without_its_trailing_newline() {
        let store = TestStore::new();
        let key_file = store.root.join("caller.key");
        fs::write(&key_file, format!("{KEY}\r\n")).unwrap();
        let mut config = callers(&[4]);
        config[0].caller_runtime_id = CALLER.to_string();
        config[0].connection_key_file = key_file;
        config[0].allowed_models = vec!["gpt-5.4".to_string()];
        config[0].max_payload_bytes = 64 * 1024;
        let admissions = load_admissions(&config).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let backend = CountingBackend::new(true);
        let path = store.path.clone();
        let served = backend.clone();
        thread::spawn(move || serve(listener, limits(), admissions, &path, served));
        let client =
            ConnectorClient::new(endpoint, KEY, FRAME, Some(Duration::from_secs(5))).unwrap();
        client.execute(&fresh("request-key")).unwrap();
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
    }
}
