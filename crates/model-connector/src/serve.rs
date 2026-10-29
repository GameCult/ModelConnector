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

use crate::contract::TransportResult;
use crate::envelope::{
    RequestFrame, ServiceError, TransportFrameError, decode_request_frame, encode_result_frame,
    encode_spend_readout_response_frame, frame_bytes_for_payload, read_transport_frame,
    write_transport_frame,
};
use crate::readout::PlanQuotaSnapshot;
use crate::service::{
    CallerAdmission, PriceTable, ProviderCall, SpendCeiling, SpendWindowMs, TransportAdmission,
    TransportService, distinct_admissions,
};

/// The only provider seam of the connector kit. A connector binary implements
/// it over one model provider; the kit names no provider.
pub trait ProviderBackend: Send + Sync {
    /// Whether the provider can take work; `Err` names the backend field that
    /// is not ready, never a value. `serve` consults it once, before it opens
    /// the replay store or accepts a connection; the request path does not
    /// consult it.
    fn ready(&self) -> Result<(), &'static str>;
    /// The tag of the provider this backend fronts. The service owns it from
    /// `serve` on: it names the provider on every receipt and decides which
    /// reasoning state is foreign.
    fn provider(&self) -> &str;
    /// What the provider's own plan allows and has used, for the spend
    /// readout. A provider with no plan to report keeps the default.
    fn plan_quota(&self) -> PlanQuotaSnapshot {
        PlanQuotaSnapshot::default()
    }
    /// Executes one admitted call. The service has already bound it to its
    /// caller and recorded its replay claim. The call cannot show a foreign
    /// reasoning item and builds the result's receipt itself.
    fn execute(&self, call: &ProviderCall) -> TransportResult;
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

/// The smallest caller payload bound serve admits. The smallest legal frame is
/// `frame_bytes_for_payload(MIN_PAYLOAD_BYTES)`.
pub const MIN_PAYLOAD_BYTES: usize = 4096;

impl ServeLimits {
    /// The bounds serve refuses before it opens anything: each limit nonzero,
    /// a frame that carries the smallest payload (which also carries the failure
    /// that stands in for an oversize result), enough connections for every caller's request
    /// slots, and every caller's payload bound between the minimum and the
    /// largest whose sealed frame, at its worst-case encoding, fits the frame.
    /// An admitted payload therefore always fits, and `complete` is given the
    /// same frame bound to fit every result in.
    pub fn validate(&self, admissions: &[CallerAdmission]) -> Result<(), ServeError> {
        if self.max_frame_bytes == 0
            || self.max_frame_bytes > u32::MAX as usize
            || self.max_connections == 0
            || self.socket_timeout_ms == 0
            || self.max_expiry_skew_ms == 0
        {
            return Err(ServeError::InvalidConfig("serve limits"));
        }
        let smallest = frame_bytes_for_payload(MIN_PAYLOAD_BYTES);
        if self.max_frame_bytes < smallest {
            return Err(ServeError::FrameBound {
                max_frame_bytes: self.max_frame_bytes,
                payload_bytes: MIN_PAYLOAD_BYTES,
                needed_frame_bytes: smallest,
            });
        }
        if admissions.is_empty() {
            return Err(ServeError::InvalidConfig("callers"));
        }
        distinct_admissions(admissions)?;
        let slots = admissions
            .iter()
            .try_fold(0_usize, |total, caller| {
                total.checked_add(caller.max_concurrent_requests())
            })
            .ok_or(ServeError::InvalidConfig("connection capacity"))?;
        if self.max_connections < slots.max(8) {
            return Err(ServeError::InvalidConfig("connection capacity"));
        }
        for caller in admissions {
            if caller.max_payload_bytes() < MIN_PAYLOAD_BYTES {
                return Err(ServeError::InvalidConfig("caller admission"));
            }
            let needed = frame_bytes_for_payload(caller.max_payload_bytes());
            if needed > self.max_frame_bytes {
                return Err(ServeError::FrameBound {
                    max_frame_bytes: self.max_frame_bytes,
                    payload_bytes: caller.max_payload_bytes(),
                    needed_frame_bytes: needed,
                });
            }
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
    /// The most the caller may spend in one window, in micro-USD. Required
    /// nonzero. A fuse set once, generously above what the dial allows.
    pub spend_ceiling_micro_usd: u64,
    /// The length of the caller's spend window, in milliseconds. Windows are
    /// fixed and aligned to the unix epoch. Required nonzero.
    pub spend_window_ms: u64,
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
                SpendCeiling(caller.spend_ceiling_micro_usd),
                SpendWindowMs(caller.spend_window_ms),
            )
            .map_err(ServeError::Service)?,
        );
    }
    Ok(admissions)
}

/// Serves admitted callers on a loopback listener until the listener fails.
/// `prices` is the connector binary's config document's table of what every
/// allowed model costs (B4 owns that document).
/// The caller binds; a listener that is not bound to loopback is refused, and
/// peers that are not loopback are dropped.
pub fn serve(
    listener: TcpListener,
    limits: ServeLimits,
    admissions: Vec<CallerAdmission>,
    prices: PriceTable,
    replay_store: &Path,
    backend: Arc<dyn ProviderBackend>,
) -> Result<(), ServeError> {
    limits.validate(&admissions)?;
    admit_listener(&listener, backend.as_ref())?;
    let service = Arc::new(Mutex::new(TransportService::open(
        replay_store,
        backend.provider(),
        prices,
        admissions,
        limits.max_expiry_skew_ms,
    )?));
    accept_loop(|| listener.accept(), limits, service, backend)
}

/// `serve` over a service the caller opened and keeps a handle to, so another
/// front of the same ledger (the Self-run credential lease) reserves in the
/// same windows. The limits must already have been validated against the
/// service's admissions.
pub fn serve_service(
    listener: TcpListener,
    limits: ServeLimits,
    service: Arc<Mutex<TransportService>>,
    backend: Arc<dyn ProviderBackend>,
) -> Result<(), ServeError> {
    admit_listener(&listener, backend.as_ref())?;
    accept_loop(|| listener.accept(), limits, service, backend)
}

/// What must be true before a serve loop touches the ledger: the listener is
/// on loopback and the backend can take work.
fn admit_listener(listener: &TcpListener, backend: &dyn ProviderBackend) -> Result<(), ServeError> {
    if !listener
        .local_addr()
        .map_err(ServeError::Listen)?
        .ip()
        .is_loopback()
    {
        return Err(ServeError::InvalidConfig("listener address"));
    }
    backend.ready().map_err(ServeError::BackendUnready)
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
    let response = answer_frame(&request, service, backend, limits)?;
    write_transport_frame(&mut stream, &response, limits.max_frame_bytes).map_err(frame_error)
}

fn answer_frame(
    request: &[u8],
    service: &Mutex<TransportService>,
    backend: &dyn ProviderBackend,
    limits: &ServeLimits,
) -> Result<Vec<u8>, ServeError> {
    let envelope = match decode_request_frame(request).map_err(|_| ServeError::FrameEncoding)? {
        RequestFrame::Invoke(envelope) => envelope,
        RequestFrame::SpendReadout(envelope) => {
            let plan = backend.plan_quota();
            let response = service
                .lock()
                .map_err(|_| ServeError::ServicePoisoned)?
                .spend_readout(&envelope, unix_ms()?, plan, limits.max_frame_bytes)?;
            return encode_spend_readout_response_frame(&response)
                .map_err(|_| ServeError::FrameEncoding);
        }
    };
    let admission = service
        .lock()
        .map_err(|_| ServeError::ServicePoisoned)?
        .begin(&envelope, unix_ms()?, limits.max_frame_bytes)?;
    let response = match admission {
        TransportAdmission::Reply(response) => response,
        TransportAdmission::Execute(claim) => {
            let result = backend.execute(claim.call());
            service
                .lock()
                .map_err(|_| ServeError::ServicePoisoned)?
                .complete(*claim, result, limits.max_frame_bytes)?
        }
    };
    encode_result_frame(&response).map_err(|_| ServeError::FrameEncoding)
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
    #[error(
        "max_frame_bytes {max_frame_bytes} cannot carry a {payload_bytes}-byte payload bound: at least {needed_frame_bytes} frame bytes are needed"
    )]
    FrameBound {
        max_frame_bytes: usize,
        payload_bytes: usize,
        needed_frame_bytes: usize,
    },
    #[error("connector connection key is unavailable")]
    ConnectionKey(#[source] std::io::Error),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error("provider backend is not ready: {0}")]
    BackendUnready(&'static str),
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
    #[error("connector frame was not a connector operation message")]
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
        FailureKind, Refusal, TransportDisposition, TransportEvent, TransportEventPayload,
        TransportInvocation, TransportOutcome, TransportResult,
    };
    use crate::fixtures::{
        CEILING, MAX_COST, TestStore, WINDOW_MS, caller, fixture_prices, invocation_for, receipt,
        request,
    };

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
        fn ready(&self) -> Result<(), &'static str> {
            self.ready_calls.fetch_add(1, Ordering::SeqCst);
            self.ready.then_some(()).ok_or("fixture")
        }

        fn provider(&self) -> &str {
            "fixture-sse"
        }

        fn execute(&self, call: &ProviderCall) -> TransportResult {
            self.executions.fetch_add(1, Ordering::SeqCst);
            call.transported(
                vec![TransportEvent {
                    sequence: 0,
                    payload: TransportEventPayload::TextDelta {
                        text: "done".to_string(),
                    },
                }],
                receipt(&fresh("sizing")).outcome,
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
            let _ = sender.send(serve(
                listener,
                limits,
                admissions,
                fixture_prices(),
                &path,
                backend,
            ));
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
        thread::spawn(move || {
            serve(
                listener,
                limits(),
                admissions,
                fixture_prices(),
                &path,
                backend,
            )
        });
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
                spend_ceiling_micro_usd: CEILING,
                spend_window_ms: WINDOW_MS,
            })
            .collect()
    }

    /// A counting backend that reports a plan, as a provider with one would.
    struct PlanBackend {
        inner: Arc<CountingBackend>,
        plan: PlanQuotaSnapshot,
    }

    impl ProviderBackend for PlanBackend {
        fn ready(&self) -> Result<(), &'static str> {
            self.inner.ready()
        }

        fn provider(&self) -> &str {
            self.inner.provider()
        }

        fn plan_quota(&self) -> PlanQuotaSnapshot {
            self.plan.clone()
        }

        fn execute(&self, call: &ProviderCall) -> TransportResult {
            self.inner.execute(call)
        }
    }

    #[test]
    fn serve_reads_out_spend_and_plan_quota_without_executing_anything() {
        let store = TestStore::new();
        let inner = CountingBackend::new(true);
        let plan = PlanQuotaSnapshot {
            windows: vec![crate::readout::PlanQuota {
                window: "five_hour".into(),
                utilization_permille: Some(80),
                resets_at_unix_ms: 1_793_307_000_000,
                status: "allowed".into(),
                observed_at_unix_ms: 1_793_300_000_000,
            }],
        };
        let backend = Arc::new(PlanBackend {
            inner: inner.clone(),
            plan: plan.clone(),
        });
        let (client, endpoint) = start_with(backend, &store, vec![caller(CALLER, KEY, 4)]);
        client.execute(&fresh("request-1")).unwrap();
        assert_eq!(inner.executions.load(Ordering::SeqCst), 1);

        let before = now_ms();
        let readout = client.spend_readout(CALLER).unwrap();
        assert!(readout.at_unix_ms >= before && readout.at_unix_ms <= now_ms());
        assert_eq!(readout.plan_quota, plan.windows);
        let [row] = readout.callers.as_slice() else {
            panic!("one admitted caller");
        };
        assert_eq!(row.caller_id, CALLER);
        assert_eq!((row.ceiling_micro_usd, row.window_ms), (CEILING, WINDOW_MS));
        assert!(row.spent_micro_usd > 0, "the settled call was charged");
        assert_eq!(row.reserved_micro_usd, 0);
        assert_eq!(
            inner.executions.load(Ordering::SeqCst),
            1,
            "a readout runs nothing"
        );

        // A client without the caller's key is dropped, not answered.
        let stranger = ConnectorClient::new(
            endpoint,
            "some-other-key",
            FRAME,
            Some(Duration::from_secs(5)),
        )
        .unwrap();
        assert!(stranger.spend_readout(CALLER).is_err());
    }

    #[test]
    fn a_backend_with_no_plan_reads_out_none() {
        let store = TestStore::new();
        let (client, _) = start(CountingBackend::new(true), &store);
        let readout = client.spend_readout(CALLER).unwrap();
        assert!(readout.plan_quota.is_empty());
    }

    #[test]
    fn serve_refuses_a_request_over_its_max_cost_without_executing_it() {
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let (client, _) = start(backend.clone(), &store);
        let mut invocation = fresh("request-costly");
        invocation.max_cost_micro_usd = 1;
        let refused = client.execute(&invocation).unwrap();
        assert_eq!(
            refused.disposition,
            TransportDisposition::Refused(Refusal::CostBound)
        );
        assert_eq!(backend.executions.load(Ordering::SeqCst), 0);

        // The refusal was not recorded: the same id with a budget that holds
        // the worst case is admitted and executed.
        invocation.max_cost_micro_usd = MAX_COST;
        let admitted = client.execute(&invocation).unwrap();
        assert!(matches!(
            admitted.disposition,
            TransportDisposition::Transported { .. }
        ));
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
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
            MAX_COST,
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
        let request = crate::envelope::encode_invocation_frame(
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
    fn serve_refuses_a_long_request_id_on_the_wire_echoing_the_id_without_dropping_the_connection()
    {
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let (_client, endpoint) = start(backend.clone(), &store);
        let security = crate::fixtures::security(KEY);
        // Read the way ConnectorClient reads a reply: decrypt_result, which
        // requires the result to name the request by its own id.
        let send = |id: &str| {
            let invocation = fresh(id);
            let request = crate::envelope::encode_invocation_frame(
                &crate::envelope::encrypt_invocation(&invocation, &security).unwrap(),
            )
            .unwrap();
            let mut stream = TcpStream::connect(endpoint).unwrap();
            write_transport_frame(&mut stream, &request, FRAME).unwrap();
            let reply = read_transport_frame(&mut stream, FRAME).unwrap();
            let envelope = crate::envelope::decode_result_frame(&reply).unwrap();
            crate::envelope::decrypt_result(&envelope, &security, &invocation).unwrap()
        };
        let served = send(&"i".repeat(crate::envelope::MAX_IDENTITY_BYTES));
        assert!(matches!(
            served.disposition,
            TransportDisposition::Transported { .. }
        ));
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
        for length in [257, 258, 5_000, 60_000] {
            let result = send(&"i".repeat(length));
            assert_eq!(
                result.disposition,
                TransportDisposition::Refused(Refusal::Malformed),
                "{length}"
            );
        }
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn serve_measures_a_replayed_record_against_its_own_max_frame() {
        // A record completed under a wide frame, replayed by a serve at a
        // narrower one, must come back as the typed stand-in that fits the
        // narrower frame; handing `begin` any other frame delivers the wide
        // record, which the narrow write then cannot carry.
        let store = TestStore::new();
        let invocation = fresh("request-narrowed");
        // The wide completion goes straight through the service: serve holds
        // the replay store for as long as it runs, so a second serve cannot
        // open it while the first lives.
        let mut service = TransportService::open(
            &store.path,
            "fixture-sse",
            fixture_prices(),
            vec![caller(CALLER, KEY, 4)],
            300_000,
        )
        .unwrap();
        let envelope =
            crate::envelope::encrypt_invocation(&invocation, &crate::fixtures::security(KEY))
                .unwrap();
        let TransportAdmission::Execute(claim) =
            service.begin(&envelope, now_ms(), 1 << 20).unwrap()
        else {
            panic!("a fresh request must execute");
        };
        let wide = sized_result(claim.call(), 150_000);
        service.complete(*claim, wide, 1 << 20).unwrap();
        drop(service);

        let narrow = 140_000;
        let narrowed = ServeLimits {
            max_frame_bytes: narrow,
            ..limits()
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let path = store.path.clone();
        let backend = SizedBackend::new(150_000);
        let served = backend.clone();
        thread::spawn(move || {
            serve(
                listener,
                narrowed,
                vec![caller(CALLER, KEY, 4)],
                fixture_prices(),
                &path,
                served,
            )
        });
        let client =
            ConnectorClient::new(endpoint, KEY, narrow, Some(Duration::from_secs(5))).unwrap();
        let replayed = client.execute(&invocation).unwrap();
        assert!(failed_result_size(&replayed));
        assert_eq!(backend.executions.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn frame_bound_error_states_the_frame_needed() {
        assert_eq!(
            ServeError::FrameBound {
                max_frame_bytes: 1000,
                payload_bytes: 2000,
                needed_frame_bytes: 4000,
            }
            .to_string(),
            "max_frame_bytes 1000 cannot carry a 2000-byte payload bound: at least 4000 frame bytes are needed"
        );
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
        assert!(matches!(
            result,
            Some(Err(ServeError::BackendUnready("fixture")))
        ));
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
        frame_bytes_for_payload(MIN_PAYLOAD_BYTES)
    }

    #[test]
    fn the_smallest_frame_also_carries_the_failure_that_stands_in_for_a_result() {
        let long = "x".repeat(crate::envelope::MAX_IDENTITY_BYTES);
        let plaintext = crate::contract::wire_encode(&crate::service::result_size_failure(
            &long,
            &long,
            &long,
            [0xff; 32],
            [0xff; 32],
            0,
            u64::MAX,
        ))
        .unwrap()
        .len();
        let worst = frame_bytes_for_payload(plaintext + GCM_TAG);
        assert!(worst <= smallest_frame(), "{worst} > {}", smallest_frame());
    }

    #[test]
    fn serve_refuses_unbounded_limits_and_admits_the_widest_frame() {
        let store = TestStore::new();
        let mutations: [fn(&mut ServeLimits); 5] = [
            |limits| limits.max_frame_bytes = 0,
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
    fn the_limits_refuse_callers_that_share_a_key_or_an_id() {
        let limits = limits();
        let shared_key = [
            caller("one", "shared-key", 1),
            caller("two", "shared-key", 1),
        ];
        assert!(matches!(
            limits.validate(&shared_key),
            Err(ServeError::Service(ServiceError::SharedCallerKey))
        ));
        let shared_id = [caller("one", "key-a", 1), caller("one", "key-b", 1)];
        assert!(matches!(
            limits.validate(&shared_id),
            Err(ServeError::Service(ServiceError::DuplicateCaller))
        ));
        let distinct = [caller("one", "key-a", 1), caller("two", "key-b", 1)];
        assert!(limits.validate(&distinct).is_ok());
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
        CallerAdmission::new(
            id,
            key,
            1,
            ["gpt-5.4".to_string()],
            slots,
            payload,
            32_768,
            SpendCeiling(CEILING),
            SpendWindowMs(WINDOW_MS),
        )
        .unwrap()
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
            Some(Err(ServeError::FrameBound { .. })) => Some("frame bound"),
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
            Some("frame bound")
        );
        // The tightest legal pair: the smallest payload in the smallest frame.
        assert_eq!(refusal(frame(tightest), payload(4096)), None);
        assert_eq!(refusal(frame(tightest), payload(4097)), Some("frame bound"));
        assert_eq!(
            refusal(frame(tightest), payload(4095)),
            Some("caller admission")
        );
        // The bound is the sealed frame at its worst encoding, not the payload:
        // a payload that is the whole frame cannot be carried.
        assert_eq!(refusal(frame(FRAME), payload(FRAME)), Some("frame bound"));
        for bytes in [8192, 65_535, 65_536, 100_000] {
            let widest = frame_bytes_for_payload(bytes);
            assert_eq!(refusal(frame(widest), payload(bytes)), None, "{bytes}");
            assert_eq!(
                refusal(frame(widest - 1), payload(bytes)),
                Some("frame bound"),
                "{bytes}"
            );
        }
        let mixed = vec![
            admission("a", "key-a-distinct", 4, 8192),
            admission("b", "key-b-distinct", 4, FRAME),
        ];
        assert_eq!(refusal(frame(FRAME), mixed), Some("frame bound"));
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
        let frame = frame_bytes_for_payload(bound);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let path = store.path.clone();
        let served = backend.clone();
        let tight = ServeLimits {
            max_frame_bytes: frame,
            ..limits()
        };
        let admissions = vec![admission(CALLER, KEY, 4, bound)];
        thread::spawn(move || serve(listener, tight, admissions, fixture_prices(), &path, served));
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
            TransportDisposition::Refused(Refusal::PayloadBound)
        );
        assert_eq!(backend.executions.load(Ordering::SeqCst), 0);
    }

    /// Answers every invocation with one text event of a chosen size.
    struct SizedBackend {
        text_len: usize,
        executions: AtomicUsize,
    }

    impl SizedBackend {
        fn new(text_len: usize) -> Arc<Self> {
            Arc::new(Self {
                text_len,
                executions: AtomicUsize::new(0),
            })
        }
    }

    impl ProviderBackend for SizedBackend {
        fn ready(&self) -> Result<(), &'static str> {
            Ok(())
        }

        fn provider(&self) -> &str {
            "fixture-sse"
        }

        fn execute(&self, call: &ProviderCall) -> TransportResult {
            self.executions.fetch_add(1, Ordering::SeqCst);
            sized_result(call, self.text_len)
        }
    }

    fn sized_result(call: &ProviderCall, text_len: usize) -> TransportResult {
        call.transported(
            vec![TransportEvent {
                sequence: 0,
                payload: TransportEventPayload::TextDelta {
                    text: "y".repeat(text_len),
                },
            }],
            receipt(&fresh("sizing")).outcome,
        )
    }

    fn encoded_len(result: &TransportResult) -> usize {
        crate::contract::wire_encode(result).unwrap().len()
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
                    && receipt.provider == "model-connector"
                    && receipt.outcome == TransportOutcome::Failed {
                        kind: FailureKind::ResultSize,
                        message: "provider result exceeded its byte bound".to_string(),
                        usage: None,
                    }
        )
    }

    fn id_cases() -> [String; 2] {
        ["request-short".to_string(), "r".repeat(256)]
    }

    /// The encoded size of a result carrying no text, for this request id.
    fn empty_result_len(request_id: &str) -> usize {
        let store = TestStore::new();
        let mut service = TransportService::open(
            &store.path,
            "fixture-sse",
            fixture_prices(),
            vec![caller(CALLER, KEY, 4)],
            300_000,
        )
        .unwrap();
        let envelope = crate::envelope::encrypt_invocation(
            &fresh(request_id),
            &crate::fixtures::security(KEY),
        )
        .unwrap();
        let TransportAdmission::Execute(claim) =
            service.begin(&envelope, now_ms(), 1 << 20).unwrap()
        else {
            panic!("a fresh request must execute");
        };
        encoded_len(&sized_result(claim.call(), 0))
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

    /// The largest result plaintext whose sealed frame fits at the worst encoding.
    fn widest_guaranteed_plaintext(base: usize) -> usize {
        (base..=FRAME)
            .take_while(|plaintext| frame_bytes_for_payload(plaintext + GCM_TAG) <= FRAME)
            .last()
            .unwrap_or(base)
    }

    #[test]
    fn a_result_within_what_the_worst_encoding_leaves_is_delivered_intact() {
        // The largest plaintext whose sealed frame fits at the worst encoding is
        // always carried, whatever the ciphertext bytes turn out to be.
        for request_id in id_cases() {
            let base = empty_result_len(&request_id);
            let plaintext = widest_guaranteed_plaintext(base);
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
            let plaintext = widest_guaranteed_plaintext(base);
            for extra in [1, 2, 3] {
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
                TransportService::open(
                    &store.path,
                    "fixture-sse",
                    fixture_prices(),
                    vec![caller(CALLER, KEY, 4)],
                    300_000,
                )
                .unwrap(),
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
        thread::spawn(move || {
            serve(
                listener,
                limits(),
                admissions,
                fixture_prices(),
                &path,
                served,
            )
        });
        let client =
            ConnectorClient::new(endpoint, KEY, FRAME, Some(Duration::from_secs(5))).unwrap();
        client.execute(&fresh("request-key")).unwrap();
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_v2_frame_gets_no_answer() {
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let (client, endpoint) = start(backend.clone(), &store);
        // The v2 envelope: positional, an integer-array ciphertext, a v2 id.
        let v2 = rmp_serde::to_vec(&(
            concat!("gamecult.", "codex.transport_envelope.v2"),
            CALLER,
            "request-v2",
            "Invocation",
            [0_u8; 12],
            vec![1_u8; 64],
        ))
        .unwrap();
        let mut stream = TcpStream::connect(endpoint).unwrap();
        write_transport_frame(&mut stream, &v2, FRAME).unwrap();
        assert!(matches!(
            read_transport_frame(&mut stream, FRAME),
            Err(TransportFrameError::Connection(_))
        ));
        assert_eq!(backend.executions.load(Ordering::SeqCst), 0);
        // The loop survives the v2 peer and serves a v3 one.
        client.execute(&fresh("request-after-v2")).unwrap();
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_reply_echoes_the_request_id() {
        use cultnet_rs::{CultNetMessage, CultNetWireContract, decode_cultnet_message_from_slice};
        let store = TestStore::new();
        let backend = CountingBackend::new(true);
        let (_client, endpoint) = start(backend.clone(), &store);
        let security = crate::fixtures::security(KEY);
        let send = |invocation: &TransportInvocation| {
            let request = crate::envelope::encode_invocation_frame(
                &crate::envelope::encrypt_invocation(invocation, &security).unwrap(),
            )
            .unwrap();
            let mut stream = TcpStream::connect(endpoint).unwrap();
            write_transport_frame(&mut stream, &request, FRAME).unwrap();
            let reply = read_transport_frame(&mut stream, FRAME).unwrap();
            let CultNetMessage::OperationResponse {
                message_id, status, ..
            } = decode_cultnet_message_from_slice(&reply, CultNetWireContract::CultNetSchemaV0)
                .unwrap()
            else {
                panic!("a reply is an operation response");
            };
            let envelope = crate::envelope::decode_result_frame(&reply).unwrap();
            let result = crate::envelope::decrypt_result(&envelope, &security, invocation).unwrap();
            (message_id, status, result)
        };

        let transported = fresh("request-echo-transported");
        let (message_id, status, result) = send(&transported);
        assert_eq!(
            (
                message_id.as_str(),
                status.as_str(),
                result.request_id.as_str()
            ),
            ("request-echo-transported", "ok", "request-echo-transported")
        );
        assert!(matches!(
            result.disposition,
            TransportDisposition::Transported { .. }
        ));

        let mut refused = fresh("request-echo-refused");
        refused.request.model = "unlisted-model".to_string();
        refused.provider_request_sha256 =
            crate::contract::provider_request_sha256(&refused.request).unwrap();
        let (message_id, status, result) = send(&refused);
        assert_eq!(
            (
                message_id.as_str(),
                status.as_str(),
                result.request_id.as_str()
            ),
            ("request-echo-refused", "ok", "request-echo-refused")
        );
        assert_eq!(
            result.disposition,
            TransportDisposition::Refused(Refusal::ModelNotAllowed)
        );
    }
}
