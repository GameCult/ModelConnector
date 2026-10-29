//! The reasoning-state rules through a live serve loop and the public surface
//! only: what a backend is shown, what a caller gets back and what it replays.
#![cfg(feature = "daemon")]

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use model_connector::*;

const CALLER: &str = "reasoning-caller";
const KEY: &str = "reasoning-distinct-test-key";
const PROVIDER: &str = "anthropic-messages";
const FRAME: usize = 256 * 1024;

/// Answers every call with fixed events and records what it was shown.
struct RecordingBackend {
    events: Vec<TransportEventPayload>,
    executions: AtomicUsize,
    seen: Mutex<Vec<ProviderRequest>>,
}

impl RecordingBackend {
    fn new(events: Vec<TransportEventPayload>) -> Arc<Self> {
        Arc::new(Self {
            events,
            executions: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<ProviderRequest> {
        self.seen.lock().unwrap().clone()
    }
}

impl ProviderBackend for RecordingBackend {
    fn ready(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn provider(&self) -> &str {
        PROVIDER
    }

    fn execute(&self, call: &ProviderCall) -> TransportResult {
        self.executions.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(call.request().clone());
        call.transported(
            self.events
                .iter()
                .cloned()
                .enumerate()
                .map(|(sequence, payload)| TransportEvent {
                    sequence: sequence as u64,
                    payload,
                })
                .collect(),
            TransportOutcome::Completed {
                provider_response_id: Some("msg-1".to_string()),
                stop_reason: StopReason::ToolUse,
                usage: Usage {
                    input_tokens: 1,
                    cache_read_tokens: 0,
                    cache_write_tokens: 0,
                    output_tokens: 1,
                    reasoning_tokens: None,
                },
            },
        )
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A running serve loop and a client for it.
fn start(backend: Arc<RecordingBackend>) -> ConnectorClient {
    start_with(backend, 4)
}

/// As `start`, with the caller's concurrent-request limit.
fn start_with(backend: Arc<dyn ProviderBackend>, max_concurrent: usize) -> ConnectorClient {
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let root: PathBuf = std::env::temp_dir().join(format!(
        "model-connector-reasoning-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    let store = root.join("replay.cc");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let admission = CallerAdmission::new(
        CALLER,
        KEY,
        1,
        ["claude-opus-4-5".to_string()],
        max_concurrent,
        64 * 1024,
        32_768,
        SpendCeiling(1 << 40),
        SpendWindowMs(3_600_000),
    )
    .unwrap();
    let limits = ServeLimits {
        max_frame_bytes: FRAME,
        max_connections: 8,
        socket_timeout_ms: 5_000,
        max_expiry_skew_ms: 300_000,
    };
    let prices = PriceTable::from([(
        "claude-opus-4-5".to_string(),
        ModelPrice {
            rates: Rates {
                input: 5_000_000,
                cache_write_short: 6_250_000,
                cache_write_long: 10_000_000,
                cache_read: 500_000,
                output: 25_000_000,
            },
            long_context: None,
            overhead_tokens: 100,
        },
    )]);
    thread::spawn(move || serve(listener, limits, vec![admission], prices, &store, backend));
    ConnectorClient::new(endpoint, KEY, FRAME, Some(Duration::from_secs(5))).unwrap()
}

fn invocation(request_id: &str, input: Vec<InputItem>) -> TransportInvocation {
    let mut request = ProviderRequest::new(
        request_id,
        "conversation-1",
        "claude-opus-4-5",
        "Return the typed result.",
        4_096,
    );
    request.input = input;
    TransportInvocation::new(CALLER, now_ms() + 60_000, [7; 32], 10_000_000, request).unwrap()
}

fn user(text: &str) -> InputItem {
    InputItem::UserText {
        text: text.to_string(),
    }
}

fn state(provider: &str, byte: u8) -> InputItem {
    InputItem::ReasoningState {
        provider: provider.to_string(),
        model: "claude-opus-4-5".to_string(),
        state: vec![0x80 | byte, byte],
    }
}

fn receipt_of(result: &TransportResult) -> &TransportReceipt {
    let TransportDisposition::Transported { receipt, .. } = &result.disposition else {
        panic!(
            "expected a transported result, got {:?}",
            result.disposition
        );
    };
    receipt
}

#[test]
fn foreign_reasoning_in_flight_is_refused_and_never_executed() {
    let backend = RecordingBackend::new(vec![TransportEventPayload::TextDelta {
        text: "done".to_string(),
    }]);
    let client = start(backend.clone());
    let result = client
        .execute(&invocation(
            "foreign-in-flight",
            vec![
                user("question"),
                InputItem::ToolCall {
                    call_id: "call-1".to_string(),
                    name: "read_source".to_string(),
                    arguments: "{}".to_string(),
                },
                state("another-provider", 1),
                InputItem::ToolResult {
                    call_id: "call-1".to_string(),
                    output: "evidence".to_string(),
                },
            ],
        ))
        .unwrap();
    assert_eq!(
        result.disposition,
        TransportDisposition::Refused(Refusal::ForeignReasoningState)
    );
    assert_eq!(backend.executions.load(Ordering::SeqCst), 0);
}

#[test]
fn a_backend_never_sees_foreign_reasoning_state() {
    let backend = RecordingBackend::new(vec![TransportEventPayload::TextDelta {
        text: "done".to_string(),
    }]);
    let client = start(backend.clone());
    let own = state(PROVIDER, 2);
    let result = client
        .execute(&invocation(
            "foreign-earlier",
            vec![
                state("another-provider", 1),
                user("first"),
                own.clone(),
                state("a-third-provider", 3),
                user("second"),
            ],
        ))
        .unwrap();
    assert_eq!(receipt_of(&result).foreign_reasoning_dropped, 2);
    assert_eq!(receipt_of(&result).provider, PROVIDER);
    assert_eq!(
        backend.seen()[0].input,
        vec![user("first"), own, user("second")]
    );
}

#[test]
fn replayed_transcript_reaches_the_same_provider_verbatim() {
    let thinking = vec![0x80, 0xfe, 0x00, 0xff];
    let backend = RecordingBackend::new(vec![
        TransportEventPayload::TextDelta {
            text: "let me ".to_string(),
        },
        TransportEventPayload::TextDelta {
            text: "look".to_string(),
        },
        TransportEventPayload::ReasoningState {
            state: thinking.clone(),
        },
        TransportEventPayload::ToolCall {
            call_id: "call-1".to_string(),
            name: "read_source".to_string(),
            arguments: "{}".to_string(),
        },
    ]);
    let client = start(backend.clone());
    let first = client
        .execute(&invocation("turn-1", vec![user("question")]))
        .unwrap();
    let added = first.transcript_items();
    assert_eq!(
        added,
        vec![
            InputItem::AssistantText {
                text: "let me look".to_string()
            },
            InputItem::ReasoningState {
                provider: PROVIDER.to_string(),
                model: "claude-opus-4-5".to_string(),
                state: thinking,
            },
            InputItem::ToolCall {
                call_id: "call-1".to_string(),
                name: "read_source".to_string(),
                arguments: "{}".to_string(),
            },
        ]
    );

    // The caller appends the items untouched and answers the tool call; the
    // next call is in flight on the same provider and is admitted as it is.
    let mut next = vec![user("question")];
    next.extend(added.clone());
    next.push(InputItem::ToolResult {
        call_id: "call-1".to_string(),
        output: "evidence".to_string(),
    });
    let second = client.execute(&invocation("turn-2", next.clone())).unwrap();
    assert_eq!(receipt_of(&second).foreign_reasoning_dropped, 0);
    assert_eq!(backend.seen()[1].input, next);
}

/// A backend that answers with a receipt it has edited after the service
/// derived it.
struct TamperingBackend {
    edit: fn(&mut TransportReceipt),
}

impl ProviderBackend for TamperingBackend {
    fn ready(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn provider(&self) -> &str {
        PROVIDER
    }

    fn execute(&self, call: &ProviderCall) -> TransportResult {
        let mut result = call.transported(
            vec![TransportEvent {
                sequence: 0,
                payload: TransportEventPayload::TextDelta {
                    text: "done".to_string(),
                },
            }],
            TransportOutcome::Completed {
                provider_response_id: None,
                stop_reason: StopReason::EndTurn,
                usage: Usage {
                    input_tokens: 1,
                    cache_read_tokens: 0,
                    cache_write_tokens: 0,
                    output_tokens: 1,
                    reasoning_tokens: None,
                },
            },
        );
        let TransportDisposition::Transported { receipt, .. } = &mut result.disposition else {
            unreachable!();
        };
        (self.edit)(receipt);
        result
    }
}

#[test]
fn a_refused_completion_reaches_the_caller_as_a_typed_failure_and_frees_the_slot() {
    let edits: [fn(&mut TransportReceipt); 3] = [
        |receipt| receipt.provider = "another-provider".to_string(),
        |receipt| receipt.foreign_reasoning_dropped += 1,
        |receipt| receipt.cost_micro_usd += 1,
    ];
    for edit in edits {
        // One concurrent request: a wedged slot would refuse the next id.
        let client = start_with(Arc::new(TamperingBackend { edit }), 1);
        let first = invocation("tampered", vec![user("question")]);
        let answer = client.execute(&first).unwrap();
        let TransportDisposition::Transported { events, receipt } = &answer.disposition else {
            panic!("expected a typed failure, got {:?}", answer.disposition);
        };
        assert!(events.is_empty());
        assert!(matches!(
            receipt.outcome,
            TransportOutcome::Failed {
                kind: FailureKind::Provider,
                ..
            }
        ));
        // The same id replays that failure rather than conflicting.
        assert_eq!(client.execute(&first).unwrap(), answer);
        // The next id is not refused for capacity.
        let next = client
            .execute(&invocation("tampered-next", vec![user("again")]))
            .unwrap();
        assert!(
            !matches!(next.disposition, TransportDisposition::Refused(_)),
            "{:?}",
            next.disposition
        );
    }
}
