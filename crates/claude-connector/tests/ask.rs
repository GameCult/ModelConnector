//! `claude-connector ask` against a real serve loop on loopback with a scripted
//! backend: the consumer side of the no-tools completion.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use claude_connector::ask::{AskArgs, AskError, ask, build_invocation};
use model_connector::*;

const CALLER: &str = "ask-caller";
const KEY: &str = "ask-test-key-0123456789-abcdefghijklmnop";
const MODEL: &str = "claude-haiku-5-5";
const FRAME: usize = 4 << 20;

/// What the scripted backend does with each call.
#[derive(Clone)]
enum Script {
    Text(&'static str),
    Empty,
    Failed(&'static str),
    Sleep(Duration),
}

struct Backend {
    script: Script,
    seen: Mutex<Vec<ProviderRequest>>,
}

impl ProviderBackend for Backend {
    fn ready(&self) -> Result<(), &'static str> {
        Ok(())
    }
    fn provider(&self) -> &str {
        "claude-code"
    }
    fn execute(&self, call: &ProviderCall) -> TransportResult {
        self.seen.lock().unwrap().push(call.request().clone());
        let usage = Usage {
            input_tokens: 1,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            output_tokens: 1,
            reasoning_tokens: None,
        };
        let text = |t: &str| {
            vec![TransportEvent {
                sequence: 0,
                payload: TransportEventPayload::TextDelta { text: t.into() },
            }]
        };
        let completed = TransportOutcome::Completed {
            provider_response_id: None,
            stop_reason: StopReason::EndTurn,
            usage: usage.clone(),
        };
        match &self.script {
            Script::Text(t) => call.transported(text(t), completed),
            Script::Empty => call.transported(Vec::new(), completed),
            Script::Failed(message) => call.transported(
                Vec::new(),
                TransportOutcome::Failed {
                    kind: FailureKind::Provider,
                    message: message.to_string(),
                    usage: None,
                },
            ),
            Script::Sleep(d) => {
                thread::sleep(*d);
                call.transported(text("late"), completed)
            }
        }
    }
}

struct Rig {
    endpoint: SocketAddr,
    dir: PathBuf,
    key_file: PathBuf,
    backend: Arc<Backend>,
}

fn rig(script: Script) -> Rig {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "claude-connector-ask-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = dir.join("caller.key");
    std::fs::write(&key_file, format!("{KEY}\n")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let admission =
        CallerAdmission::new(CALLER, KEY, 1, [MODEL.to_string()], 4, 1 << 20, 4_096).unwrap();
    let limits = ServeLimits {
        max_frame_bytes: FRAME,
        max_connections: 8,
        socket_timeout_ms: 5_000,
        max_expiry_skew_ms: 300_000,
    };
    let backend = Arc::new(Backend {
        script,
        seen: Mutex::new(Vec::new()),
    });
    let served = backend.clone();
    let store = dir.join("replay.cc");
    thread::spawn(move || serve(listener, limits, vec![admission], &store, served));
    Rig {
        endpoint,
        dir,
        key_file,
        backend,
    }
}

impl Rig {
    fn args(&self) -> AskArgs {
        AskArgs {
            endpoint: self.endpoint,
            caller_id: CALLER.into(),
            key_file: self.key_file.clone(),
            model: MODEL.into(),
            instructions: "Answer briefly.".into(),
            effort: Some(ReasoningEffort::Low),
            max_output_tokens: 1_024,
            timeout: Duration::from_secs(5),
            prompt: "SECRET-PROMPT-TEXT".into(),
        }
    }
    fn seen(&self) -> Vec<ProviderRequest> {
        self.backend.seen.lock().unwrap().clone()
    }
}

fn message(error: &AskError) -> String {
    error.to_string()
}

#[test]
fn success_returns_the_answer_text_and_the_backend_saw_a_toolless_request() {
    let rig = rig(Script::Text("four"));
    assert_eq!(ask(&rig.args()).unwrap(), "four");
    let seen = rig.seen();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].tools.is_empty());
    assert_eq!(seen[0].model, MODEL);
    assert_eq!(seen[0].instructions, "Answer briefly.");
    assert_eq!(seen[0].reasoning_effort, Some(ReasoningEffort::Low));
    assert_eq!(seen[0].max_output_tokens, 1_024);
    assert_eq!(
        seen[0].input,
        vec![InputItem::UserText {
            text: "SECRET-PROMPT-TEXT".into()
        }]
    );
}

#[test]
fn each_run_uses_a_fresh_request_id_so_replay_never_answers_a_new_question() {
    let rig = rig(Script::Text("again"));
    ask(&rig.args()).unwrap();
    ask(&rig.args()).unwrap();
    let seen = rig.seen();
    assert_eq!(seen.len(), 2, "the provider ran once per run");
    assert_ne!(seen[0].request_id, seen[1].request_id);
}

#[test]
fn the_cli_cannot_construct_a_request_with_tools() {
    let rig = rig(Script::Text("x"));
    let invocation = build_invocation(&rig.args()).unwrap();
    assert!(invocation.request.tools.is_empty());
    assert_eq!(invocation.request.tool_choice, ToolChoice::Auto);
    assert!(
        invocation
            .request
            .input
            .iter()
            .all(|item| matches!(item, InputItem::UserText { .. }))
    );
}

#[test]
fn a_model_outside_allowed_models_is_refused_loudly() {
    let rig = rig(Script::Text("x"));
    let mut args = rig.args();
    args.model = "claude-opus-5".into();
    let error = ask(&args).unwrap_err();
    assert!(
        matches!(error, AskError::Refused(Refusal::ModelNotAllowed)),
        "{error}"
    );
    assert!(rig.seen().is_empty());
}

#[test]
fn an_output_bound_over_the_callers_cap_is_refused() {
    let rig = rig(Script::Text("x"));
    let mut args = rig.args();
    args.max_output_tokens = 4_097;
    assert!(matches!(
        ask(&args).unwrap_err(),
        AskError::Refused(Refusal::OutputBound)
    ));
    assert!(rig.seen().is_empty());
}

#[test]
fn a_wrong_key_or_caller_is_an_error_and_never_reaches_the_provider() {
    let rig = rig(Script::Text("x"));
    let mut wrong_key = rig.args();
    let other = rig.dir.join("other.key");
    std::fs::write(&other, "some-other-connection-key-0123456789").unwrap();
    wrong_key.key_file = other;
    let error = ask(&wrong_key).unwrap_err();
    assert!(!message(&error).contains("some-other"), "{error}");
    let mut wrong_caller = rig.args();
    wrong_caller.caller_id = "someone-else".into();
    ask(&wrong_caller).unwrap_err();
    assert!(rig.seen().is_empty());
}

#[test]
fn an_unusable_key_file_errors_without_echoing_its_contents() {
    let rig = rig(Script::Text("x"));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", b"\n".to_vec()),
        ("long", vec![b'k'; 2_000]),
        ("binary", vec![0xff, 0xfe, 0xfd, 0x41]),
        ("padded", b"  spaced-secret-value-padded  ".to_vec()),
    ];
    for (name, bytes) in cases {
        let path = rig.dir.join(format!("{name}.key"));
        std::fs::write(&path, &bytes).unwrap();
        let mut args = rig.args();
        args.key_file = path;
        let text = message(&ask(&args).unwrap_err());
        assert!(!text.contains("spaced-secret"), "{name}: {text}");
        assert!(!text.contains("kkkk"), "{name}: {text}");
    }
    let mut missing = rig.args();
    missing.key_file = rig.dir.join("absent.key");
    assert!(matches!(
        ask(&missing).unwrap_err(),
        AskError::KeyUnreadable
    ));
    let mut directory = rig.args();
    directory.key_file = rig.dir.clone();
    assert!(matches!(
        ask(&directory).unwrap_err(),
        AskError::KeyUnreadable
    ));
    assert!(rig.seen().is_empty());
}

#[test]
fn an_empty_answer_is_an_error() {
    for script in [Script::Empty, Script::Text("  \n")] {
        let rig = rig(script);
        assert!(matches!(
            ask(&rig.args()).unwrap_err(),
            AskError::EmptyAnswer
        ));
    }
}

#[test]
fn an_empty_prompt_is_an_error_before_any_connection() {
    let rig = rig(Script::Text("x"));
    let mut args = rig.args();
    args.prompt = " \n\t".into();
    assert!(matches!(ask(&args).unwrap_err(), AskError::EmptyPrompt));
    assert!(rig.seen().is_empty());
}

#[test]
fn a_provider_failure_names_its_kind_and_not_its_message() {
    let rig = rig(Script::Failed("stderr tail with SECRET-PROMPT-TEXT"));
    let error = ask(&rig.args()).unwrap_err();
    assert!(matches!(error, AskError::Failed(FailureKind::Provider)));
    assert!(!message(&error).contains("SECRET"));
}

#[test]
fn a_connector_that_does_not_answer_in_time_is_a_timeout() {
    let rig = rig(Script::Sleep(Duration::from_secs(3)));
    let mut args = rig.args();
    args.timeout = Duration::from_millis(300);
    assert!(matches!(ask(&args).unwrap_err(), AskError::Timeout));
}

#[test]
fn a_dead_endpoint_is_a_connection_error() {
    let rig = rig(Script::Text("x"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut args = rig.args();
    args.endpoint = listener.local_addr().unwrap();
    drop(listener);
    assert!(matches!(ask(&args).unwrap_err(), AskError::Connection(_)));
}

fn run_binary(rig: &Rig, stdin: &str, extra: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_claude-connector"))
        .args(["ask", "--endpoint", &rig.endpoint.to_string()])
        .args([
            "--caller-id",
            CALLER,
            "--model",
            MODEL,
            "--system",
            "Be brief.",
        ])
        .args(["--connection-key-file", rig.key_file.to_str().unwrap()])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    }
    child.wait_with_output().unwrap()
}

#[test]
fn the_binary_prints_the_answer_on_success() {
    let rig = rig(Script::Text("pong"));
    let out = run_binary(
        &rig,
        "ping",
        &["--effort", "low", "--max-output-tokens", "1024"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "pong");
    assert!(out.stderr.is_empty());
}

#[test]
fn the_binary_fails_loudly_with_one_stderr_line_and_empty_stdout() {
    let rig = rig(Script::Text("x"));
    let out = run_binary(&rig, "", &[]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let err = String::from_utf8(out.stderr).unwrap();
    assert_eq!(err.trim_end().lines().count(), 1, "{err}");
    assert!(err.starts_with("claude-connector: "));
    assert!(!err.contains(KEY));
    // Tools, a working directory and a second endpoint are not flags.
    for flag in ["--tools", "--cwd", "--work-dir"] {
        let out = run_binary(&rig, "q", &[flag, "x"]);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }
    assert!(rig.seen().is_empty());
}
