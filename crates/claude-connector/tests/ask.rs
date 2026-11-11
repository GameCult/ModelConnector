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
    ToolCall,
    Stop(StopReason),
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
        let stop = match &self.script {
            Script::Stop(reason) => *reason,
            _ => StopReason::EndTurn,
        };
        let completed = TransportOutcome::Completed {
            provider_response_id: None,
            stop_reason: stop,
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
            Script::Stop(_) => call.transported(text("cut off"), completed),
            Script::ToolCall => call.transported(
                vec![TransportEvent {
                    sequence: 0,
                    payload: TransportEventPayload::ToolCall {
                        call_id: "c".into(),
                        name: "n".into(),
                        arguments: "{}".into(),
                    },
                }],
                completed,
            ),
            Script::Sleep(d) => {
                thread::sleep(*d);
                call.transported(text("late"), completed)
            }
        }
    }
}

fn write_key(path: &std::path::Path, bytes: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
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
    write_key(&key_file, format!("{KEY}\n").as_bytes(), 0o600);
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
    write_key(&other, b"some-other-connection-key-0123456789", 0o600);
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
        write_key(&path, &bytes, 0o600);
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
        AskError::KeyNotRegular
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
    assert!(matches!(ask(&args).unwrap_err(), AskError::NotListening));
}

fn run_binary(rig: &Rig, stdin: &str, extra: &[&str]) -> std::process::Output {
    run_binary_with_key(rig, &rig.key_file, stdin, extra)
}

fn run_binary_with_key(
    rig: &Rig,
    key_file: &std::path::Path,
    stdin: &str,
    extra: &[&str],
) -> std::process::Output {
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
        .args(["--connection-key-file", key_file.to_str().unwrap()])
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
fn a_toolcall_in_the_answer_is_an_error() {
    let rig = rig(Script::ToolCall);
    assert!(matches!(ask(&rig.args()).unwrap_err(), AskError::ToolCall));
}

/// The rule: only a turn that ended (end of turn or a stop sequence) is an
/// answer; a truncated, refused or context-limited turn is an error even when
/// it carries text.
#[test]
fn a_turn_that_did_not_end_is_an_error() {
    for reason in [
        StopReason::MaxOutputTokens,
        StopReason::Refusal,
        StopReason::ContextWindow,
        StopReason::ToolUse,
    ] {
        let rig = rig(Script::Stop(reason));
        assert!(
            matches!(ask(&rig.args()).unwrap_err(), AskError::NotCompleted(r) if r == reason),
            "{reason:?}"
        );
    }
    let rig = rig(Script::Stop(StopReason::StopSequence));
    assert_eq!(ask(&rig.args()).unwrap(), "cut off");
}

#[test]
fn a_fifo_key_file_errors_promptly_instead_of_hanging() {
    let rig = rig(Script::Text("x"));
    let fifo = rig.dir.join("fifo.key");
    let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut args = rig.args();
    args.key_file = fifo;
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || tx.send(ask(&args)).unwrap());
    let error = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("reading a FIFO key file must not hang")
        .unwrap_err();
    assert!(matches!(error, AskError::KeyNotRegular), "{error}");
}

#[test]
fn a_key_file_readable_by_group_or_world_is_refused_and_a_private_one_accepted() {
    let rig = rig(Script::Text("fine"));
    for mode in [0o644, 0o640, 0o604] {
        let path = rig.dir.join(format!("mode-{mode:o}.key"));
        write_key(&path, KEY.as_bytes(), mode);
        let mut args = rig.args();
        args.key_file = path;
        let error = ask(&args).unwrap_err();
        assert!(matches!(error, AskError::KeyExposed), "{mode:o}: {error}");
        assert!(!message(&error).contains(KEY));
    }
    assert!(rig.seen().is_empty());
    assert_eq!(ask(&rig.args()).unwrap(), "fine");
}

#[test]
fn a_symlinked_key_is_judged_by_its_target() {
    let rig = rig(Script::Text("linked"));
    let link = rig.dir.join("link.key");
    std::os::unix::fs::symlink(&rig.key_file, &link).unwrap();
    let mut args = rig.args();
    args.key_file = link;
    assert_eq!(ask(&args).unwrap(), "linked");
    let dir_link = rig.dir.join("dir.key");
    std::os::unix::fs::symlink(&rig.dir, &dir_link).unwrap();
    args.key_file = dir_link;
    assert!(matches!(ask(&args).unwrap_err(), AskError::KeyNotRegular));
}

#[test]
fn the_key_read_is_bounded_at_1024_bytes() {
    let rig = rig(Script::Text("x"));
    let path = rig.dir.join("big.key");
    write_key(&path, &vec![b'k'; 1_025], 0o600);
    assert!(matches!(
        claude_connector::ask::read_key(&path).unwrap_err(),
        AskError::KeyLength
    ));
    write_key(&path, &vec![b'k'; 1_024], 0o600);
    assert!(claude_connector::ask::read_key(&path).is_ok());
}

#[test]
fn the_instructions_file_is_capped_and_must_be_a_regular_file() {
    use claude_connector::ask::{MAX_SYSTEM_BYTES, read_system_file};
    let rig = rig(Script::Text("x"));
    let path = rig.dir.join("system.txt");
    std::fs::write(&path, vec![b's'; MAX_SYSTEM_BYTES]).unwrap();
    assert_eq!(read_system_file(&path).unwrap().len(), MAX_SYSTEM_BYTES);
    std::fs::write(&path, vec![b's'; MAX_SYSTEM_BYTES + 1]).unwrap();
    assert!(matches!(
        read_system_file(&path).unwrap_err(),
        AskError::SystemTooLarge
    ));
    assert!(matches!(
        read_system_file(&rig.dir).unwrap_err(),
        AskError::SystemUnreadable
    ));
}

#[test]
fn the_binary_never_prints_key_bytes_for_a_bad_key_file() {
    let rig = rig(Script::Text("x"));
    let cases: [(&str, &[u8], u32); 3] = [
        ("exposed", b"exposed-key-bytes-0123456789", 0o644),
        ("padded", b"  padded-key-bytes-0123456789  ", 0o600),
        ("wrong", b"wrong-but-wellformed-key-0123456789", 0o600),
    ];
    for (name, bytes, mode) in cases {
        let path = rig.dir.join(format!("bin-{name}.key"));
        write_key(&path, bytes, mode);
        let out = run_binary_with_key(&rig, &path, "q", &[]);
        assert!(!out.status.success(), "{name}");
        let shown = [out.stdout.clone(), out.stderr.clone()].concat();
        let shown = String::from_utf8_lossy(&shown);
        assert!(
            !shown.contains("key-bytes") && !shown.contains("wellformed"),
            "{name}: {shown}"
        );
        assert!(out.stdout.is_empty());
    }
    let out = run_binary(&rig, "q", &["--system-file", "/nonexistent"]);
    assert!(!out.status.success());
}

#[test]
fn stdin_and_stdout_failures_have_their_own_wording() {
    let rig = rig(Script::Text("x"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_claude-connector"))
        .args(["ask", "--endpoint", &rig.endpoint.to_string()])
        .args(["--caller-id", CALLER, "--model", MODEL, "--system", "s"])
        .args(["--connection-key-file", rig.key_file.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&[0xff, 0xfe])
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("not UTF-8"), "{err}");
    assert!(!err.contains("flag"), "{err}");
}

/// What the wire returns for a tools-bearing request that gets past the CLI's
/// own construction (here forced by hand) when the real claude backend sits
/// behind the real serve loop: the service admits it, the backend's planner
/// refuses it, the caller receives a transported `Failed(InvalidRequest)`
/// result, and the claude child is never started.
#[test]
fn a_forced_tools_request_reaches_the_planner_is_refused_and_no_child_starts() {
    use claude_connector::{
        ChildEnv, ClaudeCodeBackend, ClaudeCodeConfig, ClaudeCodeLimits, ProcessPort, RunningChild,
        SessionStore, StderrSink, TokenSource,
    };
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    struct CountingPort(Arc<AtomicUsize>);
    impl ProcessPort for CountingPort {
        fn spawn(
            &self,
            _: &[String],
            _: &ChildEnv,
            _: &std::path::Path,
            _: Vec<u8>,
            _: &str,
        ) -> std::io::Result<Box<dyn RunningChild>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other("no child in this test"))
        }
    }
    struct Fixed(&'static str);
    impl TokenSource for Fixed {
        fn read(&self) -> Option<Zeroizing<String>> {
            Some(Zeroizing::new(self.0.to_string()))
        }
    }
    struct NoSessions;
    impl SessionStore for NoSessions {
        fn exists(&self, _: &str) -> bool {
            false
        }
    }
    struct Quiet;
    impl StderrSink for Quiet {
        fn stderr_tail(&self, _: &[u8]) {}
    }

    let dir =
        std::env::temp_dir().join(format!("claude-connector-ask-tools-{}", std::process::id()));
    for sub in ["work", "config", "prompt"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let binary = dir.join("claude");
    std::fs::write(&binary, b"pretend claude").unwrap();
    let spawns = Arc::new(AtomicUsize::new(0));
    let backend = ClaudeCodeBackend::with_ports(
        ClaudeCodeConfig {
            claude_binary: binary,
            claude_binary_sha256: Sha256::digest(b"pretend claude").into(),
            work_dir: dir.join("work"),
            config_dir: dir.join("config"),
            prompt_dir: dir.join("prompt"),
            token_credential: "t".into(),
            handle_secret_credential: "h".into(),
            instance: "i".into(),
            limits: ClaudeCodeLimits {
                deadline: Duration::from_secs(5),
                max_line_bytes: 1 << 16,
                max_total_bytes: 1 << 20,
                stderr_tail_bytes: 64,
            },
        },
        Box::new(CountingPort(spawns.clone())),
        Box::new(NoSessions),
        Box::new(Quiet),
        Box::new(Fixed("token")),
        Box::new(Fixed(
            "handle-secret-0000000000000000000000000000000000000000",
        )),
    );
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
    let store = dir.join("replay.cc");
    thread::spawn(move || serve(listener, limits, vec![admission], &store, Arc::new(backend)));

    let mut args = AskArgs {
        endpoint,
        caller_id: CALLER.into(),
        key_file: dir.join("unused"),
        model: MODEL.into(),
        instructions: "i".into(),
        effort: None,
        max_output_tokens: 64,
        timeout: Duration::from_secs(5),
        prompt: "p".into(),
    };
    let mut forced = build_invocation(&args).unwrap().request;
    forced.tools.push(ToolDefinition {
        name: "lookup".into(),
        description: "d".into(),
        parameters_json: "{}".into(),
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let invocation = TransportInvocation::new(
        CALLER,
        now + 60_000,
        provider_request_sha256(&forced).unwrap(),
        forced,
    )
    .unwrap();
    let client = ConnectorClient::new(endpoint, KEY, FRAME, Some(Duration::from_secs(5))).unwrap();
    let result = client.execute(&invocation).unwrap();
    let TransportDisposition::Transported { receipt, .. } = &result.disposition else {
        panic!(
            "expected the planner's failed result, got {:?}",
            result.disposition
        );
    };
    assert!(matches!(
        receipt.outcome,
        TransportOutcome::Failed {
            kind: FailureKind::InvalidRequest,
            ..
        }
    ));
    assert_eq!(
        spawns.load(Ordering::SeqCst),
        0,
        "the claude child must never start"
    );
    // The same CLI path with no tools would have reached the spawn.
    args.key_file = dir.join("unused");
    let clean = client.execute(&build_invocation(&args).unwrap()).unwrap();
    assert!(matches!(
        clean.disposition,
        TransportDisposition::Transported { .. }
    ));
    assert_eq!(spawns.load(Ordering::SeqCst), 1);
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

/// Runs the binary with `--system-file` instead of `--system`, killing it if it
/// has not exited within five seconds (a hang is a failure, not a stuck suite).
fn run_with_system_file(rig: &Rig, file: &std::path::Path) -> std::process::Output {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_claude-connector"))
        .args(["ask", "--endpoint", &rig.endpoint.to_string()])
        .args(["--caller-id", CALLER, "--model", MODEL])
        .args(["--max-output-tokens", "1024"])
        .args(["--connection-key-file", rig.key_file.to_str().unwrap()])
        .args(["--system-file", file.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(b"question");
    let started = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(5) {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("the binary hung on its --system-file");
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn the_binary_bounds_and_guards_its_system_file() {
    use claude_connector::ask::MAX_SYSTEM_BYTES;
    let rig = rig(Script::Text("accepted"));

    let fifo = rig.dir.join("system.fifo");
    let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let out = run_with_system_file(&rig, &fifo);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());

    let zero = run_with_system_file(&rig, std::path::Path::new("/dev/zero"));
    assert!(!zero.status.success());
    assert!(zero.stdout.is_empty());

    let file = rig.dir.join("system.txt");
    std::fs::write(&file, vec![b's'; MAX_SYSTEM_BYTES + 1]).unwrap();
    let over = run_with_system_file(&rig, &file);
    assert!(!over.status.success());
    assert!(over.stdout.is_empty());
    assert!(String::from_utf8_lossy(&over.stderr).contains("larger than"));
    assert!(rig.seen().is_empty());

    std::fs::write(&file, vec![b's'; MAX_SYSTEM_BYTES]).unwrap();
    let exact = run_with_system_file(&rig, &file);
    assert!(
        exact.status.success(),
        "{}",
        String::from_utf8_lossy(&exact.stderr)
    );
    assert_eq!(String::from_utf8(exact.stdout).unwrap(), "accepted");
    assert_eq!(rig.seen()[0].instructions.len(), MAX_SYSTEM_BYTES);
}
