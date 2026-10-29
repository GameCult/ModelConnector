use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use model_connector::{
    CallerAdmission, ModelPrice, PriceTable, Rates, ReasoningEffort, SpendCeiling, SpendWindowMs,
    StopReason, ToolDefinition, TransportAdmission, TransportDisposition, TransportInvocation,
    TransportKey, TransportReceipt, TransportService, decrypt_result, encrypt_invocation,
};

use super::*;
use crate::config::ClaudeCodeLimits;
use crate::handle::{FsSessionStore, SessionStore};
use crate::launch::ChildEnv;

const CANARY_TOKEN: &str = "canary-oauth-token-value";
/// The variable the connector's own environment must never hand on.
const TOKEN_ENV: &str = "CLAUDE_CODE_OAUTH_TOKEN";
const TOKEN_FD_ENV: &str = "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR";
const MODEL: &str = "claude-haiku-5-5";
const INSTANCE: &str = "persona-a";
const SESSION: &str = "11111111-2222-3333-4444-555555555555";
const HEX_SESSION: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const OTHER_MODEL: &str = "claude-opus-5";
const FORK: &str = "66666666-7777-8888-9999-000000000000";
const FRAME: usize = 1 << 20;

// ---- fixtures, written by hand from the fields the probes observed ----

fn init_line(model: &str, session: &str) -> String {
    format!(
        r#"{{"type":"system","subtype":"init","session_id":"{session}","model":"{model}","tools":[],"apiKeySource":"none"}}"#
    )
}

fn text_line(id: &str, text: &str) -> String {
    format!(
        r#"{{"type":"assistant","message":{{"id":"{id}","role":"assistant","content":[{{"type":"text","text":"{text}"}}],"stop_reason":null}},"session_id":"{SESSION}"}}"#
    )
}

fn thinking_line(id: &str) -> String {
    format!(
        r#"{{"type":"assistant","message":{{"id":"{id}","role":"assistant","content":[{{"type":"thinking","thinking":"","signature":"sig"}}]}}}}"#
    )
}

fn tool_use_line() -> String {
    r#"{"type":"assistant","message":{"id":"msg_t","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":{}}]}}"#.to_string()
}

fn rate_limit_line(status: &str) -> String {
    format!(
        r#"{{"type":"rate_limit_event","rate_limit_info":{{"status":"{status}","rateLimitType":"five_hour"}}}}"#
    )
}

const USAGE: &str = r#"{"claude-haiku-5-5":{"inputTokens":2,"outputTokens":4,"cacheReadInputTokens":7,"cacheCreationInputTokens":1043,"thinkingTokens":3,"costUSD":0.5}}"#;

/// What a resumed session's `modelUsage` says: every turn so far. Every result
/// fixture carries it beside the turn's own `model_usage_since_last_result`,
/// so reading the wrong field shows in a price.
const CUMULATIVE: &str = r#"{"claude-haiku-5-5":{"inputTokens":900000,"outputTokens":900000,"cacheReadInputTokens":900000,"cacheCreationInputTokens":900000,"thinkingTokens":900000,"costUSD":99.0}}"#;

fn result_line(stop_reason: &str, since_last: &str) -> String {
    result_line_with(stop_reason, since_last, "")
}

/// A success result with `extra` (a leading comma and fields) appended.
fn result_line_with(stop_reason: &str, since_last: &str, extra: &str) -> String {
    format!(
        r#"{{"type":"result","subtype":"success","is_error":false,"stop_reason":"{stop_reason}","session_id":"{SESSION}","total_cost_usd":99.0,"modelUsage":{CUMULATIVE},"model_usage_since_last_result":{since_last}{extra}}}"#
    )
}

// The shapes `claude -p --json-schema` produced on the pinned CLI (2.1.312):
// the answer is a call of the CLI's own StructuredOutput tool, the result
// carries it as `structured_output` with stop_reason `tool_use`, and a
// `rate_limit_event` reports the plan's windows under `unifiedWindows`.
const SCHEMA: &str = r#"{"type":"object","properties":{"answer":{"type":"string"},"n":{"type":"integer"}},"required":["answer","n"],"additionalProperties":false}"#;
const STRUCTURED: &str = r#"{"answer":"say hello","n":0}"#;

fn structured_call_line(name: &str) -> String {
    format!(
        r#"{{"type":"assistant","message":{{"id":"msg_s","role":"assistant","content":[{{"type":"tool_use","id":"toolu_01","name":"{name}","input":{STRUCTURED},"caller":{{"type":"direct"}}}}],"stop_reason":null}},"session_id":"{SESSION}"}}"#
    )
}

fn structured_tool_result_line() -> String {
    format!(
        r#"{{"type":"user","message":{{"role":"user","content":[{{"tool_use_id":"toolu_01","type":"tool_result","content":"Structured output provided successfully"}}]}},"parent_tool_use_id":null,"session_id":"{SESSION}"}}"#
    )
}

fn plan_rate_limit_line() -> String {
    r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","resetsAt":1793307000,"rateLimitType":"five_hour","overageStatus":"rejected","isUsingOverage":false,"unifiedWindows":{"five_hour":{"utilization":0.08,"resetsAt":1793307000,"status":"allowed"},"seven_day":{"utilization":0.3,"resetsAt":1793656800,"status":"allowed"}}}}"#.to_string()
}

fn structured_result_line() -> String {
    result_line_with(
        "tool_use",
        USAGE,
        &format!(r#","structured_output":{STRUCTURED},"result":"ignored""#),
    )
}

fn structured_script() -> Script {
    Script::lines(vec![
        init_line(MODEL, SESSION),
        structured_call_line("StructuredOutput"),
        structured_tool_result_line(),
        plan_rate_limit_line(),
        structured_result_line(),
    ])
}

fn schema_request() -> ProviderRequest {
    let mut request = request(vec![user("hello")]);
    request.output_schema_json = Some(SCHEMA.to_string());
    request
}

fn a_tool() -> ToolDefinition {
    ToolDefinition {
        name: "lookup".into(),
        description: "d".into(),
        parameters_json: "{}".into(),
    }
}

fn error_result_line(extra: &str) -> String {
    format!(
        r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"{SESSION}","total_cost_usd":99.0,"modelUsage":{CUMULATIVE},"model_usage_since_last_result":{USAGE}{extra}}}"#
    )
}

fn ok_script(session: &str, text: &str) -> Script {
    Script::lines(vec![
        init_line(MODEL, session),
        text_line("msg_1", text),
        rate_limit_line("allowed"),
        result_line("end_turn", USAGE),
    ])
}

fn usage(
    input: u64,
    cache_read: u64,
    cache_write: u64,
    output: u64,
    reasoning: Option<u64>,
) -> Usage {
    Usage {
        input_tokens: input,
        cache_read_tokens: cache_read,
        cache_write_tokens: cache_write,
        output_tokens: output,
        reasoning_tokens: reasoning,
    }
}

fn user(text: &str) -> InputItem {
    InputItem::UserText { text: text.into() }
}

fn assistant(text: &str) -> InputItem {
    InputItem::AssistantText { text: text.into() }
}

fn request(input: Vec<InputItem>) -> ProviderRequest {
    let mut request = ProviderRequest::new("req", "conv", MODEL, "Be terse.", 1024);
    request.input = input;
    request
}

// ---- the scripted port: replays fixture lines and records what it was given ----

#[derive(Clone, Copy)]
enum Terminal {
    Eof,
    Timeout,
    Breach,
}

struct Script {
    lines: Vec<String>,
    terminal: Terminal,
}

impl Script {
    fn lines(lines: Vec<String>) -> Self {
        Self {
            lines,
            terminal: Terminal::Eof,
        }
    }

    fn ending(mut self, terminal: Terminal) -> Self {
        self.terminal = terminal;
        self
    }
}

#[derive(Clone, Default)]
struct Seen {
    argv: Vec<String>,
    env: Vec<(String, String)>,
    cwd: PathBuf,
    stdin: Vec<u8>,
    /// The token the backend handed the port, which a real port puts on a pipe.
    token: String,
    /// The file `--system-prompt-file` named, as it was when the child started.
    prompt_file: Option<(PathBuf, String)>,
    /// Every deadline the backend passed to a read of this child.
    deadlines: Arc<Mutex<Vec<Instant>>>,
}

struct ScriptedPort {
    scripts: Mutex<VecDeque<Script>>,
    spawns: Arc<AtomicUsize>,
    seen: Arc<Mutex<Seen>>,
    stderr: Vec<u8>,
}

struct ScriptedChild {
    lines: VecDeque<String>,
    terminal: Terminal,
    stderr: Vec<u8>,
    deadlines: Arc<Mutex<Vec<Instant>>>,
}

impl ProcessPort for ScriptedPort {
    fn spawn(
        &self,
        argv: &[String],
        env: &ChildEnv,
        cwd: &Path,
        stdin: Vec<u8>,
        token: &str,
    ) -> io::Result<Box<dyn RunningChild>> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        let deadlines = Arc::new(Mutex::new(Vec::new()));
        *self.seen.lock().unwrap() = Seen {
            prompt_file: arg_after(argv, "--system-prompt-file").map(|path| {
                (
                    PathBuf::from(path),
                    std::fs::read_to_string(path).expect("the prompt file exists at spawn"),
                )
            }),
            deadlines: deadlines.clone(),
            argv: argv.to_vec(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            cwd: cwd.to_path_buf(),
            stdin,
            token: token.to_string(),
        };
        let script = self
            .scripts
            .lock()
            .unwrap()
            .pop_front()
            .expect("the test scripted no further spawn");
        Ok(Box::new(ScriptedChild {
            lines: script.lines.into(),
            terminal: script.terminal,
            stderr: self.stderr.clone(),
            deadlines,
        }))
    }
}

impl RunningChild for ScriptedChild {
    fn read_line(&mut self, deadline: Instant) -> StdoutRead {
        self.deadlines.lock().unwrap().push(deadline);
        match self.lines.pop_front() {
            Some(line) => StdoutRead::Line(line.into_bytes()),
            None => match self.terminal {
                Terminal::Eof => StdoutRead::Eof,
                Terminal::Timeout => StdoutRead::Timeout,
                Terminal::Breach => StdoutRead::Breach,
            },
        }
    }
    fn stderr_tail(&self) -> Vec<u8> {
        self.stderr.clone()
    }
    fn kill(&mut self) {}
    fn wait(&mut self) {}
}

struct Sessions(Vec<String>);

impl SessionStore for Sessions {
    fn exists(&self, session_id: &str) -> bool {
        self.0.iter().any(|known| known == session_id)
    }
}

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl StderrSink for Sink {
    fn stderr_tail(&self, tail: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(tail);
    }
}

/// The bytes of the stand-in `claude` the scripted rigs pin.
const PINNED: &[u8] = b"the pinned claude bytes";

fn pin_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// A directory holding a pinned `claude` file and an empty `prompts` directory.
fn sandbox() -> TempDir {
    let dir = TempDir::new();
    std::fs::write(dir.path().join("claude"), PINNED).unwrap();
    std::fs::create_dir_all(dir.path().join("prompts")).unwrap();
    dir
}

fn config(dir: &Path, instance: &str, limits: ClaudeCodeLimits) -> ClaudeCodeConfig {
    ClaudeCodeConfig {
        claude_binary: dir.join("claude"),
        claude_binary_sha256: pin_of(PINNED),
        work_dir: PathBuf::from("/work"),
        config_dir: PathBuf::from("/cfg"),
        prompt_dir: dir.join("prompts"),
        token_credential: "claude-token".to_string(),
        instance: instance.to_string(),
        limits,
    }
}

/// A token source with a fixed answer.
struct FixedToken(Option<&'static str>);

impl TokenSource for FixedToken {
    fn read(&self) -> Option<Zeroizing<String>> {
        self.0.map(|token| Zeroizing::new(token.to_string()))
    }
}

fn canary_token() -> Box<dyn TokenSource> {
    Box::new(FixedToken(Some(CANARY_TOKEN)))
}

fn limits() -> ClaudeCodeLimits {
    ClaudeCodeLimits {
        deadline: Duration::from_secs(30),
        max_line_bytes: 1 << 20,
        max_total_bytes: 1 << 24,
        stderr_tail_bytes: 4096,
    }
}

struct Rig {
    dir: TempDir,
    backend: ClaudeCodeBackend,
    spawns: Arc<AtomicUsize>,
    seen: Arc<Mutex<Seen>>,
    sink: Sink,
}

fn rig_for(instance: &str, scripts: Vec<Script>, sessions: &[&str], stderr: &[u8]) -> Rig {
    let spawns = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let sink = Sink::default();
    let port = ScriptedPort {
        scripts: Mutex::new(scripts.into()),
        spawns: spawns.clone(),
        seen: seen.clone(),
        stderr: stderr.to_vec(),
    };
    let dir = sandbox();
    let backend = ClaudeCodeBackend::with_ports(
        config(dir.path(), instance, limits()),
        Box::new(port),
        Box::new(Sessions(sessions.iter().map(|s| s.to_string()).collect())),
        Box::new(sink.clone()),
        canary_token(),
    );
    Rig {
        dir,
        backend,
        spawns,
        seen,
        sink,
    }
}

fn rig(scripts: Vec<Script>) -> Rig {
    rig_for(INSTANCE, scripts, &[SESSION], b"")
}

impl Rig {
    fn run(&self, request: ProviderRequest) -> TransportResult {
        let mut door = Door::new();
        let (claim, _) = door.begin(request);
        self.backend.execute(claim.call())
    }
    fn seen(&self) -> Seen {
        self.seen.lock().unwrap().clone()
    }
    fn spawns(&self) -> usize {
        self.spawns.load(Ordering::SeqCst)
    }
}

// ---- the kit's door, so a call is what serve would hand the backend ----

static DOOR_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct Door {
    dir: PathBuf,
    service: TransportService,
    key: TransportKey,
}

fn prices() -> PriceTable {
    PriceTable::from([MODEL, OTHER_MODEL].map(|model| {
        (
            model.to_string(),
            ModelPrice {
                rates: Rates {
                    input: 3_000_000,
                    cache_write_short: 3_750_000,
                    cache_write_long: 6_000_000,
                    cache_read: 300_000,
                    output: 15_000_000,
                },
                long_context: None,
                overhead_tokens: 100,
            },
        )
    }))
}

impl Door {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "claude-connector-door-{}-{}",
            std::process::id(),
            DOOR_SEQUENCE.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let caller = CallerAdmission::new(
            "caller-1",
            "caller-1-key",
            1,
            [MODEL.to_string(), OTHER_MODEL.to_string()],
            4,
            FRAME / 2,
            32_768,
            SpendCeiling(1 << 40),
            SpendWindowMs(3_600_000),
        )
        .unwrap();
        let service =
            TransportService::open(&dir.join("replay.cc"), PROVIDER, prices(), [caller], 5_000)
                .unwrap();
        Self {
            dir,
            service,
            key: TransportKey::from_connection_secret("caller-1-key").unwrap(),
        }
    }

    fn begin(
        &mut self,
        request: ProviderRequest,
    ) -> (model_connector::ExecutionClaim, TransportInvocation) {
        let invocation =
            TransportInvocation::new("caller-1", 2_000, [7; 32], 10_000_000, request).unwrap();
        let envelope = encrypt_invocation(&invocation, &self.key).unwrap();
        match self.service.begin(&envelope, 1_000, FRAME).unwrap() {
            TransportAdmission::Execute(claim) => (*claim, invocation),
            TransportAdmission::Reply(_) => panic!("the door answered instead of admitting"),
        }
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn parts(result: &TransportResult) -> (&[TransportEvent], &TransportReceipt) {
    match &result.disposition {
        TransportDisposition::Transported { events, receipt } => (events, receipt),
        TransportDisposition::Refused(refusal) => panic!("refused: {refusal:?}"),
    }
}

fn outcome(result: &TransportResult) -> &TransportOutcome {
    &parts(result).1.outcome
}

fn failure_of(result: &TransportResult) -> (FailureKind, String, Option<Usage>) {
    match outcome(result) {
        TransportOutcome::Failed {
            kind,
            message,
            usage,
        } => (*kind, message.clone(), usage.clone()),
        other => panic!("expected a failure, got {other:?}"),
    }
}

fn arg_after<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    let at = argv.iter().position(|arg| arg == flag)?;
    argv.get(at + 1).map(String::as_str)
}

/// A second request that continues `first` with the transcript the kit itself
/// derives from `result`.
fn continuing(first: &ProviderRequest, result: &TransportResult, next: &str) -> ProviderRequest {
    let mut input = first.input.clone();
    input.extend(result.transcript_items());
    input.push(user(next));
    request(input)
}

// ---- argv and environment ----

#[test]
fn argv_is_the_fixed_hygiene_set() {
    let rig = rig(vec![ok_script(SESSION, "hi")]);
    rig.run(request(vec![user("hello")]));
    let argv = rig.seen().argv;
    let prompt_path = arg_after(&argv, "--system-prompt-file")
        .expect("the prompt is passed as a file")
        .to_string();
    let expected: Vec<String> = [
        rig.dir.path().join("claude").to_str().unwrap(),
        "-p",
        "--output-format",
        "stream-json",
        "--verbose",
        "--input-format",
        "stream-json",
        "--model",
        MODEL,
        "--system-prompt-file",
        &prompt_path,
        "--tools",
        "",
        "--strict-mcp-config",
        "--setting-sources",
        "",
        "--disable-slash-commands",
        "--permission-prompts",
        "none",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(argv, expected);
    assert!(!argv.iter().any(|arg| arg == "--system-prompt"));
    for forbidden in [
        "--bare",
        "--fallback-model",
        "--no-session-persistence",
        "--dangerously-skip-permissions",
        "--mcp-config",
        "--add-dir",
        "--agents",
        "--plugin-dir",
        "--settings",
    ] {
        assert!(!argv.iter().any(|arg| arg == forbidden), "{forbidden}");
    }
}

#[test]
fn reasoning_effort_is_passed_as_its_level() {
    for (effort, level) in [
        (ReasoningEffort::Low, "low"),
        (ReasoningEffort::Medium, "medium"),
        (ReasoningEffort::High, "high"),
        (ReasoningEffort::Max, "max"),
    ] {
        let rig = rig(vec![ok_script(SESSION, "hi")]);
        let mut asked = request(vec![user("hello")]);
        asked.reasoning_effort = Some(effort);
        rig.run(asked);
        assert_eq!(arg_after(&rig.seen().argv, "--effort"), Some(level));
    }
}

#[test]
fn resume_always_forks() {
    let rig = rig(vec![ok_script(SESSION, "hi"), ok_script(FORK, "again")]);
    let first = request(vec![user("hello")]);
    let result = rig.run(first.clone());
    let seed_argv = rig.seen().argv;
    assert!(
        !seed_argv
            .iter()
            .any(|a| a == "--resume" || a == "--fork-session")
    );

    rig.run(continuing(&first, &result, "and then?"));
    let argv = rig.seen().argv;
    let at = argv.iter().position(|a| a == "--resume").expect("resumes");
    assert_eq!(argv[at + 1], SESSION);
    assert_eq!(argv[at + 2], "--fork-session");
    assert_eq!(argv.iter().filter(|a| *a == "--fork-session").count(), 1);
}

#[test]
fn child_env_is_cleared_and_names_the_token_descriptor_never_the_token() {
    let rig = rig(vec![ok_script(SESSION, "hi")]);
    let result = rig.run(request(vec![user("hello")]));
    let seen = rig.seen();
    let mut env = seen.env.clone();
    env.sort();
    assert_eq!(
        env,
        vec![
            (
                "CLAUDE_CODE_MAX_OUTPUT_TOKENS".to_string(),
                "1024".to_string()
            ),
            (TOKEN_FD_ENV.to_string(), "3".to_string()),
            ("CLAUDE_CONFIG_DIR".to_string(), "/cfg".to_string()),
            ("HOME".to_string(), "/cfg".to_string()),
            (
                "PATH".to_string(),
                "/usr/local/bin:/usr/bin:/bin".to_string()
            ),
        ]
    );
    assert_eq!(seen.cwd, PathBuf::from("/work"));
    // The credential travels beside the environment, to the port, alone.
    assert_eq!(seen.token, CANARY_TOKEN);
    assert!(
        seen.env
            .iter()
            .all(|(name, value)| name != TOKEN_ENV && value != CANARY_TOKEN)
    );
    assert!(!format!("{result:?}").contains(CANARY_TOKEN));
}

#[test]
fn the_token_never_reaches_a_message_an_event_or_a_debug_form() {
    // A failing run, so a message is built, and the env's own Debug.
    let rig = rig_for(
        INSTANCE,
        vec![Script::lines(vec![init_line(MODEL, SESSION)])],
        &[SESSION],
        CANARY_TOKEN.as_bytes(),
    );
    let result = rig.run(request(vec![user("hello")]));
    let (_, message, _) = failure_of(&result);
    assert!(!message.contains(CANARY_TOKEN));
    assert!(!format!("{result:?}").contains(CANARY_TOKEN));
    // The tail is the sink's alone.
    assert_eq!(
        rig.sink.0.lock().unwrap().as_slice(),
        CANARY_TOKEN.as_bytes()
    );

    let env = child_env(
        &config(rig.dir.path(), INSTANCE, limits()),
        &request(vec![user("x")]),
    );
    let shown = format!("{env:?}");
    assert!(!shown.contains(CANARY_TOKEN));
    assert!(shown.contains(TOKEN_FD_ENV));
}

// ---- ready ----

/// A backend over a scripted port that never has a script: `ready` runs nothing.
fn ready_backend(config: ClaudeCodeConfig, tokens: Box<dyn TokenSource>) -> ClaudeCodeBackend {
    ClaudeCodeBackend::with_ports(
        config,
        Box::new(ScriptedPort {
            scripts: Mutex::new(VecDeque::new()),
            spawns: Arc::new(AtomicUsize::new(0)),
            seen: Arc::new(Mutex::new(Seen::default())),
            stderr: Vec::new(),
        }),
        Box::new(Sessions(vec![])),
        Box::new(Sink::default()),
        tokens,
    )
}

#[test]
fn ready_checks_the_pinned_binary_digest() {
    let dir = sandbox();
    let (work, cfg) = (dir.path().join("work"), dir.path().join("cfg"));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&cfg).unwrap();
    let binary = dir.path().join("claude");

    let ready_field = |sha: [u8; 32], binary: &Path, work: &Path, prompts: &Path, token: bool| {
        let mut config = config(dir.path(), INSTANCE, limits());
        config.claude_binary = binary.to_path_buf();
        config.claude_binary_sha256 = sha;
        config.work_dir = work.to_path_buf();
        config.config_dir = cfg.clone();
        config.prompt_dir = prompts.to_path_buf();
        let tokens = Box::new(FixedToken(token.then_some("t")));
        ready_backend(config, tokens).ready()
    };
    let ready = |sha: [u8; 32], binary: &Path, work: &Path, prompts: &Path, token: bool| {
        ready_field(sha, binary, work, prompts, token).is_ok()
    };
    let prompts = dir.path().join("prompts");
    let pin = pin_of(PINNED);
    assert_eq!(
        ready_field([0; 32], &binary, &work, &prompts, true),
        Err("claude_binary_sha256")
    );
    assert_eq!(
        ready_field(pin, &binary, &dir.path().join("absent"), &prompts, true),
        Err("work_dir")
    );
    assert_eq!(
        ready_field(pin, &binary, &work, &dir.path().join("absent"), true),
        Err("prompt_dir")
    );
    assert_eq!(
        ready_field(pin, &binary, &work, &prompts, false),
        Err("token_credential")
    );
    // The credential is checked last: a document fault is never hidden by it.
    assert_eq!(
        ready_field([0; 32], &binary, &work, &prompts, false),
        Err("claude_binary_sha256")
    );
    assert_eq!(
        ready_field(pin, &binary, &dir.path().join("absent"), &prompts, false),
        Err("work_dir")
    );

    assert!(ready(pin, &binary, &work, &prompts, true));
    assert!(!ready([0; 32], &binary, &work, &prompts, true), "other pin");
    assert!(
        !ready(pin, &dir.path().join("absent"), &work, &prompts, true),
        "no binary"
    );
    assert!(
        !ready(pin, &binary, &dir.path().join("absent"), &prompts, true),
        "no work dir"
    );
    assert!(
        !ready(pin, &binary, &work, &dir.path().join("absent"), true),
        "no prompt dir"
    );
    assert!(!ready(pin, &binary, &work, &prompts, false), "no token");
    std::fs::write(&binary, b"other bytes").unwrap();
    assert!(
        !ready(pin, &binary, &work, &prompts, true),
        "bytes differ from the pin"
    );
}

#[test]
fn token_comes_from_the_credential_file_not_the_environment() {
    static CANARY_PARENT: std::sync::Once = std::sync::Once::new();
    CANARY_PARENT.call_once(|| {
        // SAFETY: set once to a value no code path reads; the test proves none does.
        unsafe { std::env::set_var(TOKEN_ENV, "canary-environment-token") };
    });
    let dir = sandbox();
    let credentials = dir.path().join("credentials");
    for sub in ["credentials", "work", "cfg"] {
        std::fs::create_dir_all(dir.path().join(sub)).unwrap();
    }
    let seen = Arc::new(Mutex::new(Seen::default()));
    let mut config = config(dir.path(), INSTANCE, limits());
    config.work_dir = dir.path().join("work");
    config.config_dir = dir.path().join("cfg");
    let backend = ClaudeCodeBackend::with_ports(
        config,
        Box::new(ScriptedPort {
            scripts: Mutex::new(vec![ok_script(SESSION, "x")].into()),
            spawns: Arc::new(AtomicUsize::new(0)),
            seen: seen.clone(),
            stderr: Vec::new(),
        }),
        Box::new(Sessions(vec![])),
        Box::new(Sink::default()),
        Box::new(CredentialTokenSource::in_directory(
            &credentials,
            "claude-token",
        )),
    );
    let mut door = Door::new();

    // The variable is set and the file is absent: nothing to give the child.
    assert_eq!(backend.ready(), Err("token_credential"));
    let (claim, _) = door.begin(request(vec![user("hi")]));
    let (kind, message, usage) = failure_of(&backend.execute(claim.call()));
    assert_eq!(kind, FailureKind::Authentication);
    assert_eq!(usage, Some(usage_zero()));
    assert!(!message.contains("canary-environment-token"));
    assert!(seen.lock().unwrap().argv.is_empty(), "no child was spawned");

    // The file is read afresh at the call, its trailing newline trimmed, and
    // the port is handed the file's value, which is in no environment.
    std::fs::write(
        credentials.join("claude-token"),
        format!("{CANARY_TOKEN}\n"),
    )
    .unwrap();
    assert_eq!(backend.ready(), Ok(()));
    let mut door = Door::new();
    let (claim, _) = door.begin(request(vec![user("hi")]));
    let result = backend.execute(claim.call());
    assert!(matches!(
        outcome(&result),
        TransportOutcome::Completed { .. }
    ));
    let given = seen.lock().unwrap().clone();
    assert_eq!(given.token, CANARY_TOKEN);
    assert!(
        given
            .env
            .iter()
            .all(|(name, value)| name != TOKEN_ENV && !value.contains("canary-environment-token"))
    );

    // An empty credential is no token.
    std::fs::write(credentials.join("claude-token"), "\n").unwrap();
    assert_eq!(backend.ready(), Err("token_credential"));
}

#[test]
fn an_unreadable_credential_is_no_token() {
    // A credential that is a directory, or a directory that is absent.
    let dir = sandbox();
    std::fs::create_dir_all(dir.path().join("claude-token")).unwrap();
    let source = CredentialTokenSource::in_directory(dir.path(), "claude-token");
    assert!(source.read().is_none());
    assert!(
        CredentialTokenSource::in_directory(dir.path().join("absent"), "x")
            .read()
            .is_none()
    );
}

// ---- planning ----

#[test]
fn seed_renders_one_user_line_deterministically() {
    let input = vec![
        user("a"),
        assistant("b"),
        InputItem::ToolCall {
            call_id: "call-1".into(),
            name: "lookup".into(),
            arguments: "{}".into(),
        },
        InputItem::ToolResult {
            call_id: "call-1".into(),
            output: "out".into(),
        },
        InputItem::ReasoningState {
            provider: "other".into(),
            model: "m".into(),
            state: vec![1],
        },
        assistant("e"),
        user("c"),
        user("d"),
    ];
    let rig = rig(vec![ok_script(SESSION, "x"), ok_script(SESSION, "x")]);
    rig.run(request(input.clone()));
    let first = rig.seen().stdin;
    rig.run(request(input));
    assert_eq!(rig.seen().stdin, first);

    let transcript = "The conversation so far, replayed as text because the earlier session cannot be continued:\\n\\n[user]\\na\\n\\n[assistant]\\nb\\n\\n[tool_call name=lookup id=call-1]\\n{}\\n\\n[tool_result id=call-1]\\nout\\n\\n[assistant]\\ne";
    let expected = format!(
        r#"{{"type":"user","message":{{"role":"user","content":[{{"type":"text","text":"{transcript}"}},{{"type":"text","text":"c"}},{{"type":"text","text":"d"}}]}},"parent_tool_use_id":null}}"#
    ) + "\n";
    assert_eq!(String::from_utf8(first).unwrap(), expected);
}

#[test]
fn a_first_message_is_one_text_block_with_no_transcript() {
    let rig = rig(vec![ok_script(SESSION, "x")]);
    rig.run(request(vec![user("hello")]));
    let stdin = String::from_utf8(rig.seen().stdin).unwrap();
    assert_eq!(
        stdin,
        "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hello\"}]},\"parent_tool_use_id\":null}\n"
    );
}

#[test]
fn a_resume_sends_only_the_new_user_text() {
    let rig = rig(vec![ok_script(SESSION, "hi"), ok_script(FORK, "again")]);
    let first = request(vec![user("hello")]);
    let result = rig.run(first.clone());
    let mut next = continuing(&first, &result, "one");
    next.input.push(user("two"));
    rig.run(next);
    let stdin = String::from_utf8(rig.seen().stdin).unwrap();
    assert_eq!(
        stdin,
        "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"one\"},{\"type\":\"text\",\"text\":\"two\"}]},\"parent_tool_use_id\":null}\n"
    );
}

#[test]
fn handle_round_trips_through_transcript_items() {
    let rig = rig(vec![ok_script(SESSION, "hi"), ok_script(FORK, "again")]);
    let first = request(vec![user("hello")]);
    let result = rig.run(first.clone());
    let items = result.transcript_items();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0], assistant("hi"));
    assert!(
        matches!(&items[1], InputItem::ReasoningState { provider, model, .. }
        if provider == PROVIDER && model == MODEL)
    );

    rig.run(continuing(&first, &result, "next"));
    assert_eq!(arg_after(&rig.seen().argv, "--resume"), Some(SESSION));
}

#[test]
fn a_result_with_no_text_still_resumes() {
    let silent = Script::lines(vec![
        init_line(MODEL, SESSION),
        thinking_line("msg_1"),
        result_line("end_turn", USAGE),
    ]);
    let rig = rig(vec![silent, ok_script(FORK, "again")]);
    let first = request(vec![user("hello")]);
    let result = rig.run(first.clone());
    assert_eq!(result.transcript_items().len(), 1, "only the handle");
    rig.run(continuing(&first, &result, "next"));
    assert_eq!(arg_after(&rig.seen().argv, "--resume"), Some(SESSION));
}

#[test]
fn changed_instructions_or_model_reseeds() {
    let rig = rig(vec![
        ok_script(SESSION, "hi"),
        ok_script(FORK, "x"),
        ok_script(FORK, "x"),
    ]);
    let first = request(vec![user("hello")]);
    let result = rig.run(first.clone());

    let mut other_instructions = continuing(&first, &result, "next");
    other_instructions.instructions = "Be verbose.".into();
    rig.run(other_instructions);
    assert_eq!(arg_after(&rig.seen().argv, "--resume"), None);

    let mut other_model = continuing(&first, &result, "next");
    other_model.model = OTHER_MODEL.into();
    let script = Script::lines(vec![
        init_line(OTHER_MODEL, FORK),
        result_line("end_turn", USAGE),
    ]);
    let rig2 = rig_for(INSTANCE, vec![script], &[SESSION], b"");
    rig2.run(other_model);
    assert_eq!(arg_after(&rig2.seen().argv, "--resume"), None);
}

#[test]
fn foreign_instance_missing_session_or_edited_prefix_reseeds() {
    let first = request(vec![user("hello"), assistant("earlier"), user("more")]);
    let make = |instance: &str, sessions: &[&str]| {
        let rig = rig_for(
            instance,
            vec![ok_script(SESSION, "hi"), ok_script(FORK, "x")],
            sessions,
            b"",
        );
        let result = rig.run(first.clone());
        (rig, result)
    };

    // Control: the same instance with its session resumes.
    let (rig_ok, result) = make(INSTANCE, &[SESSION]);
    rig_ok.run(continuing(&first, &result, "next"));
    assert_eq!(arg_after(&rig_ok.seen().argv, "--resume"), Some(SESSION));

    // Another instance wrote the handle.
    let (rig_a, result) = make("persona-b", &[SESSION]);
    let handle_request = continuing(&first, &result, "next");
    let rig_b = rig_for(INSTANCE, vec![ok_script(FORK, "x")], &[SESSION], b"");
    rig_b.run(handle_request);
    assert_eq!(arg_after(&rig_b.seen().argv, "--resume"), None);
    drop(rig_a);

    // The session file is gone.
    let (rig_c, result) = make(INSTANCE, &[]);
    rig_c.run(continuing(&first, &result, "next"));
    assert_eq!(arg_after(&rig_c.seen().argv, "--resume"), None);

    // An item before the handle was edited.
    let (rig_d, result) = make(INSTANCE, &[SESSION]);
    let mut edited = continuing(&first, &result, "next");
    edited.input[1] = assistant("edited");
    rig_d.run(edited);
    assert_eq!(arg_after(&rig_d.seen().argv, "--resume"), None);
}

#[test]
fn assistant_items_after_the_handle_reseed() {
    for tail in [
        vec![assistant("interjection"), user("next")],
        vec![
            InputItem::ToolCall {
                call_id: "c".into(),
                name: "n".into(),
                arguments: "{}".into(),
            },
            user("next"),
        ],
    ] {
        let rig = rig(vec![ok_script(SESSION, "hi"), ok_script(FORK, "x")]);
        let first = request(vec![user("hello")]);
        let result = rig.run(first.clone());
        let mut input = first.input.clone();
        input.extend(result.transcript_items());
        input.extend(tail);
        rig.run(request(input));
        assert_eq!(arg_after(&rig.seen().argv, "--resume"), None);
    }
}

#[test]
fn the_last_own_handle_decides() {
    let rig = rig_for(
        INSTANCE,
        vec![
            ok_script(SESSION, "one"),
            ok_script(FORK, "two"),
            ok_script(SESSION, "three"),
        ],
        &[SESSION, FORK],
        b"",
    );
    let first = request(vec![user("a")]);
    let r1 = rig.run(first.clone());
    let second = continuing(&first, &r1, "b");
    let r2 = rig.run(second.clone());
    let third = continuing(&second, &r2, "c");
    rig.run(third);
    // The newest handle names the fork of the first resume, not the first session.
    assert_eq!(arg_after(&rig.seen().argv, "--resume"), Some(FORK));
}

#[test]
fn undecodable_own_handle_fails_before_spawn() {
    let rig = rig(vec![]);
    let bad = request(vec![
        user("a"),
        InputItem::ReasoningState {
            provider: PROVIDER.into(),
            model: MODEL.into(),
            state: vec![1, 2, 3],
        },
        user("b"),
    ]);
    let (kind, _, usage) = failure_of(&rig.run(bad));
    assert_eq!(kind, FailureKind::InvalidRequest);
    assert_eq!(usage, Some(usage_zero()));
    assert_eq!(rig.spawns(), 0);
}

fn usage_zero() -> Usage {
    usage(0, 0, 0, 0, None)
}

#[test]
fn tools_or_final_tool_result_fail_before_spawn() {
    let mut with_tools = request(vec![user("a")]);
    with_tools.tools.push(a_tool());
    let final_tool_result = request(vec![
        user("a"),
        InputItem::ToolCall {
            call_id: "c".into(),
            name: "n".into(),
            arguments: "{}".into(),
        },
        InputItem::ToolResult {
            call_id: "c".into(),
            output: "o".into(),
        },
    ]);
    let ends_without_user_text = request(vec![user("a"), assistant("b")]);
    let tool_result_beside_text = request(vec![
        assistant("b"),
        InputItem::ToolResult {
            call_id: "c".into(),
            output: "o".into(),
        },
        user("a"),
    ]);

    let rig = rig(vec![]);
    let mut messages = Vec::new();
    for refused in [
        with_tools,
        final_tool_result,
        ends_without_user_text,
        tool_result_beside_text,
    ] {
        let (kind, message, usage) = failure_of(&rig.run(refused));
        assert_eq!(kind, FailureKind::InvalidRequest);
        assert_eq!(usage, Some(usage_zero()));
        messages.push(message);
    }
    assert_eq!(rig.spawns(), 0);
    // Each refusal names what lifts it.
    assert_eq!(messages[1], messages[3]);
    let distinct: std::collections::HashSet<_> = messages.iter().collect();
    assert_eq!(distinct.len(), 3, "{messages:?}");
}

// ---- the stream ----

#[test]
fn stream_maps_text_in_order_and_ends_with_the_handle() {
    let script = Script::lines(vec![
        init_line(MODEL, SESSION),
        thinking_line("msg_0"),
        text_line("msg_1", "Hel"),
        text_line("msg_2", ""),
        text_line("msg_3", "lo"),
        r#"{"type":"system","subtype":"post_turn_summary","summary":"x"}"#.to_string(),
        r#"{"type":"unheard_of","field":1}"#.to_string(),
        result_line("end_turn", USAGE),
    ]);
    let rig = rig(vec![script]);
    let result = rig.run(request(vec![user("hi")]));
    let (events, receipt) = parts(&result);
    let payloads: Vec<_> = events.iter().map(|e| e.payload.clone()).collect();
    assert_eq!(payloads.len(), 3);
    assert_eq!(
        payloads[0],
        TransportEventPayload::TextDelta { text: "Hel".into() }
    );
    assert_eq!(
        payloads[1],
        TransportEventPayload::TextDelta { text: "lo".into() }
    );
    assert!(matches!(
        payloads[2],
        TransportEventPayload::ReasoningState { .. }
    ));
    assert_eq!(
        events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    let TransportOutcome::Completed {
        provider_response_id,
        stop_reason,
        usage: _,
    } = &receipt.outcome
    else {
        panic!("completed expected");
    };
    assert_eq!(provider_response_id.as_deref(), Some("msg_3"));
    assert_eq!(*stop_reason, model_connector::StopReason::EndTurn);
}

#[test]
fn every_stop_reason_has_its_own_mapping() {
    use model_connector::StopReason::*;
    for (cli, expected) in [
        ("end_turn", EndTurn),
        ("max_tokens", MaxOutputTokens),
        ("stop_sequence", StopSequence),
        ("refusal", Refusal),
        ("model_context_window_exceeded", ContextWindow),
    ] {
        let script = Script::lines(vec![init_line(MODEL, SESSION), result_line(cli, USAGE)]);
        let result = rig(vec![script]).run(request(vec![user("hi")]));
        let TransportOutcome::Completed { stop_reason, .. } = outcome(&result) else {
            panic!("{cli} should complete");
        };
        assert_eq!(*stop_reason, expected, "{cli}");
    }
    for odd in ["tool_use", "pause_turn", ""] {
        let script = Script::lines(vec![init_line(MODEL, SESSION), result_line(odd, USAGE)]);
        let (kind, _, usage) = failure_of(&rig(vec![script]).run(request(vec![user("hi")])));
        assert_eq!(kind, FailureKind::Provider);
        assert!(usage.is_some());
    }
}

#[test]
fn usage_sums_model_usage_across_models() {
    let two_models = r#"{"claude-haiku-5-5":{"inputTokens":2,"outputTokens":4,"cacheReadInputTokens":7,"cacheCreationInputTokens":1043,"thinkingTokens":3},"claude-sonnet-5":{"inputTokens":10,"outputTokens":20,"cacheReadInputTokens":30,"cacheCreationInputTokens":40,"thinkingTokens":5}}"#;
    let run = |total_cost: &str| {
        let result_line = format!(
            r#"{{"type":"result","subtype":"success","is_error":false,"stop_reason":"end_turn","total_cost_usd":{total_cost},"model_usage_since_last_result":{two_models}}}"#
        );
        let script = Script::lines(vec![init_line(MODEL, SESSION), result_line]);
        rig(vec![script]).run(request(vec![user("hi")]))
    };
    let (cheap, dear) = (run("0.000001"), run("99.5"));
    let TransportOutcome::Completed { usage: summed, .. } = outcome(&cheap) else {
        panic!("completed expected");
    };
    assert_eq!(*summed, usage(12, 37, 1083, 24, Some(8)));
    // The receipt is priced from usage alone: 12*3 + 37*0.3 + 1083*6 + 24*15 micro-USD, rounded up.
    assert_eq!(parts(&cheap).1.cost_micro_usd, 36 + 12 + 6498 + 360);
    assert_eq!(
        parts(&cheap).1.cost_micro_usd,
        parts(&dear).1.cost_micro_usd
    );

    // No model reported thinking tokens: none is claimed.
    let plain = r#"{"claude-haiku-5-5":{"inputTokens":1,"outputTokens":1,"cacheReadInputTokens":0,"cacheCreationInputTokens":0}}"#;
    let script = Script::lines(vec![
        init_line(MODEL, SESSION),
        result_line("end_turn", plain),
    ]);
    let result = rig(vec![script]).run(request(vec![user("hi")]));
    let TransportOutcome::Completed { usage, .. } = outcome(&result) else {
        panic!("completed expected");
    };
    assert_eq!(*usage, self::usage(1, 0, 0, 1, None));
}

#[test]
fn init_model_mismatch_is_a_provider_failure() {
    let script = Script::lines(vec![
        init_line("haiku", SESSION),
        result_line("end_turn", USAGE),
    ]);
    let (kind, _, usage) = failure_of(&rig(vec![script]).run(request(vec![user("hi")])));
    assert_eq!(kind, FailureKind::Provider);
    assert_eq!(usage, None);
}

#[test]
fn result_errors_map_to_failure_kinds_with_their_usage() {
    let rate_limit_text = r#","result":"You have hit your rate limit""#;
    let cases: Vec<(Vec<String>, FailureKind)> = vec![
        (
            vec![rate_limit_line("rejected"), error_result_line("")],
            FailureKind::RateLimited,
        ),
        // The rejection latches: a later event that allows does not undo it.
        (
            vec![
                rate_limit_line("rejected"),
                rate_limit_line("allowed"),
                error_result_line(""),
            ],
            FailureKind::RateLimited,
        ),
        (
            vec![error_result_line(r#","api_error_status":429"#)],
            FailureKind::RateLimited,
        ),
        (
            vec![error_result_line(rate_limit_text)],
            FailureKind::RateLimited,
        ),
        (
            vec![error_result_line(r#","errors":["rate_limit_error"]"#)],
            FailureKind::RateLimited,
        ),
        (
            vec![error_result_line(r#","api_error_status":401"#)],
            FailureKind::Authentication,
        ),
        (
            vec![error_result_line(r#","api_error_status":403"#)],
            FailureKind::Authentication,
        ),
        (
            vec![error_result_line(r#","api_error_status":400"#)],
            FailureKind::InvalidRequest,
        ),
        (
            vec![error_result_line(r#","api_error_status":500"#)],
            FailureKind::Unavailable,
        ),
        (
            vec![error_result_line(r#","api_error_status":529"#)],
            FailureKind::Unavailable,
        ),
        (
            vec![error_result_line(r#","api_error_status":null"#)],
            FailureKind::Provider,
        ),
        (
            vec![rate_limit_line("allowed"), error_result_line("")],
            FailureKind::Provider,
        ),
    ];
    for (lines, expected) in cases {
        let mut all = vec![init_line(MODEL, SESSION)];
        all.extend(lines.clone());
        let result = rig(vec![Script::lines(all)]).run(request(vec![user("hi")]));
        let (kind, _, usage) = failure_of(&result);
        assert_eq!(kind, expected, "{lines:?}");
        assert!(
            usage.is_some(),
            "a result event carries its usage: {lines:?}"
        );
    }
    // The usage of an error result is the sum the event reported.
    let result = rig(vec![Script::lines(vec![
        init_line(MODEL, SESSION),
        error_result_line(""),
    ])])
    .run(request(vec![user("hi")]));
    assert_eq!(failure_of(&result).2, Some(usage(2, 7, 1043, 4, Some(3))));
}

#[test]
fn no_result_event_is_a_failure_with_unknown_usage() {
    let ends: Vec<(Script, FailureKind)> = vec![
        (
            Script::lines(vec![init_line(MODEL, SESSION), text_line("m", "x")]),
            FailureKind::Provider,
        ),
        (
            Script::lines(vec![
                init_line(MODEL, SESSION),
                "not json at all".to_string(),
            ]),
            FailureKind::Provider,
        ),
        (
            Script::lines(vec![init_line(MODEL, SESSION)]).ending(Terminal::Breach),
            FailureKind::Provider,
        ),
        (
            Script::lines(vec![init_line(MODEL, SESSION)]).ending(Terminal::Timeout),
            FailureKind::Timeout,
        ),
    ];
    let zero_billed = {
        let (_, _, usage) = failure_of(&rig(vec![]).run({
            let mut bad = request(vec![user("a")]);
            bad.tools.push(a_tool());
            bad
        }));
        usage
    };
    assert_eq!(zero_billed, Some(usage_zero()));

    let mut costs = Vec::new();
    for (script, expected) in ends {
        let rig = rig(vec![script]);
        let result = rig.run(request(vec![user("hi")]));
        let (kind, message, usage) = failure_of(&result);
        assert_eq!(kind, expected);
        assert_eq!(usage, None, "{message}");
        assert!(result.transcript_items().is_empty());
        costs.push(parts(&result).1.cost_micro_usd);
    }
    // Unknown usage is charged the reservation, which is far above a typical turn.
    assert!(costs.iter().all(|cost| *cost >= 15_000), "{costs:?}");
    assert_eq!(
        parts(&rig(vec![]).run({
            let mut bad = request(vec![user("a")]);
            bad.tools.push(a_tool());
            bad
        }))
        .1
        .cost_micro_usd,
        0
    );
}

#[test]
fn tool_use_or_compaction_in_the_stream_is_a_provider_failure() {
    for line in [
        tool_use_line(),
        r#"{"type":"system","subtype":"compact_boundary"}"#.to_string(),
    ] {
        let script = Script::lines(vec![
            init_line(MODEL, SESSION),
            text_line("m", "partial"),
            line.clone(),
            result_line("end_turn", USAGE),
        ]);
        let result = rig(vec![script]).run(request(vec![user("hi")]));
        let (kind, _, usage) = failure_of(&result);
        assert_eq!(kind, FailureKind::Provider, "{line}");
        assert_eq!(usage, None);
        assert!(
            parts(&result).0.is_empty(),
            "no partial reasoning is replayed"
        );
    }
}

#[test]
fn a_result_before_any_init_names_no_session() {
    let script = Script::lines(vec![result_line("end_turn", USAGE)]);
    let (kind, _, usage) = failure_of(&rig(vec![script]).run(request(vec![user("hi")])));
    assert_eq!(kind, FailureKind::Provider);
    assert!(usage.is_some());
}

// ---- spawns ----

#[test]
fn one_spawn_per_execute() {
    let scripts: Vec<(Script, usize)> = vec![
        (ok_script(SESSION, "x"), 1),
        (
            Script::lines(vec![init_line(MODEL, SESSION), error_result_line("")]),
            1,
        ),
        (Script::lines(vec![]).ending(Terminal::Eof), 1),
        (Script::lines(vec![]).ending(Terminal::Timeout), 1),
        (Script::lines(vec![]).ending(Terminal::Breach), 1),
    ];
    for (script, expected) in scripts {
        let rig = rig(vec![script]);
        rig.run(request(vec![user("hi")]));
        assert_eq!(rig.spawns(), expected);
    }
}

#[test]
fn a_missing_token_fails_before_spawn() {
    let mut rig = rig(vec![ok_script(SESSION, "x")]);
    rig.backend.tokens = Box::new(FixedToken(None));
    let (kind, _, usage) = failure_of(&rig.run(request(vec![user("hi")])));
    assert_eq!(kind, FailureKind::Authentication);
    assert_eq!(usage, Some(usage_zero()));
    assert_eq!(rig.spawns(), 0);
}

#[test]
fn a_port_that_cannot_spawn_is_a_provider_failure() {
    struct Refusing;
    impl ProcessPort for Refusing {
        fn spawn(
            &self,
            _: &[String],
            _: &ChildEnv,
            _: &Path,
            _: Vec<u8>,
            _: &str,
        ) -> io::Result<Box<dyn RunningChild>> {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
    let dir = sandbox();
    let backend = ClaudeCodeBackend::with_ports(
        config(dir.path(), INSTANCE, limits()),
        Box::new(Refusing),
        Box::new(Sessions(vec![])),
        Box::new(Sink::default()),
        canary_token(),
    );
    let mut door = Door::new();
    let (claim, _) = door.begin(request(vec![user("hi")]));
    let result = backend.execute(claim.call());
    let (kind, message, usage) = failure_of(&result);
    assert_eq!(kind, FailureKind::Provider);
    assert_eq!(
        usage,
        Some(usage_zero()),
        "a child that never ran bills nothing"
    );
    assert_eq!(parts(&result).1.cost_micro_usd, 0);
    assert!(
        !message.contains(dir.path().to_str().unwrap()),
        "no path in a message"
    );
}

#[test]
fn backend_end_to_end_through_the_service() {
    let rig = rig(vec![ok_script(SESSION, "hello back")]);
    let mut door = Door::new();
    let (claim, invocation) = door.begin(request(vec![user("hello")]));
    let result = rig.backend.execute(claim.call());
    let sealed = door.service.complete(claim, result, FRAME).unwrap();
    let opened = decrypt_result(&sealed, &door.key, &invocation).unwrap();
    let (events, receipt) = parts(&opened);
    assert_eq!(receipt.provider, "claude-code");
    assert_eq!(receipt.model, MODEL);
    // USAGE priced at the table: 2*3 + 7*0.3 + 1043*6 + 4*15 micro-USD, rounded up.
    assert_eq!(receipt.cost_micro_usd, 6 + 3 + 6258 + 60);
    assert_eq!(receipt.overrun_micro_usd, 0);
    assert_eq!(events.len(), 2);
    let items = opened.transcript_items();
    assert_eq!(items[0], assistant("hello back"));
    assert!(
        matches!(&items[1], InputItem::ReasoningState { provider, .. } if provider == "claude-code")
    );
}

// ---- usage: this turn's own, or unknown ----

const USAGE_TURN_2: &str = r#"{"claude-haiku-5-5":{"inputTokens":3,"outputTokens":5,"cacheReadInputTokens":1100,"cacheCreationInputTokens":9}}"#;

/// What a call whose usage is unknown is billed: the kit's reservation.
fn reservation() -> u64 {
    let result = rig(vec![Script::lines(vec![])]).run(request(vec![user("hi")]));
    assert_eq!(failure_of(&result).2, None);
    parts(&result).1.cost_micro_usd
}

#[test]
fn a_resumed_turn_is_charged_only_its_own_usage() {
    let rig = rig(vec![
        ok_script(SESSION, "one"),
        Script::lines(vec![
            init_line(MODEL, FORK),
            text_line("msg_2", "two"),
            // The CLI's `modelUsage` here is the cumulative CUMULATIVE of
            // result_line; only the turn's own field may be billed.
            result_line("end_turn", USAGE_TURN_2),
        ]),
    ]);
    let first_request = request(vec![user("hello")]);
    let first = rig.run(first_request.clone());
    let second = rig.run(continuing(&first_request, &first, "again"));
    assert!(
        rig.seen().argv.iter().any(|arg| arg == "--resume"),
        "the second turn resumes"
    );
    let TransportOutcome::Completed { usage: billed, .. } = outcome(&second) else {
        panic!("completed expected");
    };
    assert_eq!(*billed, usage(3, 1100, 9, 5, None));
    // 3*3 + 1100*0.3 + 9*6 + 5*15 micro-USD.
    assert_eq!(parts(&second).1.cost_micro_usd, 9 + 330 + 54 + 75);
}

#[test]
fn usage_the_result_does_not_report_is_billed_the_reservation() {
    let reservation = reservation();
    assert!(reservation >= 15_000, "{reservation}");
    let success = |fields: &str| {
        format!(
            r#"{{"type":"result","subtype":"success","is_error":false,"stop_reason":"end_turn","modelUsage":{CUMULATIVE}{fields}}}"#
        )
    };
    let error = |fields: &str| {
        format!(
            r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"modelUsage":{CUMULATIVE}{fields}}}"#
        )
    };
    let renamed = r#","model_usage_since_last_result":{"claude-haiku-5-5":{"input_tokens":5000,"output_tokens":9000}}"#;
    let no_cache_counts = r#","model_usage_since_last_result":{"claude-haiku-5-5":{"inputTokens":1,"outputTokens":1}}"#;
    let cases = [
        success(""),
        success(r#","model_usage_since_last_result":{}"#),
        success(r#","model_usage_since_last_result":null"#),
        success(r#","model_usage_since_last_result":"none""#),
        success(renamed),
        success(no_cache_counts),
        error(""),
        error(r#","model_usage_since_last_result":{}"#),
        error(renamed),
    ];
    // An empty report from a server error, or none from a refusal, is not a
    // refusal at the door that reported nothing spent.
    let by_status = [
        (
            r#","api_error_status":500,"model_usage_since_last_result":{}"#,
            FailureKind::Unavailable,
        ),
        (r#","api_error_status":401"#, FailureKind::Authentication),
    ];
    for (fields, expected) in by_status {
        let line = error(fields);
        let result = rig(vec![Script::lines(vec![
            init_line(MODEL, SESSION),
            text_line("m", "work"),
            line.clone(),
        ])])
        .run(request(vec![user("hi")]));
        let (kind, _, usage) = failure_of(&result);
        assert_eq!(kind, expected, "{line}");
        assert_eq!(usage, None, "{line}");
        assert_eq!(parts(&result).1.cost_micro_usd, reservation, "{line}");
    }
    for line in cases {
        let result = rig(vec![Script::lines(vec![
            init_line(MODEL, SESSION),
            text_line("m", "work"),
            line.clone(),
        ])])
        .run(request(vec![user("hi")]));
        let (kind, _, usage) = failure_of(&result);
        assert_eq!(kind, FailureKind::Provider, "{line}");
        assert_eq!(usage, None, "{line}");
        assert_eq!(parts(&result).1.cost_micro_usd, reservation, "{line}");
        assert!(result.transcript_items().is_empty(), "{line}");
    }
}

#[test]
fn door_set_is_exactly_401_403_429() {
    // Ruling claude-code-plan-quota-fuse-2 with spend-bills-on-identity-not-
    // validity: a refusal at the door is charged nothing, for exactly the
    // statuses the provider cannot have billed (401, 403, 429) and only when
    // the result says its usage is explicitly empty. Every other shape is
    // billed the reservation. The 401 shape is a real claude 2.1.312 capture
    // with a bogus token.
    let retry = r#"{"type":"system","subtype":"api_retry","error":"authentication_failed"}"#;
    let synthetic = r#"{"type":"assistant","api_error_status":401,"error":"authentication_failed","message":{"id":"e48001b7-cf4f-49b1-9810-db8fd7f73c73","model":"<synthetic>","stop_reason":"stop_sequence","content":[{"type":"text","text":"Failed to authenticate. API Error: 401 OAuth access token is invalid."}]}}"#;
    let reservation = reservation();
    let statuses: [Option<u16>; 9] = [
        Some(400),
        Some(401),
        Some(402),
        Some(403),
        Some(404),
        Some(429),
        Some(500),
        Some(529),
        None,
    ];
    let shapes = [
        (Some("{}"), "empty"),
        (None, "absent"),
        (Some("null"), "null"),
    ];
    for status in statuses {
        for (since_last, shape) in shapes {
            let status_field = status
                .map(|status| format!(r#""api_error_status":{status},"#))
                .unwrap_or_default();
            let usage_field = since_last
                .map(|usage| format!(r#","model_usage_since_last_result":{usage}"#))
                .unwrap_or_default();
            let result_line = format!(
                r#"{{"type":"result","subtype":"success","is_error":true,{status_field}"stop_reason":"stop_sequence","result":"Failed.","modelUsage":{CUMULATIVE}{usage_field},"terminal_reason":"api_error"}}"#
            );
            let result = rig(vec![Script::lines(vec![
                init_line(MODEL, SESSION),
                retry.to_string(),
                synthetic.to_string(),
                result_line,
            ])])
            .run(request(vec![user("hi")]));
            let (_, _, usage) = failure_of(&result);
            let case = format!("{status:?} {shape}");
            if matches!(status, Some(401 | 403 | 429)) && shape == "empty" {
                assert_eq!(usage, Some(usage_zero()), "{case}");
                assert_eq!(parts(&result).1.cost_micro_usd, 0, "{case}");
            } else {
                assert_eq!(usage, None, "{case}");
                assert_eq!(parts(&result).1.cost_micro_usd, reservation, "{case}");
            }
        }
    }
}

#[test]
fn the_deadline_is_the_configured_deadline() {
    let rig = rig(vec![ok_script(SESSION, "x")]);
    let (before, configured) = (Instant::now(), limits().deadline);
    rig.run(request(vec![user("hi")]));
    let after = Instant::now();
    let deadlines = rig.seen().deadlines.lock().unwrap().clone();
    assert!(deadlines.len() >= 2, "the result read and the drain read");
    for deadline in deadlines {
        // Neither clamped nor scaled: exactly `configured` after the call began.
        assert!(
            deadline >= before + configured,
            "the deadline was shortened"
        );
        assert!(deadline <= after + configured, "the deadline was stretched");
    }
}

#[test]
fn the_system_prompt_goes_in_a_file_however_large() {
    let instructions = "p".repeat(300 * 1024);
    let rig = rig(vec![ok_script(SESSION, "x")]);
    let mut big = request(vec![user("hi")]);
    big.instructions = instructions.clone();
    rig.run(big);
    let seen = rig.seen();
    assert!(
        seen.argv.iter().all(|arg| arg.len() < 4096),
        "no argument carries the instructions"
    );
    let (path, contents) = seen.prompt_file.expect("the argv names a prompt file");
    assert_eq!(contents, instructions);
    assert!(!path.exists(), "the backend removes the file it staged");
}

#[test]
fn the_prompt_file_is_removed_when_the_call_fails() {
    for script in [
        Script::lines(vec![]).ending(Terminal::Eof),
        Script::lines(vec![]).ending(Terminal::Timeout),
        Script::lines(vec![init_line(MODEL, SESSION), error_result_line("")]),
    ] {
        let rig = rig(vec![script]);
        rig.run(request(vec![user("hi")]));
        let (path, _) = rig.seen().prompt_file.expect("a prompt file");
        assert!(!path.exists());
    }
}

#[test]
fn prompt_file_lives_in_prompt_dir_exclusively() {
    let rig = rig(vec![ok_script(SESSION, "x")]);
    rig.run(request(vec![user("hi")]));
    let (path, _) = rig.seen().prompt_file.expect("a prompt file");
    assert_eq!(
        path.parent(),
        Some(rig.dir.path().join("prompts").as_path())
    );

    // A prompt directory that cannot take the file fails staging: nothing
    // reached the provider, so it bills nothing, and no child runs.
    let rig = rig_for(INSTANCE, vec![ok_script(SESSION, "x")], &[SESSION], b"");
    std::fs::remove_dir_all(rig.dir.path().join("prompts")).unwrap();
    let result = rig.run(request(vec![user("hi")]));
    let (kind, _, usage) = failure_of(&result);
    assert_eq!((kind, usage), (FailureKind::Provider, Some(usage_zero())));
    assert_eq!(parts(&result).1.cost_micro_usd, 0);
    assert_eq!(rig.spawns(), 0);
}

#[test]
fn pin_is_checked_before_every_spawn() {
    let rig = rig(vec![ok_script(SESSION, "x"), ok_script(SESSION, "y")]);
    let binary = rig.dir.path().join("claude");
    assert!(rig.backend.binary_matches_pin());
    rig.run(request(vec![user("hi")]));
    assert_eq!(rig.spawns(), 1);

    // The binary is swapped after readiness: the next call never spawns.
    std::fs::write(&binary, b"swapped bytes").unwrap();
    let result = rig.run(request(vec![user("hi")]));
    let (kind, message, usage) = failure_of(&result);
    assert_eq!((kind, usage), (FailureKind::Provider, Some(usage_zero())));
    assert_eq!(
        parts(&result).1.cost_micro_usd,
        0,
        "billed nothing, not the reservation"
    );
    assert!(!message.contains(rig.dir.path().to_str().unwrap()));
    assert_eq!(rig.spawns(), 1, "no child for a binary off its pin");
    assert!(!rig.backend.binary_matches_pin());
    let staged = std::fs::read_dir(rig.dir.path().join("prompts")).unwrap();
    assert_eq!(staged.count(), 0, "no prompt was staged for it");

    // Restoring the pinned bytes is enough: nothing remembers the verdict.
    std::fs::write(&binary, PINNED).unwrap();
    rig.run(request(vec![user("hi")]));
    assert_eq!(rig.spawns(), 2);
}

#[test]
fn the_provider_tag_is_claude_code() {
    assert_eq!(rig(vec![]).backend.provider(), "claude-code");
}

// ---- the session store ----

#[test]
fn the_session_store_finds_only_canonical_session_files() {
    let dir = TempDir::new();
    let project = dir.path().join("projects").join("-work");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join(format!("{SESSION}.jsonl")), b"{}").unwrap();
    std::fs::write(project.join(format!("{HEX_SESSION}.jsonl")), b"{}").unwrap();
    // Files a loose check would find: one character short, one too long.
    std::fs::write(project.join(format!("{}.jsonl", &SESSION[..35])), b"{}").unwrap();
    std::fs::write(project.join(format!("{SESSION}0.jsonl")), b"{}").unwrap();
    std::fs::write(dir.path().join("projects").join("secret.jsonl"), b"{}").unwrap();
    let store = FsSessionStore::new(dir.path().to_path_buf());
    assert!(store.exists(SESSION));
    assert!(!store.exists(FORK));
    assert!(!store.exists("secret"));
    assert!(!store.exists("../secret"));
    assert!(store.exists(HEX_SESSION));
    assert!(!store.exists(&HEX_SESSION.to_uppercase()));
    assert!(!store.exists("gggggggg-bbbb-cccc-dddd-eeeeeeeeeeee"));
    assert!(!store.exists(&SESSION[..35]));
    assert!(!store.exists(&format!("{SESSION}0")));
    assert!(!store.exists("11111111_2222-3333-4444-555555555555"));
    assert!(!FsSessionStore::new(dir.path().join("absent")).exists(SESSION));
}

// ---- real processes: a fake claude shell script (unix) ----

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "claude-connector-test-{}-{}",
            std::process::id(),
            DOOR_SEQUENCE.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- structured output and the plan quota ----

#[test]
fn schema_request_lowers_to_json_schema() {
    let rig = rig(vec![structured_script(), ok_script(SESSION, "hi")]);
    rig.run(schema_request());
    let argv = rig.seen().argv;
    assert_eq!(arg_after(&argv, "--json-schema"), Some(SCHEMA));
    assert_eq!(argv.iter().filter(|a| *a == "--json-schema").count(), 1);
    // The tool-less hygiene stays with it.
    assert_eq!(arg_after(&argv, "--tools"), Some(""));
    assert!(argv.iter().any(|a| a == "--strict-mcp-config"));
    assert!(!argv.iter().any(|a| a == "--mcp-config"));

    rig.run(request(vec![user("hello")]));
    assert!(!rig.seen().argv.iter().any(|a| a == "--json-schema"));
}

#[test]
fn structured_output_becomes_assistant_text() {
    let rig = rig(vec![structured_script()]);
    let result = rig.run(schema_request());
    let TransportOutcome::Completed {
        stop_reason, usage, ..
    } = outcome(&result)
    else {
        panic!("expected completion, got {:?}", outcome(&result));
    };
    assert_eq!(*stop_reason, StopReason::EndTurn);
    assert_eq!(*usage, usage_cost_fixture());
    let (events, _) = parts(&result);
    let texts: Vec<&str> = events
        .iter()
        .filter_map(|event| match &event.payload {
            TransportEventPayload::TextDelta { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, [STRUCTURED]);
    let items = result.transcript_items();
    assert_eq!(items[0], assistant(STRUCTURED));
    // The answer is JSON the caller decodes with serde: it is the object.
    let decoded: serde_json::Value = serde_json::from_str(STRUCTURED).unwrap();
    assert_eq!(decoded["answer"], "say hello");
}

fn usage_cost_fixture() -> Usage {
    usage(2, 7, 1043, 4, Some(3))
}

#[test]
fn a_schema_turn_without_structured_output_is_a_provider_failure_billed_as_reported() {
    for line in [
        result_line("tool_use", USAGE),
        result_line_with("end_turn", USAGE, r#","structured_output":null"#),
    ] {
        let rig = rig(vec![Script::lines(vec![
            init_line(MODEL, SESSION),
            text_line("msg_1", "prose, not the schema"),
            line,
        ])]);
        let result = rig.run(schema_request());
        let (kind, _, usage) = failure_of(&result);
        assert_eq!(kind, FailureKind::Provider);
        assert_eq!(usage, Some(usage_cost_fixture()), "the turn was billed");
        assert!(result.transcript_items().is_empty());
    }
}

#[test]
fn only_the_structured_output_tool_is_allowed_and_only_when_a_schema_was_sent() {
    // Without a schema the same call is a tool in a tool-less turn.
    let first = rig(vec![structured_script()]);
    let (kind, message, _) = failure_of(&first.run(request(vec![user("hello")])));
    assert_eq!(kind, FailureKind::Provider);
    assert!(message.contains("tool"), "{message}");

    // With a schema, any other tool is still refused.
    let second = rig(vec![Script::lines(vec![
        init_line(MODEL, SESSION),
        structured_call_line("Bash"),
        structured_result_line(),
    ])]);
    let (kind, message, _) = failure_of(&second.run(schema_request()));
    assert_eq!(kind, FailureKind::Provider);
    assert!(message.contains("tool"), "{message}");

    // `tool_use` is a stop reason only for a schema turn.
    let third = rig(vec![Script::lines(vec![
        init_line(MODEL, SESSION),
        text_line("msg_1", "hi"),
        result_line("tool_use", USAGE),
    ])]);
    let (kind, message, _) = failure_of(&third.run(request(vec![user("hello")])));
    assert_eq!(kind, FailureKind::Provider);
    assert!(message.contains("stop reason"), "{message}");
}

fn quota_of(rig: &Rig) -> model_connector::PlanQuotaSnapshot {
    rig.backend.plan_quota()
}

fn window(name: &str, permille: u32, resets_at_unix_ms: u64) -> model_connector::PlanQuota {
    model_connector::PlanQuota {
        window: name.to_string(),
        utilization_permille: permille,
        resets_at_unix_ms,
        status: "allowed".to_string(),
    }
}

#[test]
fn rate_limit_event_updates_quota_cell() {
    let rig = rig(vec![structured_script()]);
    assert!(quota_of(&rig).windows.is_empty());
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    rig.run(schema_request());
    let snapshot = quota_of(&rig);
    assert_eq!(
        snapshot.windows,
        vec![
            window("five_hour", 80, 1_793_307_000_000),
            window("seven_day", 300, 1_793_656_800_000),
        ]
    );
    assert!(snapshot.observed_at_unix_ms.unwrap() >= before);
    // The cell is the one the backend hands out.
    assert_eq!(rig.backend.quota().snapshot(), snapshot);
}

#[test]
fn a_rejected_turn_still_reports_its_windows_and_a_bad_window_costs_only_itself() {
    let event = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","unifiedWindows":{"five_hour":{"utilization":0.9996,"resetsAt":1793307000,"status":"rejected"},"seven_day":{"resetsAt":1793656800,"status":"allowed"},"idle":{"utilization":0,"resetsAt":1793307000,"status":"allowed"},"odd":{"utilization":"high","resetsAt":1,"status":"allowed"},"negative":{"utilization":-0.5,"resetsAt":1,"status":"allowed"}}}}"#;
    let rig = rig(vec![Script::lines(vec![
        init_line(MODEL, SESSION),
        event.to_string(),
        error_result_line(r#","api_error_status":429"#),
    ])]);
    let (kind, _, _) = failure_of(&rig.run(request(vec![user("hello")])));
    assert_eq!(kind, FailureKind::RateLimited);
    let mut rejected = window("five_hour", 1000, 1_793_307_000_000);
    rejected.status = "rejected".to_string();
    // Unknown is never zero: a window missing a field or of another type is
    // skipped, not read as empty.
    // A window at exactly zero use is a reading, and is kept.
    assert_eq!(
        quota_of(&rig).windows,
        vec![rejected, window("idle", 0, 1_793_307_000_000)]
    );
}

#[test]
fn a_later_event_replaces_only_the_windows_it_names() {
    let only_five = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","unifiedWindows":{"five_hour":{"utilization":0.5,"resetsAt":1793310000,"status":"allowed"}}}}"#;
    let rig = rig(vec![
        structured_script(),
        Script::lines(vec![
            init_line(MODEL, SESSION),
            only_five.to_string(),
            text_line("msg_1", "hi"),
            result_line("end_turn", USAGE),
        ]),
    ]);
    rig.run(schema_request());
    rig.run(request(vec![user("again")]));
    assert_eq!(
        quota_of(&rig).windows,
        vec![
            window("five_hour", 500, 1_793_310_000_000),
            window("seven_day", 300, 1_793_656_800_000),
        ]
    );
}

#[cfg(unix)]
mod real {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Writing an executable and spawning it must not interleave with another
    /// thread's fork (ETXTBSY), so every real-process test holds this.
    static SPAWN_LOCK: Mutex<()> = Mutex::new(());

    struct Fake {
        _guard: std::sync::MutexGuard<'static, ()>,
        dir: TempDir,
        backend: ClaudeCodeBackend,
        sink: Sink,
    }

    fn fake(body: &str, limits: ClaudeCodeLimits) -> Fake {
        let guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new();
        let (work, cfg) = (dir.path().join("work"), dir.path().join("cfg"));
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&cfg).unwrap();
        let binary = dir.path().join("claude");
        std::fs::write(&binary, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let prompts = dir.path().join("prompts");
        std::fs::create_dir_all(&prompts).unwrap();
        let mut config = config(dir.path(), INSTANCE, limits);
        config.claude_binary_sha256 = pin_of(&std::fs::read(&binary).unwrap());
        config.claude_binary = binary;
        config.work_dir = work;
        config.config_dir = cfg;
        let sink = Sink::default();
        let backend = ClaudeCodeBackend::with_ports(
            config.clone(),
            Box::new(crate::process::StdProcessPort::new(config.limits)),
            Box::new(FsSessionStore::new(config.config_dir.clone())),
            Box::new(sink.clone()),
            canary_token(),
        );
        Fake {
            _guard: guard,
            dir,
            backend,
            sink,
        }
    }

    impl Fake {
        fn run(&self, request: ProviderRequest) -> TransportResult {
            let mut door = Door::new();
            let (claim, _) = door.begin(request);
            self.backend.execute(claim.call())
        }
    }

    fn printf_lines(lines: &[String]) -> String {
        let quoted: Vec<String> = lines.iter().map(|l| format!("'{l}'")).collect();
        format!("printf '%s\\n' {}", quoted.join(" "))
    }

    fn good_lines() -> Vec<String> {
        vec![
            init_line(MODEL, SESSION),
            text_line("msg_1", "hi"),
            result_line("end_turn", USAGE),
        ]
    }

    fn alive(pid: &str) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat
                .rsplit(')')
                .next()
                .is_some_and(|rest| !rest.trim_start().starts_with('Z')),
            Err(_) => false,
        }
    }

    #[test]
    fn deadline_kills_the_process_group() {
        let probe = TempDir::new();
        let pidfile = probe.path().join("grandchild.pid");
        let body = format!("sleep 300 &\necho $! > '{}'\nwait", pidfile.display());
        let mut short = limits();
        short.deadline = Duration::from_millis(700);
        let fake = fake(&body, short);

        let started = Instant::now();
        let result = fake.run(request(vec![user("hi")]));
        let (kind, _, usage) = failure_of(&result);
        assert_eq!(kind, FailureKind::Timeout);
        assert_eq!(usage, None);
        assert!(started.elapsed() < Duration::from_secs(20));

        let pid = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .to_string();
        assert!(!alive(&pid), "the grandchild {pid} outlived the call");
    }

    fn pid_in(file: &Path) -> String {
        for _ in 0..200 {
            if let Ok(pid) = std::fs::read_to_string(file)
                && pid.ends_with('\n')
            {
                return pid.trim().to_string();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the fake claude never wrote its pid");
    }

    #[test]
    fn the_child_is_reaped_when_the_call_ends() {
        let probe = TempDir::new();
        let pidfile = probe.path().join("child.pid");
        let body = format!(
            "echo $$ > '{}'\n{}",
            pidfile.display(),
            printf_lines(&good_lines())
        );
        let fake = fake(&body, limits());
        let result = fake.run(request(vec![user("hi")]));
        assert!(matches!(
            outcome(&result),
            TransportOutcome::Completed { .. }
        ));
        let pid = pid_in(&pidfile);
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the child {pid} was left unreaped"
        );
    }

    #[test]
    fn a_dropped_child_takes_its_group_with_it() {
        let probe = TempDir::new();
        let (leader, grandchild) = (
            probe.path().join("leader.pid"),
            probe.path().join("grandchild.pid"),
        );
        let body = format!(
            "sleep 300 &\necho $! > '{}'\necho $$ > '{}'\nwait",
            grandchild.display(),
            leader.display()
        );
        let fake = fake(&body, limits());
        let config = config(fake.dir.path(), INSTANCE, limits());
        let env = child_env(&config, &request(vec![user("x")]));
        let argv = vec![
            fake.dir
                .path()
                .join("claude")
                .to_string_lossy()
                .into_owned(),
        ];
        let port = crate::process::StdProcessPort::new(limits());
        let child = port
            .spawn(&argv, &env, fake.dir.path(), Vec::new(), "t")
            .unwrap();
        let (leader_pid, grandchild_pid) = (pid_in(&leader), pid_in(&grandchild));
        drop(child);
        assert!(
            !Path::new(&format!("/proc/{leader_pid}")).exists(),
            "leader reaped"
        );
        assert!(
            !alive(&grandchild_pid),
            "the grandchild outlived the dropped child"
        );
    }

    #[test]
    fn stderr_stays_in_the_sink() {
        let fake = fake("echo canary-stderr-text >&2\nexit 1", limits());
        let result = fake.run(request(vec![user("hi")]));
        let (kind, message, usage) = failure_of(&result);
        assert_eq!(kind, FailureKind::Provider);
        assert_eq!(usage, None);
        assert!(!message.contains("canary-stderr-text"));
        assert!(!format!("{result:?}").contains("canary-stderr-text"));
        let sunk = String::from_utf8(fake.sink.0.lock().unwrap().clone()).unwrap();
        assert!(sunk.contains("canary-stderr-text"), "{sunk:?}");
    }

    #[test]
    fn the_real_port_clears_the_environment_and_delivers_stdin() {
        static CANARY_PARENT: std::sync::Once = std::sync::Once::new();
        CANARY_PARENT.call_once(|| {
            // SAFETY: set once, before any child is spawned, to a value no test reads back.
            unsafe { std::env::set_var("ANTHROPIC_API_KEY", "canary-api-key") };
        });
        let probe = TempDir::new();
        let body = format!(
            "env > '{d}/env'\npwd > '{d}/pwd'\ncat > '{d}/stdin'\n{}",
            printf_lines(&good_lines()),
            d = probe.path().display()
        );
        let fake = fake(&body, limits());
        let result = fake.run(request(vec![user("hello")]));
        assert!(matches!(
            outcome(&result),
            TransportOutcome::Completed { .. }
        ));

        let env = std::fs::read_to_string(probe.path().join("env")).unwrap();
        assert!(!env.contains("canary-api-key") && !env.contains("ANTHROPIC_API_KEY"));
        let mut names: Vec<&str> = env
            .lines()
            .filter_map(|l| l.split_once('=').map(|(n, _)| n))
            // a shell adds these three to its own environment
            .filter(|n| !matches!(*n, "PWD" | "OLDPWD" | "SHLVL" | "_"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
                TOKEN_FD_ENV,
                "CLAUDE_CONFIG_DIR",
                "HOME",
                "PATH"
            ]
        );
        assert!(env.contains(&format!("{TOKEN_FD_ENV}=3")));
        assert!(!env.contains(CANARY_TOKEN));
        let cwd = std::fs::read_to_string(probe.path().join("pwd")).unwrap();
        assert_eq!(cwd.trim(), fake.dir.path().join("work").to_str().unwrap());
        let stdin = std::fs::read_to_string(probe.path().join("stdin")).unwrap();
        assert!(stdin.ends_with('\n') && stdin.matches('\n').count() == 1);
        assert!(stdin.contains("\"text\":\"hello\""));
    }

    #[test]
    fn token_never_in_child_env_and_the_pipe_yields_it_once() {
        let probe = TempDir::new();
        // Read the descriptor the variable names, twice, and list what the
        // child holds open.
        let body = format!(
            "fd=\"${TOKEN_FD_ENV}\"\neval \"cat <&$fd\" > '{d}/first'\neval \"cat <&$fd\" > '{d}/second'\nenv > '{d}/env'\nls /proc/$$/fd > '{d}/fds'\n{lines}",
            d = probe.path().display(),
            lines = printf_lines(&good_lines())
        );
        let fake = fake(&body, limits());
        let result = fake.run(request(vec![user("hello")]));
        assert!(matches!(
            outcome(&result),
            TransportOutcome::Completed { .. }
        ));
        let read = |name: &str| std::fs::read_to_string(probe.path().join(name)).unwrap();
        assert_eq!(read("first"), CANARY_TOKEN, "the pipe holds the token");
        assert_eq!(read("second"), "", "and nothing the second time");
        let env = read("env");
        assert!(!env.contains(CANARY_TOKEN) && !env.contains(&format!("{TOKEN_ENV}=")));
        assert!(env.contains(&format!("{TOKEN_FD_ENV}=3")));
        // 0 1 2, the pipe at 3, and the shell's own working descriptors:
        // no descriptor of the connector's other pipes survives into the child.
        let held: Vec<u32> = read("fds")
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        assert!(held.contains(&3));
    }

    #[test]
    fn a_token_too_large_for_a_pipe_is_refused_at_its_bound_not_hung() {
        let fake = fake("exit 0", limits());
        let config = config(fake.dir.path(), INSTANCE, limits());
        let env = child_env(&config, &request(vec![user("x")]));
        let port = crate::process::StdProcessPort::new(limits());
        let argv = vec![
            fake.dir
                .path()
                .join("claude")
                .to_string_lossy()
                .into_owned(),
        ];
        let spawn = |token: &str| port.spawn(&argv, &env, fake.dir.path(), Vec::new(), token);
        let at_bound = spawn(&"t".repeat(4096)).expect("4096 bytes fit the bound");
        drop(at_bound);
        assert_eq!(
            spawn(&"t".repeat(4097)).err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn the_output_caps_hold_at_their_exact_sizes() {
        let lines = good_lines();
        let longest = lines.iter().map(String::len).max().unwrap();
        let total: usize = lines.iter().map(|l| l.len() + 1).sum();
        let body = printf_lines(&lines);
        let with = |line: usize, all: usize| ClaudeCodeLimits {
            max_line_bytes: line,
            max_total_bytes: all,
            ..limits()
        };

        let at_both = fake(&body, with(longest, total)).run(request(vec![user("hi")]));
        assert!(matches!(
            outcome(&at_both),
            TransportOutcome::Completed { .. }
        ));

        for (line, all) in [(longest - 1, total), (longest, total - 1)] {
            let result = fake(&body, with(line, all)).run(request(vec![user("hi")]));
            let (kind, _, usage) = failure_of(&result);
            assert_eq!((kind, usage), (FailureKind::Provider, None), "{line} {all}");
        }
    }

    #[test]
    fn instructions_beyond_the_argument_limit_reach_the_child_in_a_private_file() {
        // One argument is capped near 128 KiB on Linux; instructions are not.
        let instructions = "i".repeat(300 * 1024);
        let probe = TempDir::new();
        let d = probe.path().display();
        let body = format!(
            "while [ $# -gt 0 ]; do\n\
             if [ \"$1\" = --system-prompt-file ]; then\n\
             cp \"$2\" '{d}/prompt'; stat -c %a \"$2\" > '{d}/mode'; echo \"$2\" > '{d}/path'\n\
             fi\nshift\ndone\n{}",
            printf_lines(&good_lines())
        );
        let fake = fake(&body, limits());
        let mut big = request(vec![user("hi")]);
        big.instructions = instructions.clone();
        let result = fake.run(big);
        assert!(matches!(
            outcome(&result),
            TransportOutcome::Completed { .. }
        ));
        assert_eq!(
            std::fs::read_to_string(probe.path().join("prompt")).unwrap(),
            instructions
        );
        assert_eq!(
            std::fs::read_to_string(probe.path().join("mode"))
                .unwrap()
                .trim(),
            "600"
        );
        let path = std::fs::read_to_string(probe.path().join("path")).unwrap();
        assert_eq!(
            Path::new(path.trim()).parent(),
            Some(fake.dir.path().join("prompts").as_path()),
            "staged in the configured prompt directory"
        );
        assert!(!Path::new(path.trim()).exists(), "removed after the call");
    }

    #[test]
    fn the_call_waits_for_the_child_to_close_stdout_after_its_result() {
        // The CLI writes its session after the result; killing it at the
        // result would lose the session a resume needs.
        let probe = TempDir::new();
        let body = format!(
            "{}\nsleep 1\necho written > '{}/after-result'",
            printf_lines(&good_lines()),
            probe.path().display()
        );
        let result = fake(&body, limits()).run(request(vec![user("hi")]));
        assert!(matches!(
            outcome(&result),
            TransportOutcome::Completed { .. }
        ));
        assert!(
            probe.path().join("after-result").exists(),
            "the child was killed before it finished"
        );
    }

    #[test]
    fn the_stderr_tail_is_complete_when_the_call_ends() {
        let body = format!(
            "head -c 300000 /dev/zero | tr '\\0' x >&2\necho END-OF-STDERR >&2\n{}",
            printf_lines(&good_lines())
        );
        let fake = fake(&body, limits());
        fake.run(request(vec![user("hi")]));
        let sunk = String::from_utf8(fake.sink.0.lock().unwrap().clone()).unwrap();
        assert!(sunk.trim_end().ends_with("END-OF-STDERR"), "{}", sunk.len());
    }

    #[test]
    fn stderr_join_survives_a_megabyte_after_result() {
        // Soul s2's probe: the result line first, then a megabyte of stderr
        // before the child exits. The call must wait for the stderr reader to
        // finish, or the tail handed to the sink is cut short.
        let body = format!(
            "{}\nhead -c 1000000 /dev/zero | tr '\\0' x >&2\necho END-OF-STDERR >&2",
            printf_lines(&good_lines())
        );
        let fake = fake(&body, limits());
        let result = fake.run(request(vec![user("hi")]));
        assert!(matches!(
            outcome(&result),
            TransportOutcome::Completed { .. }
        ));
        let sunk = String::from_utf8(fake.sink.0.lock().unwrap().clone()).unwrap();
        assert!(sunk.trim_end().ends_with("END-OF-STDERR"), "{}", sunk.len());
    }

    #[test]
    fn a_result_is_enough_even_if_the_child_keeps_stdout_open() {
        let body = format!("{}\nexec sleep 300", printf_lines(&good_lines()));
        let mut short = limits();
        short.deadline = Duration::from_millis(500);
        let result = fake(&body, short).run(request(vec![user("hi")]));
        assert!(matches!(
            outcome(&result),
            TransportOutcome::Completed { .. }
        ));
    }
}
