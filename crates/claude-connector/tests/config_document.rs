//! The claude-connector's configuration document and binary: what the
//! document accepts, what it refuses, and that no refusal or output echoes a
//! byte of a value that was typed, stored or read from a credential.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use claude_connector::{
    ClaudeConnectorConfig, ConfigError, LeaseCallerConfig, load_config, write_config,
};
use cultcache_rs::{
    CacheBackingStore, CultCache, CultCacheEnvelope, DatabaseEntry,
    SingleFileMessagePackBackingStore,
};
use model_connector::{CallerConfig, MIN_PAYLOAD_BYTES, ModelPrice, Rates};

const CANARY: &str = "canary-9f3b7c1d";
const OPUS: &str = "claude-opus-5-1";
const HAIKU: &str = "claude-haiku-5-5";

/// An edit that should make the valid document refuse.
type Change = Box<dyn Fn(&mut ClaudeConnectorConfig)>;

static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "claude-connector-config-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn price() -> ModelPrice {
    ModelPrice {
        rates: Rates {
            input: 3_000_000,
            cache_write_short: 3_750_000,
            cache_write_long: 3_750_000,
            cache_read: 300_000,
            output: 15_000_000,
        },
        long_context: None,
        overhead_tokens: 100,
    }
}

fn valid() -> ClaudeConnectorConfig {
    ClaudeConnectorConfig {
        listen: "127.0.0.1:7443".to_string(),
        replay_store: "/var/lib/claude-connector/replay.cc".into(),
        claude_binary: "/opt/claude/bin/claude".into(),
        claude_binary_sha256: [7; 32],
        work_dir: "/var/lib/claude-connector/work".into(),
        config_dir: "/var/lib/claude-connector/home".into(),
        prompt_dir: "/var/lib/claude-connector/prompts".into(),
        instance: "persona-a".to_string(),
        token_credential: "claude-token".to_string(),
        handle_secret_credential: "claude-handle-secret".to_string(),
        deadline_ms: 600_000,
        max_line_bytes: 4 << 20,
        max_total_bytes: 64 << 20,
        stderr_tail_bytes: 8192,
        max_frame_bytes: 2 << 20,
        max_connections: 8,
        socket_timeout_ms: 10_000,
        max_expiry_skew_ms: 300_000,
        callers: vec![CallerConfig {
            caller_runtime_id: "persona-a-caller".to_string(),
            connection_key_file: "/etc/claude-connector/caller.key".into(),
            connection_key_epoch: 1,
            allowed_models: vec![HAIKU.to_string(), OPUS.to_string()],
            max_concurrent_requests: 4,
            max_payload_bytes: 1 << 20,
            max_output_tokens: 32_768,
            spend_ceiling_micro_usd: 50_000_000,
            spend_window_ms: 3_600_000,
        }],
        prices: BTreeMap::from([(HAIKU.to_string(), price()), (OPUS.to_string(), price())]),
        lease_socket: Some("/run/claude-connector/lease.sock".into()),
        lease_callers: vec![LeaseCallerConfig {
            unix_user: "mind-eureka-self".to_string(),
            caller_id: "persona-a-caller".to_string(),
            unit_instance: "eureka".to_string(),
            reservation_micro_usd: 5_000_000,
        }],
        lease_max_ms: 3_600_000,
    }
}

fn refused(config: &ClaudeConnectorConfig) -> &'static str {
    match config.validate() {
        Err(ConfigError::Invalid(field)) => field,
        other => panic!("expected a refusal naming a field, got {other:?}"),
    }
}

#[test]
fn config_round_trips_through_cultcache() {
    let scratch = Scratch::new();
    let path = scratch.path("connector.cc");
    let config = valid();
    write_config(&path, &config).unwrap();
    assert_eq!(load_config(&path).unwrap(), config);
}

#[test]
fn a_second_record_or_the_wrong_type_is_refused() {
    let scratch = Scratch::new();
    let path = scratch.path("two.cc");
    let config = valid();
    write_config(&path, &config).unwrap();
    let mut cache = CultCache::new();
    cache
        .register_entry_type::<ClaudeConnectorConfig>()
        .unwrap();
    cache
        .add_generic_backing_store(SingleFileMessagePackBackingStore::new(&path))
        .unwrap();
    cache.pull_all_backing_stores().unwrap();
    cache.put("extra", &config).unwrap();
    assert!(matches!(load_config(&path), Err(ConfigError::Store)));

    #[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
    #[cultcache(type = "gamecult.other.document.v1")]
    struct Other {
        #[cultcache(key = 0)]
        value: u32,
    }
    let other = scratch.path("other.cc");
    let mut cache = CultCache::new();
    cache.register_entry_type::<Other>().unwrap();
    cache
        .add_generic_backing_store(SingleFileMessagePackBackingStore::new(&other))
        .unwrap();
    cache.pull_all_backing_stores().unwrap();
    cache.put("runtime", &Other { value: 1 }).unwrap();
    assert!(matches!(load_config(&other), Err(ConfigError::Store)));

    assert!(matches!(
        load_config(&scratch.path("absent.cc")),
        Err(ConfigError::Store)
    ));
}

fn store_raw(path: &Path, key: &str, ty: &str, schema: Option<&str>, payload: Vec<u8>) {
    let mut store = SingleFileMessagePackBackingStore::new(path);
    store
        .push(&CultCacheEnvelope {
            key: key.to_string(),
            r#type: ty.to_string(),
            payload,
            stored_at: "2026-10-29T00:00:00Z".to_string(),
            schema_id: schema.map(str::to_string),
        })
        .unwrap();
}

#[test]
fn the_envelope_must_be_exactly_the_documents_key_type_schema_and_encoding() {
    let scratch = Scratch::new();
    let canonical = rmp_serde::to_vec(&valid()).unwrap();
    let ty = ClaudeConnectorConfig::TYPE;
    let mut trailing = canonical.clone();
    trailing.push(0xc0);

    let cases = vec![
        ("wrong key", "other", ty, Some(ty), canonical.clone()),
        (
            "wrong type",
            "runtime",
            "gamecult.other.v1",
            Some(ty),
            canonical.clone(),
        ),
        (
            "wrong schema",
            "runtime",
            ty,
            Some("gamecult.other.v1"),
            canonical.clone(),
        ),
        ("not canonical", "runtime", ty, Some(ty), trailing),
    ];
    for (name, key, ty, schema, payload) in cases {
        let path = scratch.path(&format!("{}.cc", name.replace(' ', "-")));
        store_raw(&path, key, ty, schema, payload);
        assert!(
            matches!(load_config(&path), Err(ConfigError::Store)),
            "{name}"
        );
    }

    // The same bytes with every part right load.
    let path = scratch.path("right.cc");
    store_raw(&path, "runtime", ty, Some(ty), canonical);
    assert_eq!(load_config(&path).unwrap(), valid());
}

#[test]
fn bounds_sit_exactly_where_the_connector_needs_them() {
    let mut config = valid();
    config.max_total_bytes = config.max_line_bytes;
    config.validate().unwrap();
    config.callers[0].max_payload_bytes = MIN_PAYLOAD_BYTES;
    config.validate().unwrap();
    config.callers[0].max_payload_bytes = MIN_PAYLOAD_BYTES - 1;
    assert_eq!(refused(&config), "caller bounds");

    for set in [
        (|c: &mut ClaudeConnectorConfig| c.max_connections = 0) as fn(&mut ClaudeConnectorConfig),
        |c| c.socket_timeout_ms = 0,
        |c| c.max_expiry_skew_ms = 0,
        |c| c.max_frame_bytes = 0,
    ] {
        let mut config = valid();
        set(&mut config);
        assert_eq!(refused(&config), "serve limits");
    }
    let mut config = valid();
    config.prices.insert("claude-".to_string(), price());
    assert_eq!(refused(&config), "prices");
}

#[test]
fn a_write_refuses_an_invalid_document_and_leaves_no_file() {
    let scratch = Scratch::new();
    let path = scratch.path("bad.cc");
    let mut config = valid();
    config.callers[0].allowed_models = vec!["opus".to_string()];
    assert!(write_config(&path, &config).is_err());
    assert!(!path.exists());
}

#[test]
fn config_refuses_aliases_unpriced_models_and_second_callers() {
    let valid_config = valid();
    assert_eq!(valid_config.validate().unwrap().port(), 7443);

    let cases: Vec<(&str, Change)> = vec![
        (
            "alias allowed",
            Box::new(|c| {
                c.callers[0].allowed_models = vec!["opus".to_string()];
            }),
        ),
        (
            "alias price key",
            Box::new(|c| {
                c.prices.insert("sonnet".to_string(), price());
            }),
        ),
        (
            "bare prefix",
            Box::new(|c| {
                c.callers[0].allowed_models = vec!["claude-".to_string()];
            }),
        ),
        (
            "family only",
            Box::new(|c| {
                c.callers[0].allowed_models = vec!["claude-haiku".to_string()];
                c.prices.insert("claude-haiku".to_string(), price());
            }),
        ),
        (
            "latest alias",
            Box::new(|c| {
                c.callers[0].allowed_models = vec!["claude-sonnet-latest".to_string()];
                c.prices.insert("claude-sonnet-latest".to_string(), price());
            }),
        ),
        (
            "uppercase family",
            Box::new(|c| {
                c.callers[0].allowed_models = vec!["claude-Opus-5-1".to_string()];
                c.prices.insert("claude-Opus-5-1".to_string(), price());
            }),
        ),
        (
            "short date",
            Box::new(|c| {
                c.callers[0].allowed_models = vec!["claude-opus-5-1-2026".to_string()];
                c.prices.insert("claude-opus-5-1-2026".to_string(), price());
            }),
        ),
        (
            "trailing part",
            Box::new(|c| {
                c.callers[0].allowed_models = vec!["claude-opus-5-1-20260101-x".to_string()];
                c.prices
                    .insert("claude-opus-5-1-20260101-x".to_string(), price());
            }),
        ),
        (
            "unpriced allowed",
            Box::new(|c| {
                c.prices.remove(OPUS);
            }),
        ),
        (
            "duplicate allowed",
            Box::new(|c| {
                c.callers[0].allowed_models = vec![HAIKU.to_string(), HAIKU.to_string()];
            }),
        ),
        (
            "no allowed",
            Box::new(|c| c.callers[0].allowed_models.clear()),
        ),
        (
            "duplicate caller id",
            Box::new(|c| {
                let again = c.callers[0].clone();
                c.callers.push(again);
            }),
        ),
        ("no caller", Box::new(|c| c.callers.clear())),
    ];
    let fields = [
        "allowed_models",
        "prices",
        "allowed_models",
        "allowed_models",
        "allowed_models",
        "allowed_models",
        "allowed_models",
        "allowed_models",
        "allowed_models",
        "allowed_models",
        "allowed_models",
        "callers",
        "callers",
    ];
    for ((name, change), field) in cases.iter().zip(fields) {
        let mut config = valid();
        change(&mut config);
        assert_eq!(refused(&config), field, "{name}");
    }
}

#[test]
fn a_priced_id_of_any_loose_form_is_allowed_and_the_price_table_decides() {
    // Real ids come with a minor, without one, and with a date either way.
    for id in [
        "claude-opus-5-1-20260101",
        "claude-opus-5",
        "claude-opus-5-20260101",
        "claude-sonnet-4-5",
    ] {
        let mut config = valid();
        config.callers[0].allowed_models = vec![id.to_string()];
        config.prices.insert(id.to_string(), price());
        config.validate().unwrap_or_else(|e| panic!("{id}: {e}"));

        // The same id with no price is not on the known list.
        config.prices.remove(id);
        assert_eq!(refused(&config), "allowed_models", "{id}");
    }
}

#[test]
fn a_price_with_a_zero_billed_component_is_refused() {
    type Zero = fn(&mut Rates);
    let zeroed: Vec<(&str, Zero)> = vec![
        ("input", |r| r.input = 0),
        ("cache_write_short", |r| r.cache_write_short = 0),
        ("cache_write_long", |r| r.cache_write_long = 0),
        ("cache_read", |r| r.cache_read = 0),
        ("output", |r| r.output = 0),
    ];
    for (name, zero) in &zeroed {
        let mut config = valid();
        zero(&mut config.prices.get_mut(HAIKU).unwrap().rates);
        assert_eq!(refused(&config), "prices", "{name}");

        let mut config = valid();
        let mut long = price().rates;
        zero(&mut long);
        config.prices.get_mut(HAIKU).unwrap().long_context = Some(model_connector::LongContext {
            above_prompt_tokens: 200_000,
            rates: long,
        });
        assert_eq!(refused(&config), "prices", "long context {name}");
    }
    // A zero overhead is not a rate.
    let mut config = valid();
    config.prices.get_mut(HAIKU).unwrap().overhead_tokens = 0;
    config.validate().unwrap();
}

#[test]
fn config_refuses_exposed_listeners_relative_paths_and_empty_bounds() {
    let cases: Vec<(&str, &str, Change)> = vec![
        (
            "wildcard listen",
            "listen",
            Box::new(|c| c.listen = "0.0.0.0:7443".into()),
        ),
        (
            "lan listen",
            "listen",
            Box::new(|c| c.listen = "192.168.1.9:7443".into()),
        ),
        (
            "hostname listen",
            "listen",
            Box::new(|c| c.listen = "localhost:7443".into()),
        ),
        (
            "replay",
            "replay_store",
            Box::new(|c| c.replay_store = "replay.cc".into()),
        ),
        (
            "binary",
            "claude_binary",
            Box::new(|c| c.claude_binary = "claude".into()),
        ),
        ("work", "work_dir", Box::new(|c| c.work_dir = "work".into())),
        (
            "config",
            "config_dir",
            Box::new(|c| c.config_dir = "cfg".into()),
        ),
        (
            "prompts",
            "prompt_dir",
            Box::new(|c| c.prompt_dir = "prompts".into()),
        ),
        (
            "key file",
            "connection_key_file",
            Box::new(|c| {
                c.callers[0].connection_key_file = "caller.key".into();
            }),
        ),
        (
            "zero pin",
            "claude_binary_sha256",
            Box::new(|c| c.claude_binary_sha256 = [0; 32]),
        ),
        (
            "blank instance",
            "instance",
            Box::new(|c| c.instance = " ".into()),
        ),
        (
            "credential path",
            "token_credential",
            Box::new(|c| c.token_credential = "a/b".into()),
        ),
        (
            "credential parent",
            "token_credential",
            Box::new(|c| c.token_credential = "..".into()),
        ),
        (
            "credential empty",
            "token_credential",
            Box::new(|c| c.token_credential = String::new()),
        ),
        (
            "zero deadline",
            "child limits",
            Box::new(|c| c.deadline_ms = 0),
        ),
        (
            "total below line",
            "child limits",
            Box::new(|c| c.max_total_bytes = c.max_line_bytes - 1),
        ),
        (
            "zero frame",
            "serve limits",
            Box::new(|c| c.max_frame_bytes = 0),
        ),
        (
            "zero epoch",
            "connection_key_epoch",
            Box::new(|c| c.callers[0].connection_key_epoch = 0),
        ),
        (
            "tiny payload",
            "caller bounds",
            Box::new(|c| c.callers[0].max_payload_bytes = 16),
        ),
        (
            "no ceiling",
            "caller bounds",
            Box::new(|c| c.callers[0].spend_ceiling_micro_usd = 0),
        ),
    ];
    for (name, field, change) in cases {
        let mut config = valid();
        change(&mut config);
        assert_eq!(refused(&config), field, "{name}");
    }
}

#[test]
fn no_refusal_echoes_a_value() {
    let canary_path: PathBuf = format!("{CANARY}/relative").into();
    let canaried: Vec<Change> = vec![
        Box::new(|c| c.listen = format!("{CANARY}:1")),
        Box::new(|c| c.instance = format!(" {CANARY} ")),
        Box::new(|c| c.token_credential = format!("{CANARY}/x")),
        Box::new(|c| c.callers[0].allowed_models = vec![format!("{CANARY}-model")]),
        Box::new(|c| {
            c.prices.insert(format!("{CANARY}-alias"), price());
        }),
        Box::new(|c| c.callers[0].caller_runtime_id = format!(" {CANARY}")),
        Box::new({
            let path = canary_path.clone();
            move |c| c.replay_store = path.clone()
        }),
        Box::new({
            let path = canary_path.clone();
            move |c| c.callers[0].connection_key_file = path.clone()
        }),
        Box::new(|c| {
            let mut second = c.callers[0].clone();
            second.caller_runtime_id = format!(" {CANARY}");
            c.callers.push(second);
        }),
    ];
    for change in canaried {
        let mut config = valid();
        change(&mut config);
        let error = config.validate().unwrap_err();
        for shown in [error.to_string(), format!("{error:?}")] {
            assert!(!shown.contains(CANARY), "{shown}");
        }
        let scratch = Scratch::new();
        let write = write_config(&scratch.path("x.cc"), &config).unwrap_err();
        assert!(!format!("{write} {write:?}").contains(CANARY));
    }
}

// ---- the binary ----

/// How long any connector verb may take in these tests. `check` and `init`
/// return at once and `serve` is meant to refuse; a `serve` that starts
/// instead would run forever, so it fails a named test here, not the suite.
const VERB_DEADLINE: Duration = Duration::from_secs(20);

fn run(args: &[&str], envs: &[(&str, &Path)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_claude-connector"));
    command.args(args).env_clear();
    for (name, value) in envs {
        command.env(name, value);
    }
    run_within(command, VERB_DEADLINE).unwrap_or_else(|| {
        panic!(
            "`{}` was still running after {VERB_DEADLINE:?}: it started",
            args.join(" ")
        )
    })
}

/// The command's output, or `None` when it outlived `deadline` and was killed.
fn run_within(mut command: Command, deadline: Duration) -> Option<Output> {
    use std::process::Stdio;
    use std::time::Instant;

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(child.wait_with_output().unwrap())
}

#[cfg(unix)]
#[test]
fn a_process_past_its_deadline_is_killed_and_reported_as_none() {
    let mut forever = Command::new("sleep");
    forever.arg("60");
    let started = std::time::Instant::now();
    assert!(run_within(forever, Duration::from_millis(200)).is_none());
    assert!(started.elapsed() < Duration::from_secs(10));
    let mut quick = Command::new("true");
    quick.env_clear();
    assert!(
        run_within(quick, Duration::from_secs(10))
            .unwrap()
            .status
            .success()
    );
}

fn shown(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn init_flags<'a>(scratch: &'a Scratch, extra: &[&'a str]) -> Vec<String> {
    let path = |name: &str| scratch.path(name).to_string_lossy().into_owned();
    let mut flags: Vec<String> = [
        "--listen",
        "127.0.0.1:0",
        "--replay-store",
        &path("replay.cc"),
        "--claude-binary",
        &path("claude"),
        "--claude-sha256",
        &"ab".repeat(32),
        "--work-dir",
        &path("work"),
        "--config-dir",
        &path("home"),
        "--prompt-dir",
        &path("prompts"),
        "--instance",
        "persona-a",
        "--token-credential",
        "claude-token",
        "--handle-secret-credential",
        "claude-handle-secret",
        "--handle-secret-file",
        &path("handle.secret"),
        "--caller-id",
        "persona-a-caller",
        "--connection-key-file",
        &path("caller.key"),
        "--connection-key-epoch",
        "1",
        "--spend-ceiling-micro-usd",
        "50000000",
        "--spend-window-ms",
        "3600000",
        "--allowed-model",
        HAIKU,
        "--price",
        &format!("{HAIKU}:1000000:5000000:1250000:100000:100"),
    ]
    .map(String::from)
    .to_vec();
    flags.extend(extra.iter().map(|flag| flag.to_string()));
    flags
}

fn init(scratch: &Scratch, flags: &[String]) -> Output {
    let config = scratch.path("connector.cc");
    let mut args = vec!["config", "init", config.to_str().unwrap()];
    args.extend(flags.iter().map(String::as_str));
    run(&args, &[])
}

#[test]
fn config_init_writes_the_flags_into_the_document() {
    let scratch = Scratch::new();
    let made = init(&scratch, &init_flags(&scratch, &[]));
    assert!(made.status.success(), "{}", shown(&made));
    let config = load_config(&scratch.path("connector.cc")).unwrap();
    assert_eq!(config.callers[0].allowed_models, [HAIKU]);
    assert_eq!(config.prices[HAIKU].rates.output, 5_000_000);
    assert_eq!(config.prices[HAIKU].rates.cache_write_long, 1_250_000);
    assert_eq!(config.prices[HAIKU].overhead_tokens, 100);
    assert_eq!(config.claude_binary_sha256, [0xab; 32]);
}

/// A scratch directory in which `serve` would start: every directory, the
/// pinned binary, the connection key and the credential exist. Returns the
/// `config init` flags and the credential directory.
#[cfg(unix)]
fn prepare(scratch: &Scratch) -> (Vec<String>, PathBuf) {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    for name in ["work", "home", "prompts", "credentials"] {
        std::fs::create_dir_all(scratch.path(name)).unwrap();
    }
    std::fs::set_permissions(
        scratch.path("prompts"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(scratch.path("credentials/claude-token"), CANARY).unwrap();
    std::fs::write(
        scratch.path("credentials/claude-handle-secret"),
        "s".repeat(64),
    )
    .unwrap();
    std::fs::write(scratch.path("caller.key"), "caller-secret").unwrap();
    std::fs::write(scratch.path("claude"), b"pinned claude").unwrap();
    let sha: String = Sha256::digest(b"pinned claude")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut flags = init_flags(scratch, &[]);
    let at = flags
        .iter()
        .position(|flag| flag == "--claude-sha256")
        .unwrap();
    flags[at + 1] = sha;
    (flags, scratch.path("credentials"))
}

#[cfg(unix)]
fn check_and_serve(config: &Path, credentials: Option<&Path>) -> (Output, Output) {
    let envs: Vec<(&str, &Path)> = credentials
        .map(|dir| ("CREDENTIALS_DIRECTORY", dir))
        .into_iter()
        .collect();
    let path = config.to_str().unwrap();
    (
        run(&["config", "check", path], &envs),
        run(&["serve", "--config", path], &envs),
    )
}

#[cfg(unix)]
#[test]
fn check_passes_a_document_serve_can_start_and_reports_counts_only() {
    let scratch = Scratch::new();
    let (flags, credentials) = prepare(&scratch);
    let made = init(&scratch, &flags);
    assert!(made.status.success(), "{}", shown(&made));
    let checked = run(
        &[
            "config",
            "check",
            scratch.path("connector.cc").to_str().unwrap(),
        ],
        &[("CREDENTIALS_DIRECTORY", &credentials)],
    );
    assert!(checked.status.success(), "{}", shown(&checked));
    let text = shown(&checked);
    assert!(text.contains("callers: 1") && text.contains("lease_callers: 0"));
    assert!(text.contains("prices: 1"));
    for secret in ["persona-a", HAIKU, CANARY, "caller-secret"] {
        assert!(!text.contains(secret), "{text}");
    }
}

#[cfg(unix)]
#[test]
fn check_refuses_exactly_what_serve_refuses_and_names_the_field() {
    use std::os::unix::fs::PermissionsExt;

    type Break = fn(&Scratch, &Path);
    let cases: Vec<(&str, &str, Break)> = vec![
        ("open prompt dir", "prompt directory", |s, _| {
            std::fs::set_permissions(s.path("prompts"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }),
        ("no key file", "connection_key_file", |s, _| {
            std::fs::remove_file(s.path("caller.key")).unwrap();
        }),
        ("binary off its pin", "claude_binary_sha256", |s, _| {
            std::fs::write(s.path("claude"), b"other bytes").unwrap();
        }),
        ("no credential", "token_credential", |_, credentials| {
            std::fs::remove_file(credentials.join("claude-token")).unwrap();
        }),
        ("no work dir", "work_dir", |s, _| {
            std::fs::remove_dir(s.path("work")).unwrap();
        }),
        ("no config dir", "config_dir", |s, _| {
            std::fs::remove_dir(s.path("home")).unwrap();
        }),
        ("frame too small", "max_frame_bytes", |s, _| {
            let path = s.path("connector.cc");
            let mut config = load_config(&path).unwrap();
            config.max_frame_bytes = 4099;
            write_config(&path, &config).unwrap();
        }),
        ("two callers on one key", "callers", |s, _| {
            std::fs::write(s.path("twin.key"), "caller-secret").unwrap();
            let config = s.path("connector.cc");
            let twin = s.path("twin.key");
            let added = run(
                &[
                    "config",
                    "add-caller",
                    config.to_str().unwrap(),
                    "--caller-id",
                    "twin",
                    "--connection-key-file",
                    twin.to_str().unwrap(),
                    "--connection-key-epoch",
                    "1",
                    "--allowed-model",
                    HAIKU,
                    "--spend-ceiling-micro-usd",
                    "1000",
                    "--spend-window-ms",
                    "60000",
                ],
                &[],
            );
            assert!(added.status.success(), "{}", shown(&added));
        }),
        ("too few connections", "connection capacity", |s, _| {
            let path = s.path("connector.cc");
            let mut config = load_config(&path).unwrap();
            config.max_connections = 1;
            write_config(&path, &config).unwrap();
        }),
    ];
    for (name, field, break_it) in cases {
        let scratch = Scratch::new();
        let (flags, credentials) = prepare(&scratch);
        let made = init(&scratch, &flags);
        assert!(made.status.success(), "{name}: {}", shown(&made));
        break_it(&scratch, &credentials);
        let (checked, served) = check_and_serve(&scratch.path("connector.cc"), Some(&credentials));
        assert!(!checked.status.success(), "{name} check passed");
        assert!(!served.status.success(), "{name} serve started");
        assert!(
            shown(&checked).contains(field),
            "{name}: {}",
            shown(&checked)
        );
        assert_eq!(shown(&checked), shown(&served), "{name}");
        for secret in [CANARY, "caller-secret", "other bytes"] {
            assert!(!shown(&checked).contains(secret), "{name}");
        }
    }

    // No credential directory at all is the same refusal.
    let scratch = Scratch::new();
    let (flags, _) = prepare(&scratch);
    assert!(init(&scratch, &flags).status.success());
    let (checked, served) = check_and_serve(&scratch.path("connector.cc"), None);
    assert!(!checked.status.success() && !served.status.success());
    assert!(shown(&checked).contains("credentials_directory"));
    assert!(!shown(&checked).contains("token_credential"));
    assert_eq!(shown(&checked), shown(&served));

    // A credential directory without the credential is the other fault, and
    // the token is checked last: a broken pin is named first.
    let scratch = Scratch::new();
    let (flags, credentials) = prepare(&scratch);
    assert!(init(&scratch, &flags).status.success());
    std::fs::remove_file(credentials.join("claude-token")).unwrap();
    std::fs::write(scratch.path("claude"), b"other bytes").unwrap();
    let (checked, _) = check_and_serve(&scratch.path("connector.cc"), Some(&credentials));
    assert!(
        shown(&checked).contains("claude_binary_sha256"),
        "{}",
        shown(&checked)
    );
    std::fs::write(scratch.path("claude"), b"pinned claude").unwrap();
    let (checked, _) = check_and_serve(&scratch.path("connector.cc"), Some(&credentials));
    assert!(
        shown(&checked).contains("token_credential"),
        "{}",
        shown(&checked)
    );
    assert!(!shown(&checked).contains("credentials_directory"));
}

#[test]
fn usage_says_check_runs_in_the_units_environment() {
    let output = run(&["nonsense"], &[]);
    assert!(!output.status.success());
    assert!(
        shown(&output).contains("unit's environment"),
        "{}",
        shown(&output)
    );
}

#[cfg(unix)]
#[test]
fn serve_names_a_corrupt_replay_store_without_its_path() {
    let scratch = Scratch::new();
    let (mut flags, credentials) = prepare(&scratch);
    let store = scratch.path(&format!("{CANARY}-store/replay.cc"));
    std::fs::create_dir_all(store.parent().unwrap()).unwrap();
    std::fs::write(&store, b"not a cultcache store").unwrap();
    let at = flags
        .iter()
        .position(|flag| flag == "--replay-store")
        .unwrap();
    flags[at + 1] = store.to_string_lossy().into_owned();
    assert!(init(&scratch, &flags).status.success());
    let (_, served) = check_and_serve(&scratch.path("connector.cc"), Some(&credentials));
    assert!(!served.status.success());
    let text = shown(&served);
    assert!(text.contains("replay_store"), "{text}");
    assert!(
        !text.contains(CANARY) && !text.contains("replay.cc"),
        "{text}"
    );
}

#[test]
fn the_binary_refuses_without_echoing_what_it_was_given() {
    let spaced = format!(" {CANARY}");
    // Each pair replaces the value of an existing flag; the others are appended.
    let replaced: Vec<(&str, &str)> = vec![
        ("--listen", CANARY),
        ("--claude-sha256", CANARY),
        ("--claude-sha256", "abcd"),
        ("--price", CANARY),
        ("--instance", &spaced),
        ("--connection-key-epoch", CANARY),
        ("--allowed-model", CANARY),
    ];
    let appended: Vec<Vec<&str>> = vec![
        vec![CANARY, CANARY],
        vec!["--listen"],
        vec!["--listen", "127.0.0.1:1"],
    ];
    let mut attempts: Vec<Vec<String>> = Vec::new();
    for (name, value) in replaced {
        let scratch = Scratch::new();
        let mut flags = init_flags(&scratch, &[]);
        let at = flags.iter().position(|flag| flag == name).unwrap();
        flags[at + 1] = value.to_string();
        attempts.push(flags);
    }
    for extra in appended {
        let scratch = Scratch::new();
        attempts.push(init_flags(&scratch, &extra));
    }
    for flags in attempts {
        let scratch = Scratch::new();
        let made = init(&scratch, &flags);
        assert!(!made.status.success(), "{flags:?}");
        assert!(!shown(&made).contains(CANARY), "{}", shown(&made));
        assert!(!scratch.path("connector.cc").exists());
    }

    // A missing flag is refused by name.
    let scratch = Scratch::new();
    let mut flags = init_flags(&scratch, &[]);
    let at = flags.iter().position(|f| f == "--instance").unwrap();
    flags.drain(at..at + 2);
    let made = init(&scratch, &flags);
    assert!(!made.status.success());
    assert!(shown(&made).contains("--instance"));
}

#[cfg(unix)]
#[test]
fn serve_refuses_an_unsafe_prompt_dir_and_prints_no_credential() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let scratch = Scratch::new();
    let credentials = scratch.path("credentials");
    std::fs::create_dir_all(&credentials).unwrap();
    std::fs::write(credentials.join("claude-token"), CANARY).unwrap();
    std::fs::write(scratch.path("caller.key"), "caller-secret").unwrap();
    let made = init(&scratch, &init_flags(&scratch, &[]));
    assert!(made.status.success(), "{}", shown(&made));
    let config = scratch.path("connector.cc");
    let serve = |config: &Path| {
        run(
            &["serve", "--config", config.to_str().unwrap()],
            &[("CREDENTIALS_DIRECTORY", &credentials)],
        )
    };

    // No prompt directory, then one others can enter, then a link to a good one.
    let prompts = scratch.path("prompts");
    let refused = serve(&config);
    assert!(!refused.status.success());
    assert!(
        shown(&refused).contains("prompt directory"),
        "{}",
        shown(&refused)
    );
    std::fs::create_dir_all(&prompts).unwrap();
    std::fs::set_permissions(&prompts, std::fs::Permissions::from_mode(0o755)).unwrap();
    let open = serve(&config);
    assert!(
        shown(&open).contains("prompt directory"),
        "{}",
        shown(&open)
    );
    assert!(claude_connector::check_prompt_dir(&prompts).is_err());
    std::fs::set_permissions(&prompts, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(claude_connector::check_prompt_dir(&prompts).is_ok());
    let linked = scratch.path("linked");
    symlink(&prompts, &linked).unwrap();
    assert!(claude_connector::check_prompt_dir(&linked).is_err());

    // A safe directory but no claude binary: the backend is not ready, and
    // nothing the credential holds is printed.
    let not_ready = serve(&config);
    assert!(!not_ready.status.success());
    for output in [&refused, &open, &not_ready] {
        let text = shown(output);
        assert!(
            !text.contains(CANARY) && !text.contains("caller-secret"),
            "{text}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_private_regular_file_is_not_a_prompt_dir() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let file = scratch.path("file");
    std::fs::write(&file, "x").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(claude_connector::check_prompt_dir(&file).is_err());
    assert!(claude_connector::check_prompt_dir(&scratch.path("absent")).is_err());
}

#[test]
fn leases_are_configured_together_or_not_at_all() {
    let cases: Vec<(&str, Change)> = vec![
        (
            "lease_socket",
            Box::new(|c| c.lease_socket = Some("lease.sock".into())),
        ),
        ("lease_callers", Box::new(|c| c.lease_callers.clear())),
        ("lease_callers", Box::new(|c| c.lease_socket = None)),
        (
            "lease_callers",
            Box::new(|c| c.lease_callers[0].caller_id = "another-caller".to_string()),
        ),
        (
            "lease_callers",
            Box::new(|c| c.lease_callers[0].unix_user = " ".to_string()),
        ),
        (
            "lease_callers",
            Box::new(|c| {
                let again = c.lease_callers[0].clone();
                c.lease_callers.push(again);
            }),
        ),
        ("lease_max_ms", Box::new(|c| c.lease_max_ms = 0)),
        (
            "lease_callers",
            Box::new(|c| c.lease_callers[0].reservation_micro_usd = 0),
        ),
        (
            "lease_callers",
            Box::new(|c| c.lease_callers[0].reservation_micro_usd = 50_000_001),
        ),
        (
            "lease_callers",
            Box::new(|c| c.lease_callers[0].unit_instance = String::new()),
        ),
        (
            "lease_callers",
            Box::new(|c| c.lease_callers[0].unit_instance = "a/b".to_string()),
        ),
    ];
    for (field, change) in cases {
        let mut config = valid();
        change(&mut config);
        assert_eq!(refused(&config), field);
    }
    // The whole ceiling is a reservation the caller can hold.
    let mut whole = valid();
    whole.lease_callers[0].reservation_micro_usd = 50_000_000;
    whole.validate().unwrap();
    let mut none = valid();
    none.lease_socket = None;
    none.lease_callers.clear();
    none.validate().unwrap();
}

#[test]
fn config_init_binds_each_lease_user_to_the_configured_caller() {
    let scratch = Scratch::new();
    let made = init(
        &scratch,
        &init_flags(
            &scratch,
            &[
                "--lease-socket",
                "/run/claude-connector/lease.sock",
                "--lease-user",
                "mind-eureka-self",
                "--lease-max-ms",
                "120000",
                "--lease-unit-instance",
                "eureka",
                "--lease-reservation-micro-usd",
                "5000000",
            ],
        ),
    );
    assert!(made.status.success(), "{}", shown(&made));
    let config = load_config(&scratch.path("connector.cc")).unwrap();
    assert_eq!(
        config.lease_callers,
        [LeaseCallerConfig {
            unix_user: "mind-eureka-self".to_string(),
            caller_id: "persona-a-caller".to_string(),
            unit_instance: "eureka".to_string(),
            reservation_micro_usd: 5_000_000,
        }]
    );
    assert_eq!(config.lease_max_ms, 120_000);
}

#[cfg(target_os = "linux")]
#[test]
fn config_check_refuses_a_lease_account_the_system_does_not_have() {
    let scratch = Scratch::new();
    let (mut flags, credentials) = prepare(&scratch);
    let socket = scratch.path("lease.sock");
    flags.extend(
        [
            "--lease-socket",
            socket.to_str().unwrap(),
            "--lease-user",
            "no-such-account-4f1c",
            "--lease-unit-instance",
            "eureka",
            "--lease-reservation-micro-usd",
            "5000000",
        ]
        .map(String::from),
    );
    let made = init(&scratch, &flags);
    assert!(made.status.success(), "{}", shown(&made));
    let config = scratch.path("connector.cc");
    let checked = run(
        &["config", "check", config.to_str().unwrap()],
        &[("CREDENTIALS_DIRECTORY", &credentials)],
    );
    assert!(!checked.status.success());
    assert!(
        shown(&checked).contains("lease_callers"),
        "{}",
        shown(&checked)
    );
    assert!(!shown(&checked).contains("no-such-account"));
}

#[cfg(target_os = "linux")]
#[test]
fn serve_binds_the_lease_socket_and_answers_a_stranger_with_a_refusal() {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    use std::time::Instant;

    use claude_connector::{
        LeaseMessage, LeaseRefusalKind, LeaseRefused, LeaseRequest, decode_frame, encode_frame,
    };

    let scratch = Scratch::new();
    let (mut flags, credentials) = prepare(&scratch);
    let socket = scratch.path("lease.sock");
    // The test runs as someone other than `nobody`, so it is a stranger.
    flags.extend(
        [
            "--lease-socket",
            socket.to_str().unwrap(),
            "--lease-user",
            "nobody",
            "--lease-unit-instance",
            "eureka",
            "--lease-reservation-micro-usd",
            "5000000",
        ]
        .map(String::from),
    );
    let made = init(&scratch, &flags);
    assert!(made.status.success(), "{}", shown(&made));
    let config = scratch.path("connector.cc");
    let mut server = Command::new(env!("CARGO_BIN_EXE_claude-connector"))
        .args(["serve", "--config", config.to_str().unwrap()])
        .env_clear()
        .env("CREDENTIALS_DIRECTORY", &credentials)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !socket.exists() && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
    }
    let outcome = std::panic::catch_unwind(|| {
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o660
        );
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .write_all(&encode_frame(&LeaseMessage::ClaudeLeaseRequest(
                LeaseRequest {
                    expires_at_unix_ms: u64::MAX / 2,
                },
            )))
            .unwrap();
        let mut reply = vec![0_u8; 4096];
        let read = stream.read(&mut reply).unwrap();
        assert!(matches!(
            decode_frame(&reply[..read]),
            Some(LeaseMessage::ClaudeLeaseRefusal(LeaseRefused {
                kind: LeaseRefusalKind::UnknownCaller,
                ..
            }))
        ));
    });
    // The server is still serving: it did not return when it started.
    let running = server.try_wait().unwrap().is_none();
    server.kill().unwrap();
    server.wait().unwrap();
    outcome.unwrap();
    assert!(running);
}

// ---- many callers ----

fn second_caller() -> CallerConfig {
    CallerConfig {
        caller_runtime_id: "heartbeat".to_string(),
        connection_key_file: "/etc/claude-connector/heartbeat.key".into(),
        connection_key_epoch: 3,
        allowed_models: vec![HAIKU.to_string()],
        max_concurrent_requests: 1,
        max_payload_bytes: 64 << 10,
        max_output_tokens: 1024,
        spend_ceiling_micro_usd: 1_000_000,
        spend_window_ms: 60_000,
    }
}

#[test]
fn several_callers_round_trip_and_each_is_validated_alone() {
    let scratch = Scratch::new();
    let path = scratch.path("connector.cc");
    let mut config = valid();
    config.callers.push(second_caller());
    write_config(&path, &config).unwrap();
    assert_eq!(load_config(&path).unwrap(), config);

    let broken: Vec<(&str, Change)> = vec![
        (
            "caller bounds",
            Box::new(|c| c.callers[1].spend_ceiling_micro_usd = 0),
        ),
        (
            "connection_key_epoch",
            Box::new(|c| c.callers[1].connection_key_epoch = 0),
        ),
        (
            "connection_key_file",
            Box::new(|c| c.callers[1].connection_key_file = "heartbeat.key".into()),
        ),
        (
            "allowed_models",
            Box::new(|c| c.callers[1].allowed_models = vec!["claude-opus-9".to_string()]),
        ),
        (
            "callers",
            Box::new(|c| c.callers[1].caller_runtime_id = c.callers[0].caller_runtime_id.clone()),
        ),
    ];
    for (field, change) in &broken {
        let mut config = valid();
        config.callers.push(second_caller());
        change(&mut config);
        assert_eq!(refused(&config), *field);
    }
}

#[test]
fn a_lease_caller_bills_one_configured_caller_within_that_callers_ceiling() {
    let mut config = valid();
    config.callers.push(second_caller());
    let lease = |user: &str, caller: &str, instance: &str, reservation: u64| LeaseCallerConfig {
        unix_user: user.to_string(),
        caller_id: caller.to_string(),
        unit_instance: instance.to_string(),
        reservation_micro_usd: reservation,
    };
    // A lease caller of each caller, each within its own caller's ceiling.
    config
        .lease_callers
        .push(lease("mind-heartbeat", "heartbeat", "heartbeat", 1_000_000));
    config.validate().unwrap();
    // The first caller's ceiling does not stretch to the second's lease, nor the reverse.
    config.lease_callers[1].reservation_micro_usd = 1_000_001;
    assert_eq!(refused(&config), "lease_callers");
    config.lease_callers[1].reservation_micro_usd = 1;
    config.lease_callers[0].reservation_micro_usd = 50_000_001;
    assert_eq!(refused(&config), "lease_callers");
    config.lease_callers[0].reservation_micro_usd = 50_000_000;
    // A lease caller naming no configured caller, or sharing another's account.
    config.lease_callers[1].caller_id = "nobody".to_string();
    assert_eq!(refused(&config), "lease_callers");
    config.lease_callers[1].caller_id = "heartbeat".to_string();
    config.lease_callers[1].unix_user = config.lease_callers[0].unix_user.clone();
    assert_eq!(refused(&config), "lease_callers");
}

#[test]
fn add_caller_and_add_lease_caller_extend_the_document_and_grow_the_serve_limits() {
    let scratch = Scratch::new();
    let made = init(
        &scratch,
        &init_flags(
            &scratch,
            &[
                "--lease-socket",
                "/run/claude-connector/lease.sock",
                "--lease-user",
                "mind-eureka-self",
                "--lease-unit-instance",
                "eureka",
                "--lease-reservation-micro-usd",
                "5000000",
            ],
        ),
    );
    assert!(made.status.success(), "{}", shown(&made));
    let path = scratch.path("connector.cc");
    let path_text = path.to_str().unwrap();
    let before = load_config(&path).unwrap();

    let key = scratch.path("heartbeat.key");
    let added = run(
        &[
            "config",
            "add-caller",
            path_text,
            "--caller-id",
            "heartbeat",
            "--connection-key-file",
            key.to_str().unwrap(),
            "--connection-key-epoch",
            "2",
            "--allowed-model",
            HAIKU,
            "--spend-ceiling-micro-usd",
            "2000000",
            "--spend-window-ms",
            "60000",
            "--max-concurrent-requests",
            "30",
            "--max-payload-bytes",
            "4194304",
        ],
        &[],
    );
    assert!(added.status.success(), "{}", shown(&added));
    let leased = run(
        &[
            "config",
            "add-lease-caller",
            path_text,
            "--lease-user",
            "mind-heartbeat",
            "--caller-id",
            "heartbeat",
            "--lease-unit-instance",
            "heartbeat",
            "--lease-reservation-micro-usd",
            "1000000",
        ],
        &[],
    );
    assert!(leased.status.success(), "{}", shown(&leased));

    let after = load_config(&path).unwrap();
    assert_eq!(after.callers[0], before.callers[0]);
    assert_eq!(after.callers.len(), 2);
    let heartbeat = &after.callers[1];
    assert_eq!(heartbeat.caller_runtime_id, "heartbeat");
    assert_eq!(heartbeat.connection_key_epoch, 2);
    assert_eq!(heartbeat.spend_ceiling_micro_usd, 2_000_000);
    assert_eq!(heartbeat.max_payload_bytes, 4 << 20);
    assert_eq!(after.lease_callers[0], before.lease_callers[0]);
    assert_eq!(after.lease_callers[1].caller_id, "heartbeat");
    // The frame carries the largest payload and the connections every slot.
    assert!(after.max_frame_bytes > before.max_frame_bytes);
    assert!(after.max_connections >= 34);
    assert_eq!(after.prices, before.prices);
    assert_eq!(
        after.handle_secret_credential,
        before.handle_secret_credential
    );

    // Repeating either verb is refused and leaves the document as it was.
    let again = run(
        &[
            "config",
            "add-caller",
            path_text,
            "--caller-id",
            "heartbeat",
            "--connection-key-file",
            key.to_str().unwrap(),
            "--connection-key-epoch",
            "2",
            "--allowed-model",
            HAIKU,
            "--spend-ceiling-micro-usd",
            "2000000",
            "--spend-window-ms",
            "60000",
        ],
        &[],
    );
    assert!(!again.status.success());
    assert_eq!(load_config(&path).unwrap(), after);
    let unleased = run(
        &[
            "config",
            "add-lease-caller",
            path_text,
            "--lease-user",
            "mind-heartbeat",
            "--caller-id",
            "heartbeat",
            "--lease-unit-instance",
            "heartbeat",
            "--lease-reservation-micro-usd",
            "1000000",
        ],
        &[],
    );
    assert!(!unleased.status.success());
    assert_eq!(load_config(&path).unwrap(), after);
}

#[test]
fn add_lease_caller_needs_a_document_that_lends_a_token() {
    let scratch = Scratch::new();
    let made = init(&scratch, &init_flags(&scratch, &[]));
    assert!(made.status.success(), "{}", shown(&made));
    let path = scratch.path("connector.cc");
    let leased = run(
        &[
            "config",
            "add-lease-caller",
            path.to_str().unwrap(),
            "--lease-user",
            "mind-heartbeat",
            "--caller-id",
            "persona-a-caller",
            "--lease-unit-instance",
            "heartbeat",
            "--lease-reservation-micro-usd",
            "1000000",
        ],
        &[],
    );
    assert!(!leased.status.success());
    assert!(load_config(&path).unwrap().lease_callers.is_empty());
}

#[cfg(unix)]
#[test]
fn init_creates_the_handle_secret_once_private_and_never_shows_it() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new();
    let secret = scratch.path("handle.secret");
    let made = init(&scratch, &init_flags(&scratch, &[]));
    assert!(made.status.success(), "{}", shown(&made));
    let metadata = std::fs::metadata(&secret).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let text = std::fs::read_to_string(&secret).unwrap();
    assert_eq!(text.len(), 64);
    assert!(text.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!shown(&made).contains(&text));

    // A second init keeps the secret the first one made, since handles depend on it.
    std::fs::remove_file(scratch.path("connector.cc")).unwrap();
    let again = init(&scratch, &init_flags(&scratch, &[]));
    assert!(again.status.success(), "{}", shown(&again));
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), text);

    // A refused document leaves no secret file behind.
    let fresh = Scratch::new();
    let flags = init_flags(&fresh, &["--max-payload-bytes", "1"]);
    let refused = init(&fresh, &flags);
    assert!(!refused.status.success());
    assert!(!fresh.path("handle.secret").exists());
}

#[cfg(unix)]
#[test]
fn check_wants_the_handle_secret_credential_and_names_it() {
    let scratch = Scratch::new();
    let (flags, credentials) = prepare(&scratch);
    let made = init(&scratch, &flags);
    assert!(made.status.success(), "{}", shown(&made));
    let config = scratch.path("connector.cc");
    let path = config.to_str().unwrap();
    for body in [None, Some("too-short")] {
        let secret = credentials.join("claude-handle-secret");
        match body {
            None => std::fs::remove_file(&secret).unwrap(),
            Some(text) => std::fs::write(&secret, text).unwrap(),
        }
        let checked = run(
            &["config", "check", path],
            &[("CREDENTIALS_DIRECTORY", &credentials)],
        );
        assert!(!checked.status.success());
        let text = shown(&checked);
        assert!(text.contains("handle_secret_credential"), "{text}");
        assert!(!text.contains("too-short"), "{text}");
    }
}

/// A document written before the handle secret had a field cannot name where
/// the secret is, so it is not a document this connector serves from: it is
/// refused as a store fault, to be authored again with `config init`.
#[test]
fn a_document_without_the_handle_secret_field_is_refused_as_a_store() {
    let scratch = Scratch::new();
    let path = scratch.path("old.cc");
    let mut payload = rmp_serde::to_vec(&valid()).unwrap();
    // array16(23) -> array16(22), and drop the trailing 20-byte fixstr.
    assert_eq!(payload[..3], [0xdc, 0, 23]);
    payload[2] = 22;
    payload.truncate(payload.len() - 21);
    store_raw(
        &path,
        "runtime",
        ClaudeConnectorConfig::TYPE,
        Some(ClaudeConnectorConfig::TYPE),
        payload,
    );
    assert!(matches!(load_config(&path), Err(ConfigError::Store)));
}

#[test]
fn the_handle_secret_credential_is_a_name_of_its_own() {
    for name in ["claude-token", "a/b", "", ".."] {
        let mut config = valid();
        config.handle_secret_credential = name.to_string();
        assert_eq!(refused(&config), "handle_secret_credential", "{name:?}");
    }
}

#[cfg(unix)]
#[test]
fn init_refuses_a_secret_file_it_cannot_create_and_writes_no_document() {
    let scratch = Scratch::new();
    let mut flags = init_flags(&scratch, &[]);
    let at = flags
        .iter()
        .position(|f| f == "--handle-secret-file")
        .unwrap();
    flags[at + 1] = scratch
        .path("absent/handle.secret")
        .to_string_lossy()
        .into_owned();
    let made = init(&scratch, &flags);
    assert!(!made.status.success());
    assert!(!scratch.path("connector.cc").exists());
}

#[cfg(unix)]
#[test]
fn config_init_keeps_an_existing_secret_file_only_if_it_is_usable() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let write = |path: &Path, bytes: usize, mode: u32| {
        std::fs::write(path, "k".repeat(bytes)).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    type Plant = fn(&Scratch, &Path);
    let refused: Vec<(&str, Plant)> = vec![
        ("world readable", |_, p| {
            std::fs::write(p, "k".repeat(64)).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }),
        ("group writable", |_, p| {
            std::fs::write(p, "k".repeat(64)).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o660)).unwrap();
        }),
        ("read only", |_, p| {
            std::fs::write(p, "k".repeat(64)).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o400)).unwrap();
        }),
        ("one byte short", |_, p| {
            std::fs::write(p, "k".repeat(31)).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }),
        ("empty", |_, p| {
            std::fs::write(p, "").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }),
        ("a directory", |_, p| {
            std::fs::create_dir(p).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }),
        ("a link to a good file", |s, p| {
            let target = s.path("elsewhere.secret");
            std::fs::write(&target, "k".repeat(64)).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
            symlink(&target, p).unwrap();
        }),
    ];
    for (name, plant) in refused {
        let scratch = Scratch::new();
        let flags = init_flags(&scratch, &[]);
        let secret = scratch.path("handle.secret");
        plant(&scratch, &secret);
        let before = std::fs::symlink_metadata(&secret).unwrap();
        let made = init(&scratch, &flags);
        assert!(!made.status.success(), "{name} was accepted");
        assert!(shown(&made).contains("--handle-secret-file"), "{name}");
        assert!(!shown(&made).contains("kkkk"), "{name}");
        assert!(
            !scratch.path("connector.cc").exists(),
            "{name} left a document"
        );
        let after = std::fs::symlink_metadata(&secret).unwrap();
        assert_eq!(
            before.permissions().mode(),
            after.permissions().mode(),
            "{name}"
        );
        assert_eq!(before.len(), after.len(), "{name}");
        assert_eq!(
            before.file_type().is_symlink(),
            after.file_type().is_symlink(),
            "{name}"
        );
    }

    // The smallest usable file is accepted and left exactly as it was.
    let scratch = Scratch::new();
    let flags = init_flags(&scratch, &[]);
    let secret = scratch.path("handle.secret");
    write(&secret, 32, 0o600);
    let made = init(&scratch, &flags);
    assert!(made.status.success(), "{}", shown(&made));
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "k".repeat(32));
    assert!(scratch.path("connector.cc").exists());
}
