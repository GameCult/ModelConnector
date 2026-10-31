//! The claude-connector's configuration document and binary: what the
//! document accepts, what it refuses, and that a document of the dollar era
//! fails closed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use claude_connector::{
    ClaudeConnectorConfig, ConfigError, LeaseCallerConfig, load_config, write_config,
};
use cultcache_rs::{CultCache, DatabaseEntry, SingleFileMessagePackBackingStore};
use model_connector::{CallerConfig, LeaseTurn};

const OPUS: &str = "claude-opus-5-1";
const HAIKU: &str = "claude-haiku-5-5";

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
        }],
        lease_socket: Some("/run/claude-connector/lease.sock".into()),
        lease_callers: vec![LeaseCallerConfig {
            unix_user: "mind-eureka-self".to_string(),
            caller_id: "persona-a-caller".to_string(),
            turn: LeaseTurn::SelfRun,
            unit_instance: "eureka".to_string(),
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
fn a_valid_document_validates() {
    assert!(valid().validate().is_ok());
}

/// A document of the dollar era: the first type id, carrying a price table.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "gamecult.model_connector.claude_connector_config.v1")]
struct DollarEraConfig {
    #[cultcache(key = 0)]
    listen: String,
    #[cultcache(key = 18)]
    prices: BTreeMap<String, u64>,
}

#[test]
fn a_dollar_era_config_is_refused_at_load() {
    let scratch = Scratch::new();
    let path = scratch.path("old.cc");
    {
        let mut cache = CultCache::new();
        cache.register_entry_type::<DollarEraConfig>().unwrap();
        cache
            .add_generic_backing_store(SingleFileMessagePackBackingStore::new(&path))
            .unwrap();
        cache
            .put(
                "runtime".to_string(),
                &DollarEraConfig {
                    listen: "127.0.0.1:7443".to_string(),
                    prices: BTreeMap::from([(OPUS.to_string(), 5_000_000)]),
                },
            )
            .unwrap();
    }
    assert!(matches!(load_config(&path), Err(ConfigError::Store)));
}

#[test]
fn the_known_models_are_the_allowed_models_by_form_alone() {
    for good in [
        "claude-opus-5-1",
        "claude-haiku-5-5",
        "claude-opus-5",
        "claude-opus-5-1-20260101",
    ] {
        let mut config = valid();
        config.callers[0].allowed_models = vec![good.to_string()];
        assert!(config.validate().is_ok(), "{good}");
    }
    for bad in [
        "sonnet",
        "claude-",
        "claude-sonnet-latest",
        "claude-Opus-5-1",
        "claude-opus-5-1-2026",
        "claude-opus-5-1-20260101-x",
    ] {
        let mut config = valid();
        config.callers[0].allowed_models = vec![bad.to_string()];
        assert_eq!(refused(&config), "allowed_models", "{bad}");
    }
    let mut twice = valid();
    twice.callers[0].allowed_models = vec![OPUS.to_string(), OPUS.to_string()];
    assert_eq!(refused(&twice), "allowed_models");
    let mut none = valid();
    none.callers[0].allowed_models.clear();
    assert_eq!(refused(&none), "allowed_models");
}

#[test]
fn caller_bounds_are_required_nonzero() {
    let edits: [fn(&mut ClaudeConnectorConfig); 3] = [
        |c| c.callers[0].max_concurrent_requests = 0,
        |c| c.callers[0].max_output_tokens = 0,
        |c| c.callers[0].max_payload_bytes = 0,
    ];
    for edit in edits {
        let mut config = valid();
        edit(&mut config);
        assert_eq!(refused(&config), "caller bounds");
    }
}

#[test]
fn a_lease_caller_names_a_configured_caller_and_a_socket_exists_exactly_when_it_leases() {
    let mut stranger = valid();
    stranger.lease_callers[0].caller_id = "nobody".to_string();
    assert_eq!(refused(&stranger), "lease_callers");

    let mut no_callers = valid();
    no_callers.lease_callers.clear();
    assert_eq!(refused(&no_callers), "lease_callers");

    let mut no_socket = valid();
    no_socket.lease_socket = None;
    assert_eq!(refused(&no_socket), "lease_callers");
    no_socket.lease_callers.clear();
    assert!(no_socket.validate().is_ok());

    let mut twice = valid();
    twice.lease_callers.push(twice.lease_callers[0].clone());
    assert_eq!(refused(&twice), "lease_callers");
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_claude-connector"))
        .args(args)
        .env_clear()
        .output()
        .unwrap()
}

fn init_flags(scratch: &Scratch, extra: &[&str]) -> Vec<String> {
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
        "--allowed-model",
        HAIKU,
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
    run(&args)
}

#[test]
fn config_init_writes_the_flags_into_the_document() {
    let scratch = Scratch::new();
    let made = init(&scratch, &init_flags(&scratch, &[]));
    assert!(made.status.success(), "{:?}", made);
    let config = load_config(&scratch.path("connector.cc")).unwrap();
    assert_eq!(config.callers[0].allowed_models, [HAIKU]);
    assert_eq!(config.claude_binary_sha256, [0xab; 32]);
    assert!(config.lease_callers.is_empty());
}

#[test]
fn the_dollar_flags_are_not_flags() {
    let dollar_flags: [&[&str]; 4] = [
        &["--spend-ceiling-micro-usd", "50000000"],
        &["--spend-window-ms", "3600000"],
        &["--price", "claude-haiku-5-5:1:1:1:1:1"],
        &["--lease-reservation-micro-usd", "5000000"],
    ];
    for extra in dollar_flags {
        let scratch = Scratch::new();
        let made = init(&scratch, &init_flags(&scratch, extra));
        assert!(!made.status.success(), "{extra:?} was accepted");
        assert!(
            !Path::new(&scratch.path("connector.cc")).exists(),
            "{extra:?}"
        );
    }
}
