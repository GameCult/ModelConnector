//! The claude-connector's configuration document and its serve verb. One typed
//! CultCache record owns every bound and path the backend and the serve loop
//! run with; nothing in the connector's environment, flags or JSON can change
//! them. Validation errors name a field and never echo a value.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cultcache_rs::{CultCache, DatabaseEntry, SingleFileMessagePackBackingStore};
use model_connector::{
    CallerConfig, MIN_PAYLOAD_BYTES, ModelPrice, ServeError, ServeLimits, load_admissions, serve,
};
use thiserror::Error;

use crate::{ClaudeCodeBackend, ClaudeCodeConfig, ClaudeCodeLimits, StderrSink};

const CONFIG_KEY: &str = "runtime";
const MODEL_PREFIX: &str = "claude-";

#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "gamecult.model_connector.claude_connector_config.v1")]
pub struct ClaudeConnectorConfig {
    /// A loopback socket address.
    #[cultcache(key = 0)]
    pub listen: String,
    #[cultcache(key = 1)]
    pub replay_store: PathBuf,
    #[cultcache(key = 2)]
    pub claude_binary: PathBuf,
    #[cultcache(key = 3)]
    pub claude_binary_sha256: [u8; 32],
    #[cultcache(key = 4)]
    pub work_dir: PathBuf,
    #[cultcache(key = 5)]
    pub config_dir: PathBuf,
    /// Where each call's system prompt is staged: a directory the connector
    /// owns, mode 0700.
    #[cultcache(key = 6)]
    pub prompt_dir: PathBuf,
    #[cultcache(key = 7)]
    pub instance: String,
    /// The name of the systemd credential that holds the child's token.
    #[cultcache(key = 8)]
    pub token_credential: String,
    #[cultcache(key = 9)]
    pub deadline_ms: u64,
    #[cultcache(key = 10)]
    pub max_line_bytes: usize,
    #[cultcache(key = 11)]
    pub max_total_bytes: usize,
    #[cultcache(key = 12)]
    pub stderr_tail_bytes: usize,
    #[cultcache(key = 13)]
    pub max_frame_bytes: usize,
    #[cultcache(key = 14)]
    pub max_connections: usize,
    #[cultcache(key = 15)]
    pub socket_timeout_ms: u64,
    #[cultcache(key = 16)]
    pub max_expiry_skew_ms: u64,
    /// Exactly one caller until claude-handle-caller-binding lands.
    #[cultcache(key = 17)]
    pub callers: Vec<CallerConfig>,
    /// What each allowed model costs; keys are canonical model ids.
    #[cultcache(key = 18)]
    pub prices: BTreeMap<String, ModelPrice>,
}

/// A refusal. It names the field or stage that failed and nothing the
/// operator or the file typed.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid configuration field {0}")]
    Invalid(&'static str),
    #[error("the configuration store could not be read as a claude connector document")]
    Store,
    #[error("the prompt directory is not a directory owned by this process with mode 0700")]
    PromptDir,
    #[error("the listener could not be bound")]
    Listen,
    #[error(transparent)]
    Serve(#[from] ServeError),
}

impl ClaudeConnectorConfig {
    /// The one validation: `config init`, `config check` and `serve` all pass
    /// through it. Returns the listen address.
    pub fn validate(&self) -> Result<SocketAddr, ConfigError> {
        let listen = self
            .listen
            .parse::<SocketAddr>()
            .ok()
            .filter(|address| address.ip().is_loopback())
            .ok_or(ConfigError::Invalid("listen"))?;
        let paths = [
            ("replay_store", &self.replay_store),
            ("claude_binary", &self.claude_binary),
            ("work_dir", &self.work_dir),
            ("config_dir", &self.config_dir),
            ("prompt_dir", &self.prompt_dir),
        ];
        for (field, path) in paths {
            if !path.is_absolute() {
                return Err(ConfigError::Invalid(field));
            }
        }
        if self.claude_binary_sha256 == [0; 32] {
            return Err(ConfigError::Invalid("claude_binary_sha256"));
        }
        if !is_trimmed_nonempty(&self.instance) {
            return Err(ConfigError::Invalid("instance"));
        }
        if !is_credential_name(&self.token_credential) {
            return Err(ConfigError::Invalid("token_credential"));
        }
        if self.deadline_ms == 0
            || self.max_line_bytes == 0
            || self.max_total_bytes < self.max_line_bytes
            || self.stderr_tail_bytes == 0
        {
            return Err(ConfigError::Invalid("child limits"));
        }
        if self.max_frame_bytes == 0
            || self.max_connections == 0
            || self.socket_timeout_ms == 0
            || self.max_expiry_skew_ms == 0
        {
            return Err(ConfigError::Invalid("serve limits"));
        }
        let [caller] = self.callers.as_slice() else {
            return Err(ConfigError::Invalid("callers"));
        };
        if !is_trimmed_nonempty(&caller.caller_runtime_id) {
            return Err(ConfigError::Invalid("caller_runtime_id"));
        }
        if !caller.connection_key_file.is_absolute() {
            return Err(ConfigError::Invalid("connection_key_file"));
        }
        if caller.connection_key_epoch == 0 {
            return Err(ConfigError::Invalid("connection_key_epoch"));
        }
        if caller.max_concurrent_requests == 0
            || caller.max_payload_bytes < MIN_PAYLOAD_BYTES
            || caller.max_output_tokens == 0
            || caller.spend_ceiling_micro_usd == 0
            || caller.spend_window_ms == 0
        {
            return Err(ConfigError::Invalid("caller bounds"));
        }
        if caller.allowed_models.is_empty() {
            return Err(ConfigError::Invalid("allowed_models"));
        }
        let mut seen = BTreeSet::new();
        for model in &caller.allowed_models {
            if !is_canonical_model(model)
                || !seen.insert(model.as_str())
                || !self.prices.contains_key(model)
            {
                return Err(ConfigError::Invalid("allowed_models"));
            }
        }
        if !self.prices.keys().all(|model| is_canonical_model(model)) {
            return Err(ConfigError::Invalid("prices"));
        }
        Ok(listen)
    }

    fn backend_config(&self) -> ClaudeCodeConfig {
        ClaudeCodeConfig {
            claude_binary: self.claude_binary.clone(),
            claude_binary_sha256: self.claude_binary_sha256,
            work_dir: self.work_dir.clone(),
            config_dir: self.config_dir.clone(),
            prompt_dir: self.prompt_dir.clone(),
            token_credential: self.token_credential.clone(),
            instance: self.instance.clone(),
            limits: ClaudeCodeLimits {
                deadline: Duration::from_millis(self.deadline_ms),
                max_line_bytes: self.max_line_bytes,
                max_total_bytes: self.max_total_bytes,
                stderr_tail_bytes: self.stderr_tail_bytes,
            },
        }
    }

    fn serve_limits(&self) -> ServeLimits {
        ServeLimits {
            max_frame_bytes: self.max_frame_bytes,
            max_connections: self.max_connections,
            socket_timeout_ms: self.socket_timeout_ms,
            max_expiry_skew_ms: self.max_expiry_skew_ms,
        }
    }
}

fn is_trimmed_nonempty(text: &str) -> bool {
    !text.is_empty() && text.trim() == text
}

/// A model id the CLI echoes back unchanged: aliases are refused because the
/// stream's `init.model` must equal the requested model.
fn is_canonical_model(model: &str) -> bool {
    model.starts_with(MODEL_PREFIX)
        && model.len() > MODEL_PREFIX.len()
        && model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
}

/// One file name under `$CREDENTIALS_DIRECTORY`, never a path.
fn is_credential_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
}

/// Reads the document without writing: a shared snapshot of exactly one
/// record, with the exact key, type and schema id, in canonical positional
/// MessagePack, then validated.
pub fn load_config(path: &Path) -> Result<ClaudeConnectorConfig, ConfigError> {
    let store = SingleFileMessagePackBackingStore::new(path);
    let config = store
        .with_read_only_shared_snapshot(|entries| {
            let [envelope] = entries.as_slice() else {
                anyhow::bail!("not exactly one record");
            };
            if envelope.key != CONFIG_KEY
                || envelope.r#type != ClaudeConnectorConfig::TYPE
                || envelope.schema_id.as_deref() != Some(ClaudeConnectorConfig::TYPE)
            {
                anyhow::bail!("wrong typed envelope");
            }
            let config: ClaudeConnectorConfig = rmp_serde::from_slice(&envelope.payload)?;
            if rmp_serde::to_vec(&config)? != envelope.payload {
                anyhow::bail!("not canonical positional MessagePack");
            }
            Ok(config)
        })
        .map_err(|_| ConfigError::Store)?;
    config.validate()?;
    Ok(config)
}

/// Validates, then writes the document as the store's only record.
pub fn write_config(path: &Path, config: &ClaudeConnectorConfig) -> Result<(), ConfigError> {
    config.validate()?;
    let mut cache = CultCache::new();
    cache
        .register_entry_type::<ClaudeConnectorConfig>()
        .map_err(|_| ConfigError::Store)?;
    cache
        .add_generic_backing_store(SingleFileMessagePackBackingStore::new(path))
        .map_err(|_| ConfigError::Store)?;
    cache
        .pull_all_backing_stores()
        .map_err(|_| ConfigError::Store)?;
    cache
        .put(CONFIG_KEY, config)
        .map_err(|_| ConfigError::Store)?;
    Ok(())
}

/// The prompt directory holds every system prompt in flight: it must be a
/// real directory (not a link) that this process owns and nobody else can
/// enter.
#[cfg(unix)]
pub fn check_prompt_dir(dir: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(dir).map_err(|_| ConfigError::PromptDir)?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(ConfigError::PromptDir);
    }
    Ok(())
}

/// The child's stderr is the log's business by size only: its bytes are never
/// written anywhere the connector controls.
struct LogSink;

impl StderrSink for LogSink {
    fn stderr_tail(&self, tail: &[u8]) {
        eprintln!("claude-connector: child stderr, {} bytes", tail.len());
    }
}

/// Loads the document and serves until the listener fails.
#[cfg(unix)]
pub fn serve_config(path: &Path) -> Result<(), ConfigError> {
    let config = load_config(path)?;
    let listen = config.validate()?;
    check_prompt_dir(&config.prompt_dir)?;
    let admissions = load_admissions(&config.callers)?;
    let backend = Arc::new(ClaudeCodeBackend::new(
        config.backend_config(),
        Box::new(LogSink),
    ));
    let listener = TcpListener::bind(listen).map_err(|_| ConfigError::Listen)?;
    serve(
        listener,
        config.serve_limits(),
        admissions,
        config.prices.clone(),
        &config.replay_store,
        backend,
    )?;
    Ok(())
}
