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
    CallerAdmission, CallerConfig, MIN_PAYLOAD_BYTES, ModelPrice, ServeError, ServeLimits,
    ServiceError, load_admissions, serve,
};
use thiserror::Error;

use crate::backend::readiness;
use crate::{
    ClaudeCodeBackend, ClaudeCodeConfig, ClaudeCodeLimits, CredentialTokenSource, StderrSink,
};

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
    /// Something the document names exists but cannot be used now.
    #[error("the configured {0} cannot be used")]
    Unusable(&'static str),
    /// The serve loop failed after it started.
    #[error("the serve loop failed at {0}")]
    Serving(&'static str),
}

/// The kit's serve errors carry stored paths, ids and numbers; none of that
/// text is shown. Each maps to the configuration field or stage it names.
impl From<ServeError> for ConfigError {
    fn from(error: ServeError) -> Self {
        match error {
            ServeError::InvalidConfig(field) | ServeError::BackendUnready(field) => {
                Self::Unusable(field)
            }
            ServeError::FrameBound { .. } => Self::Invalid("max_frame_bytes"),
            ServeError::ConnectionKey(_) => Self::Unusable("connection_key_file"),
            ServeError::Service(error) => match error {
                ServiceError::ReplayStore(_) => Self::Unusable("replay_store"),
                ServiceError::UnpricedModel(_) => Self::Invalid("prices"),
                ServiceError::InvalidAdmission
                | ServiceError::DuplicateCaller
                | ServiceError::SharedCallerKey => Self::Invalid("callers"),
                _ => Self::Serving("service"),
            },
            ServeError::ServicePoisoned => Self::Serving("service"),
            ServeError::Listen(_) => Self::Serving("listener"),
            ServeError::Thread(_) | ServeError::Connection(_) => Self::Serving("connection"),
            ServeError::FrameSize | ServeError::FrameEncoding => Self::Serving("frame"),
            ServeError::Clock => Self::Serving("clock"),
        }
    }
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
        if !self
            .prices
            .iter()
            .all(|(model, price)| is_canonical_model(model) && is_fully_priced(price))
        {
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

/// A model id the CLI echoes back unchanged: `claude-<family>-<major>-<minor>`
/// with an optional `-YYYYMMDD` suffix, the family lowercase letters. Aliases
/// and bare prefixes are refused because the stream's `init.model` must equal
/// the requested model.
fn is_canonical_model(model: &str) -> bool {
    let Some(rest) = model.strip_prefix(MODEL_PREFIX) else {
        return false;
    };
    let digits = |part: &str, most: usize| {
        (1..=most).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    let mut parts = rest.split('-');
    let family = parts.next().unwrap_or("");
    let major = parts.next().unwrap_or("");
    let minor = parts.next().unwrap_or("");
    let date = parts.next();
    !family.is_empty()
        && family.bytes().all(|byte| byte.is_ascii_lowercase())
        && digits(major, 2)
        && digits(minor, 2)
        && date.is_none_or(|date| date.len() == 8 && digits(date, 8))
        && parts.next().is_none()
}

/// A price is a fuse only if every component it bills is nonzero: a zero rate
/// lets a call cost nothing against the caller's ceiling.
fn is_fully_priced(price: &ModelPrice) -> bool {
    let long = price.long_context.map(|long| long.rates);
    [Some(price.rates), long]
        .into_iter()
        .flatten()
        .all(|rates| {
            [
                rates.input,
                rates.cache_write_short,
                rates.cache_write_long,
                rates.cache_read,
                rates.output,
            ]
            .iter()
            .all(|rate| *rate > 0)
        })
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
struct LogSink<W>(std::sync::Mutex<W>);

impl<W: std::io::Write + Send> StderrSink for LogSink<W> {
    fn stderr_tail(&self, tail: &[u8]) {
        if let Ok(mut log) = self.0.lock() {
            let _ = writeln!(log, "claude-connector: child stderr, {} bytes", tail.len());
        }
    }
}

/// Everything `serve` needs true before it binds, in one place so that
/// `config check` passes exactly what `serve` will start: the prompt
/// directory, the other directories, the credential, the pin, the connection
/// key and the frame and connection bounds. Returns the admitted callers.
fn readiness_of(config: &ClaudeConnectorConfig) -> Result<Vec<CallerAdmission>, ConfigError> {
    config.validate()?;
    #[cfg(unix)]
    check_prompt_dir(&config.prompt_dir)?;
    let admissions = load_admissions(&config.callers)?;
    config.serve_limits().validate(&admissions)?;
    let backend = config.backend_config();
    readiness(
        &backend,
        &CredentialTokenSource::from_environment(backend.token_credential.clone()),
    )
    .map_err(ConfigError::Unusable)?;
    Ok(admissions)
}

/// Whether `serve` would start with this document and this environment.
pub fn check_ready(config: &ClaudeConnectorConfig) -> Result<(), ConfigError> {
    readiness_of(config).map(drop)
}

/// Loads the document and serves until the listener fails.
#[cfg(unix)]
pub fn serve_config(path: &Path) -> Result<(), ConfigError> {
    let config = load_config(path)?;
    let admissions = readiness_of(&config)?;
    let listen = config.validate()?;
    let backend = Arc::new(ClaudeCodeBackend::new(
        config.backend_config(),
        Box::new(LogSink(std::sync::Mutex::new(std::io::stderr()))),
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// A log that a test can read back.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn serve_errors_name_a_field_or_stage_and_never_a_stored_value() {
        const CANARY: &str = "canary-path-8e2a";
        let io = || std::io::Error::other(CANARY);
        let cases: Vec<(ServeError, &str)> = vec![
            (ServeError::InvalidConfig("callers"), "callers"),
            (ServeError::BackendUnready("work_dir"), "work_dir"),
            (
                ServeError::FrameBound {
                    max_frame_bytes: 4099,
                    payload_bytes: 4096,
                    needed_frame_bytes: 9999,
                },
                "max_frame_bytes",
            ),
            (ServeError::ConnectionKey(io()), "connection_key_file"),
            (
                ServeError::Service(ServiceError::ReplayStore(format!("{CANARY}/replay.cc"))),
                "replay_store",
            ),
            (
                ServeError::Service(ServiceError::UnpricedModel(CANARY.to_string())),
                "prices",
            ),
            (
                ServeError::Service(ServiceError::InvalidAdmission),
                "callers",
            ),
            (
                ServeError::Service(ServiceError::DuplicateCaller),
                "callers",
            ),
            (
                ServeError::Service(ServiceError::SharedCallerKey),
                "callers",
            ),
            (ServeError::Listen(io()), "listener"),
        ];
        for (error, field) in cases {
            let shown = ConfigError::from(error);
            let text = format!("{shown} {shown:?}");
            assert!(text.contains(field), "{text}");
            for stored in [CANARY, "4099", "9999", "replay.cc"] {
                assert!(!text.contains(stored), "{text}");
            }
        }
    }

    #[test]
    fn the_log_gets_the_size_of_the_childs_stderr_and_never_its_bytes() {
        let log = Captured::default();
        let sink = LogSink(Mutex::new(log.clone()));
        sink.stderr_tail(b"canary-stderr-text, 22 bytes");
        let written = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            written,
            "claude-connector: child stderr, 28 bytes
"
        );
        assert!(!written.contains("canary"));
    }

    #[cfg(unix)]
    mod prompt_dir {
        use std::os::unix::fs::{PermissionsExt, chown, symlink};
        use std::path::PathBuf;

        use super::super::check_prompt_dir;

        struct Dir(PathBuf);

        impl Dir {
            fn new(name: &str) -> Self {
                let path = std::env::temp_dir()
                    .join(format!("claude-prompt-dir-{}-{name}", std::process::id()));
                let _ = std::fs::remove_dir_all(&path);
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }
            fn mode(&self, mode: u32) {
                std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(mode)).unwrap();
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn only_mode_0700_passes() {
            let dir = Dir::new("modes");
            dir.mode(0o700);
            assert!(check_prompt_dir(&dir.0).is_ok());
            // Each of these leaves the owner able to enter, or adds a bit
            // beyond the owner's three; all are refused.
            for mode in [
                0o500, 0o300, 0o100, 0o600, 0o770, 0o707, 0o750, 0o755, 0o1700, 0o2700, 0o4700,
            ] {
                dir.mode(mode);
                assert!(check_prompt_dir(&dir.0).is_err(), "{mode:o}");
            }
        }

        #[test]
        fn a_link_to_a_good_directory_is_refused() {
            let dir = Dir::new("link-target");
            dir.mode(0o700);
            let link =
                std::env::temp_dir().join(format!("claude-prompt-dir-{}-link", std::process::id()));
            let _ = std::fs::remove_file(&link);
            symlink(&dir.0, &link).unwrap();
            let refused = check_prompt_dir(&link).is_err();
            std::fs::remove_file(&link).unwrap();
            assert!(refused);
        }

        #[test]
        fn a_directory_owned_by_another_user_is_refused() {
            // SAFETY: geteuid has no preconditions and cannot fail.
            if unsafe { libc::geteuid() } != 0 {
                eprintln!("skipped: only root can give a directory away");
                return;
            }
            let dir = Dir::new("owner");
            dir.mode(0o700);
            assert!(check_prompt_dir(&dir.0).is_ok());
            chown(&dir.0, Some(1234), None).unwrap();
            assert!(check_prompt_dir(&dir.0).is_err());
        }
    }
}
