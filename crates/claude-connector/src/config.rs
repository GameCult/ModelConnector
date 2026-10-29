use std::path::PathBuf;
use std::time::Duration;

/// The provider tag the kit puts on every receipt and on the reasoning state
/// of this backend. It is distinct from any Messages-API backend's tag, so the
/// kit treats each backend's state as foreign to the other.
pub(crate) const PROVIDER: &str = "claude-code";

/// What the connector's binary hands the backend. Every path is absolute.
#[derive(Debug, Clone)]
pub struct ClaudeCodeConfig {
    /// The `claude` executable.
    pub claude_binary: PathBuf,
    /// The SHA-256 the executable must have for [`ready`](model_connector::ProviderBackend::ready).
    pub claude_binary_sha256: [u8; 32],
    /// An empty directory the connector owns: the CLI writes its cwd, git state
    /// and platform into the system prompt.
    pub work_dir: PathBuf,
    /// Passed to the child as `CLAUDE_CONFIG_DIR` and `HOME`; it holds the
    /// CLI's session store.
    pub config_dir: PathBuf,
    /// The connector instance id written into every handle.
    pub instance: String,
    pub limits: ClaudeCodeLimits,
}

/// The bounds of one child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaudeCodeLimits {
    /// The whole call, spawn to result.
    pub deadline: Duration,
    pub max_line_bytes: usize,
    pub max_total_bytes: usize,
    pub stderr_tail_bytes: usize,
}
