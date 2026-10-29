//! The claude argv and the child environment: every flag and variable name
//! this backend sends is a constant or built here, so a CLI upgrade is one
//! place to re-probe.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use model_connector::{ProviderRequest, ReasoningEffort};
use zeroize::Zeroizing;

use crate::config::ClaudeCodeConfig;
use crate::handle::Plan;

/// The one credential variable, copied by name from the connector's own
/// environment into the child and nowhere else.
pub(crate) const TOKEN_VAR: &str = "CLAUDE_CODE_OAUTH_TOKEN";
const CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The environment of the child: exactly these names and nothing inherited.
/// Values are never formatted; `Debug` lists names only.
pub struct ChildEnv(Vec<(&'static str, Zeroizing<String>)>);

impl ChildEnv {
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(name, value)| (*name, value.as_str()))
    }
}

impl fmt::Debug for ChildEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name))
            .finish()
    }
}

pub(crate) fn child_env(
    config: &ClaudeCodeConfig,
    request: &ProviderRequest,
    token: Zeroizing<String>,
) -> ChildEnv {
    let config_dir = config.config_dir.to_string_lossy().into_owned();
    ChildEnv(vec![
        ("PATH", Zeroizing::new(CHILD_PATH.to_string())),
        ("HOME", Zeroizing::new(config_dir.clone())),
        ("CLAUDE_CONFIG_DIR", Zeroizing::new(config_dir)),
        (
            "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
            Zeroizing::new(request.max_output_tokens.to_string()),
        ),
        (TOKEN_VAR, token),
    ])
}

/// The system prompt staged for one child: an exclusively created file only
/// its owner can read, removed when this value drops, however the call ends.
pub(crate) struct PromptFile(PathBuf);

static PROMPT_FILES: AtomicU64 = AtomicU64::new(0);

impl PromptFile {
    pub(crate) fn create(instructions: &str) -> io::Result<Self> {
        let name = format!(
            "claude-connector-prompt-{}-{}",
            std::process::id(),
            PROMPT_FILES.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&path)?;
        let owned = Self(path);
        file.write_all(instructions.as_bytes())?;
        Ok(owned)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PromptFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn effort(effort: ReasoningEffort) -> &'static str {
    match effort {
        ReasoningEffort::Low => "low",
        ReasoningEffort::Medium => "medium",
        ReasoningEffort::High => "high",
        ReasoningEffort::Max => "max",
    }
}

/// The program and its arguments. The system prompt is replaced, by a file
/// rather than an argument because one argument is capped near 128 KiB
/// (E2BIG) and instructions are not, the child has
/// no tools, no MCP servers, no settings, no slash commands and nobody to ask
/// for permission, and a resume always forks.
pub(crate) fn argv(
    config: &ClaudeCodeConfig,
    request: &ProviderRequest,
    plan: &Plan,
    system_prompt_file: &Path,
) -> Vec<String> {
    let mut argv: Vec<String> = [
        config.claude_binary.to_string_lossy().as_ref(),
        "-p",
        "--output-format",
        "stream-json",
        "--verbose",
        "--input-format",
        "stream-json",
        "--model",
        &request.model,
        "--system-prompt-file",
        &system_prompt_file.to_string_lossy(),
        "--tools",
        "",
        "--strict-mcp-config",
        "--setting-sources",
        "",
        "--disable-slash-commands",
        "--permission-prompts",
        "none",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    if let Some(level) = request.reasoning_effort {
        argv.extend(["--effort".to_string(), effort(level).to_string()]);
    }
    if let Plan::Resume { session_id, .. } = plan {
        argv.extend([
            "--resume".to_string(),
            session_id.clone(),
            "--fork-session".to_string(),
        ]);
    }
    argv
}
