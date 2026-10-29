//! The claude argv and the child environment: every flag and variable name
//! this backend sends is a constant or built here, so a CLI upgrade is one
//! place to re-probe.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use model_connector::{ProviderRequest, ReasoningEffort};

use crate::config::ClaudeCodeConfig;
use crate::handle::Plan;

/// The variable that tells the CLI which file descriptor holds its credential.
/// The token itself never enters the environment: the process port writes it
/// into a pipe and hands the child the read end at [`TOKEN_FD`].
pub(crate) const TOKEN_FD_VAR: &str = "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR";
/// The descriptor number the child finds the token pipe at: the first one
/// after stdin, stdout and stderr.
pub(crate) const TOKEN_FD: i32 = 3;
const CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The environment of the child: exactly these names and nothing inherited.
/// `Debug` lists names only.
pub struct ChildEnv(Vec<(&'static str, String)>);

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

pub(crate) fn child_env(config: &ClaudeCodeConfig, request: &ProviderRequest) -> ChildEnv {
    let config_dir = config.config_dir.to_string_lossy().into_owned();
    ChildEnv(vec![
        ("PATH", CHILD_PATH.to_string()),
        ("HOME", config_dir.clone()),
        ("CLAUDE_CONFIG_DIR", config_dir),
        (
            "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
            request.max_output_tokens.to_string(),
        ),
        (TOKEN_FD_VAR, TOKEN_FD.to_string()),
    ])
}

/// The system prompt staged for one child: an exclusively created file only
/// its owner can read, removed when this value drops, however the call ends.
pub(crate) struct PromptFile(PathBuf);

static PROMPT_FILES: AtomicU64 = AtomicU64::new(0);

impl PromptFile {
    pub(crate) fn create(dir: &Path, instructions: &str) -> io::Result<Self> {
        let name = format!(
            "claude-connector-prompt-{}-{}",
            std::process::id(),
            PROMPT_FILES.fetch_add(1, Ordering::Relaxed)
        );
        Self::create_at(dir.join(name), instructions)
    }

    /// Creates `path` and nothing that already exists there: a file, a link
    /// (dangling or not) or a directory at the name fails, and is left alone.
    fn create_at(path: PathBuf, instructions: &str) -> io::Result<Self> {
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
/// for permission, and a resume always forks. A request's output schema goes
/// to the CLI as `--json-schema`; without one the flag is absent.
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
    if let Some(schema) = &request.output_schema_json {
        argv.extend(["--json-schema".to_string(), schema.clone()]);
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

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "claude-connector-launch-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_prompt_is_created_private_and_removed_on_drop() {
        let dir = scratch("private");
        let prompt = PromptFile::create(&dir, "the prompt").unwrap();
        let path = prompt.path().to_path_buf();
        assert_eq!(path.parent(), Some(dir.as_path()));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "the prompt");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(prompt);
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_name_already_taken_is_never_written_or_removed() {
        let dir = scratch("taken");
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep").unwrap();

        let file = dir.join("file");
        std::fs::write(&file, "mine").unwrap();
        let link = dir.join("link");
        symlink(&victim, &link).unwrap();
        let dangling = dir.join("dangling");
        symlink(dir.join("nowhere"), &dangling).unwrap();

        for taken in [&file, &link, &dangling] {
            assert!(PromptFile::create_at(taken.clone(), "the prompt").is_err());
        }
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "mine");
        assert!(!dir.join("nowhere").exists());
        assert!(link.exists() && dangling.symlink_metadata().is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
