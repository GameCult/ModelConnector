//! The Claude backend of the connector kit. [`ClaudeCodeBackend`] answers each
//! call by driving the unmodified `claude` binary once, in print mode with
//! stream-json in and out, with every tool, MCP server, settings source and
//! plugin switched off. A binary wires it to [`model_connector::serve`].

mod backend;
mod config;
mod daemon;
mod handle;
mod launch;
mod process;
mod stream;

pub use backend::{ClaudeCodeBackend, CredentialTokenSource, StderrSink, TokenSource};
pub use config::{ClaudeCodeConfig, ClaudeCodeLimits};
pub use daemon::{ClaudeConnectorConfig, ConfigError, load_config, write_config};
#[cfg(unix)]
pub use daemon::{check_prompt_dir, serve_config};
pub use handle::{FsSessionStore, SessionStore};
pub use launch::ChildEnv;
#[cfg(unix)]
pub use process::StdProcessPort;
pub use process::{ProcessPort, RunningChild, StdoutRead};
