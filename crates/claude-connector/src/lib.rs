//! The Claude backend of the connector kit. [`ClaudeCodeBackend`] answers each
//! call by driving the unmodified `claude` binary once, in print mode with
//! stream-json in and out, with every tool, MCP server, settings source and
//! plugin switched off. A binary wires it to [`model_connector::serve`].

mod backend;
mod config;
mod daemon;
mod handle;
mod launch;
#[cfg(target_os = "linux")]
mod lease;
mod process;
mod quota;
mod stream;
#[cfg(target_os = "linux")]
mod unit;

pub use backend::{ClaudeCodeBackend, CredentialTokenSource, StderrSink, TokenSource};
pub use config::{ClaudeCodeConfig, ClaudeCodeLimits};
pub use daemon::{
    ClaudeConnectorConfig, ConfigError, LeaseCallerConfig, check_ready, load_config, write_config,
};
#[cfg(unix)]
pub use daemon::{check_prompt_dir, serve_config};
pub use handle::{FsSessionStore, MIN_SECRET_BYTES, SessionStore};
pub use launch::ChildEnv;
#[cfg(target_os = "linux")]
pub use lease::{
    LeaseCaller, LeaseGranted, LeaseLimits, LeaseMessage, LeaseRefusalKind, LeaseRefused,
    LeaseRequest, MAX_LEASE_FRAME_BYTES, PeerCredentials, PeerUnit, PeerUnits, decode_frame,
    encode_frame, peer_credentials, serve_leases, user_uid,
};
#[cfg(unix)]
pub use process::StdProcessPort;
pub use process::{ProcessPort, RunningChild, StdoutRead};
pub use quota::QuotaCell;
#[cfg(target_os = "linux")]
pub use unit::SystemdUnits;
