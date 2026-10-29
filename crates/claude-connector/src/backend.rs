use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::Instant;

use model_connector::{
    FailureKind, InputItem, ProviderBackend, ProviderCall, ProviderRequest, TransportEvent,
    TransportEventPayload, TransportOutcome, TransportResult, Usage,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config::{ClaudeCodeConfig, PROVIDER};
use crate::handle::{ClaudeCodeHandle, SessionStore, plan, prefix_digest, stdin_bytes};
use crate::launch::{PromptFile, argv, child_env};
use crate::process::{ProcessPort, RunningChild, StdoutRead};
use crate::stream::{Failure, Finished, Step, StreamState};

/// Where the child's credential comes from, read afresh at every use. The
/// connector's own environment is never a source (ruling
/// claude-connector-token-credential).
pub trait TokenSource: Send + Sync {
    /// The token, or `None` when there is none or it is empty.
    fn read(&self) -> Option<Zeroizing<String>>;
}

/// A token in a file named by a systemd credential: the file
/// `$CREDENTIALS_DIRECTORY/<name>`, read on every call so a rotated credential
/// is picked up by the next spawn.
pub struct CredentialTokenSource {
    directory: Option<PathBuf>,
    name: String,
}

impl CredentialTokenSource {
    /// The credential `name` under the directory systemd names in
    /// `CREDENTIALS_DIRECTORY`; with no such variable the source has no token.
    /// The variable names a directory, never a token.
    pub fn from_environment(name: impl Into<String>) -> Self {
        Self {
            directory: std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from),
            name: name.into(),
        }
    }

    pub fn in_directory(directory: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        Self {
            directory: Some(directory.into()),
            name: name.into(),
        }
    }
}

impl TokenSource for CredentialTokenSource {
    fn read(&self) -> Option<Zeroizing<String>> {
        let directory = self.directory.as_ref()?;
        let mut token = Zeroizing::new(std::fs::read_to_string(directory.join(&self.name)).ok()?);
        let trimmed = token.trim_end_matches(['\r', '\n']).len();
        token.truncate(trimmed);
        (!token.is_empty()).then_some(token)
    }
}

/// Where the tail of a child's stderr goes. The backend never puts it in a
/// result; the connector binary wires this to its log.
pub trait StderrSink: Send + Sync {
    fn stderr_tail(&self, tail: &[u8]);
}

/// Answers each call with one `claude` child process: never more than one per
/// call, and a failed call is never run again.
pub struct ClaudeCodeBackend {
    config: ClaudeCodeConfig,
    port: Box<dyn ProcessPort>,
    sessions: Box<dyn SessionStore>,
    sink: Box<dyn StderrSink>,
    tokens: Box<dyn TokenSource>,
}

impl ClaudeCodeBackend {
    /// The backend over real processes and the CLI's real session store.
    #[cfg(unix)]
    pub fn new(config: ClaudeCodeConfig, sink: Box<dyn StderrSink>) -> Self {
        let port = Box::new(crate::process::StdProcessPort::new(config.limits));
        let sessions = Box::new(crate::handle::FsSessionStore::new(
            config.config_dir.clone(),
        ));
        let tokens = Box::new(CredentialTokenSource::from_environment(
            config.token_credential.clone(),
        ));
        Self::with_ports(config, port, sessions, sink, tokens)
    }

    pub fn with_ports(
        config: ClaudeCodeConfig,
        port: Box<dyn ProcessPort>,
        sessions: Box<dyn SessionStore>,
        sink: Box<dyn StderrSink>,
        tokens: Box<dyn TokenSource>,
    ) -> Self {
        Self {
            config,
            port,
            sessions,
            sink,
            tokens,
        }
    }

    /// The one pin check: `ready` and every spawn use it, and nothing caches
    /// its answer.
    fn binary_matches_pin(&self) -> bool {
        binary_matches_pin(&self.config)
    }

    fn run(&self, request: &ProviderRequest) -> (Vec<TransportEvent>, TransportOutcome) {
        let plan = match plan(request, &self.config, self.sessions.as_ref()) {
            Ok(plan) => plan,
            Err(error) => {
                return failed(
                    FailureKind::InvalidRequest,
                    error.to_string(),
                    Some(zero_usage()),
                );
            }
        };
        let Some(token) = self.tokens.read() else {
            return failed(
                FailureKind::Authentication,
                "claude-code: the connector has no credential to give the child".to_string(),
                Some(zero_usage()),
            );
        };
        if !self.binary_matches_pin() {
            return failure(Failure::never_reached(
                FailureKind::Provider,
                "claude-code: the claude binary does not match its pin",
            ));
        }
        let Ok(prompt) = PromptFile::create(&self.config.prompt_dir, &request.instructions) else {
            return failure(Failure::never_reached(
                FailureKind::Provider,
                "claude-code: the system prompt could not be staged",
            ));
        };
        let argv = argv(&self.config, request, &plan, prompt.path());
        let env = child_env(&self.config, request, token);
        let deadline = Instant::now() + self.config.limits.deadline;

        let spawned = self.port.spawn(
            &argv,
            &env,
            &self.config.work_dir,
            stdin_bytes(plan.blocks()),
        );
        let Ok(mut child) = spawned else {
            return failure(Failure::never_reached(
                FailureKind::Provider,
                "claude-code: the child could not be spawned",
            ));
        };
        let finished = read_stream(child.as_mut(), deadline, &request.model);
        child.kill();
        child.wait();
        let tail = child.stderr_tail();
        if !tail.is_empty() {
            self.sink.stderr_tail(&tail);
        }

        match finished {
            Ok(finished) => self.completed(request, finished),
            Err(failure_) => failure(failure_),
        }
    }

    fn completed(
        &self,
        request: &ProviderRequest,
        finished: Finished,
    ) -> (Vec<TransportEvent>, TransportOutcome) {
        let mut payloads: Vec<TransportEventPayload> = finished
            .texts
            .iter()
            .map(|text| TransportEventPayload::TextDelta { text: text.clone() })
            .collect();

        let mut prefix = request.input.clone();
        if !finished.texts.is_empty() {
            prefix.push(InputItem::AssistantText {
                text: finished.texts.concat(),
            });
        }
        let handle = ClaudeCodeHandle::Ended {
            session_id: finished.session_id,
            instance: self.config.instance.clone(),
            prefix_sha256: prefix_digest(&request.instructions, &request.model, &prefix),
        };
        payloads.push(TransportEventPayload::ReasoningState {
            state: handle.encode(),
        });

        let events = payloads
            .into_iter()
            .enumerate()
            .map(|(sequence, payload)| TransportEvent {
                sequence: sequence as u64,
                payload,
            })
            .collect();
        (
            events,
            TransportOutcome::Completed {
                provider_response_id: finished.message_id,
                stop_reason: finished.stop_reason,
                usage: finished.usage,
            },
        )
    }
}

impl ProviderBackend for ClaudeCodeBackend {
    fn ready(&self) -> Result<(), &'static str> {
        readiness(&self.config, self.tokens.as_ref())
    }

    fn provider(&self) -> &str {
        PROVIDER
    }

    fn execute(&self, call: &ProviderCall) -> TransportResult {
        let (events, outcome) = self.run(call.request());
        call.transported(events, outcome)
    }
}

fn read_stream(
    child: &mut dyn RunningChild,
    deadline: Instant,
    model: &str,
) -> Result<Finished, Failure> {
    let mut state = StreamState::new(model);
    let finished = loop {
        match child.read_line(deadline) {
            StdoutRead::Line(line) => {
                if let Step::Done(done) = state.feed(&line) {
                    break *done;
                }
            }
            StdoutRead::Eof => {
                return Err(Failure::cost_unknown(
                    FailureKind::Provider,
                    "claude-code: the stream ended without a result",
                ));
            }
            StdoutRead::Timeout => {
                return Err(Failure::cost_unknown(
                    FailureKind::Timeout,
                    "claude-code: the deadline passed before a result",
                ));
            }
            StdoutRead::Breach => {
                return Err(Failure::cost_unknown(
                    FailureKind::Provider,
                    "claude-code: the output passed its size cap",
                ));
            }
        }
    };
    // The result is in; give the child until its deadline to close stdout.
    while matches!(child.read_line(deadline), StdoutRead::Line(_)) {}
    finished
}

fn binary_matches_pin(config: &ClaudeCodeConfig) -> bool {
    let Ok(mut file) = File::open(&config.claude_binary) else {
        return false;
    };
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).is_ok()
        && <[u8; 32]>::from(hasher.finalize()) == config.claude_binary_sha256
}

/// Whether the backend can take work, naming the first config field that
/// cannot be used. `config check` and `serve` both ask this.
pub(crate) fn readiness(
    config: &ClaudeCodeConfig,
    tokens: &dyn TokenSource,
) -> Result<(), &'static str> {
    if !config.work_dir.is_dir() {
        return Err("work_dir");
    }
    if !config.config_dir.is_dir() {
        return Err("config_dir");
    }
    if !config.prompt_dir.is_dir() {
        return Err("prompt_dir");
    }
    if tokens.read().is_none() {
        return Err("token_credential");
    }
    if !binary_matches_pin(config) {
        return Err("claude_binary_sha256");
    }
    Ok(())
}

fn zero_usage() -> Usage {
    Usage {
        input_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        output_tokens: 0,
        reasoning_tokens: None,
    }
}

fn failed(
    kind: FailureKind,
    message: String,
    usage: Option<Usage>,
) -> (Vec<TransportEvent>, TransportOutcome) {
    (
        Vec::new(),
        TransportOutcome::Failed {
            kind,
            message,
            usage,
        },
    )
}

fn failure(failure: Failure) -> (Vec<TransportEvent>, TransportOutcome) {
    failed(failure.kind, failure.message.to_string(), failure.usage)
}

#[cfg(test)]
mod tests;
