//! `claude-connector ask`: one no-tools completion through a running connector.
//!
//! A thin caller over [`ConnectorClient`]. It builds a [`ProviderRequest`] with
//! `ProviderRequest::new`, which carries no tools, and has no field, flag or
//! path by which a caller could add one; the working directory and environment
//! of the model child belong to the connector. Every failure is an
//! [`AskError`] whose text names a cause and never echoes the key, the prompt
//! or the instructions.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use model_connector::{
    ConnectorClient, ConnectorClientError, FailureKind, InputItem, ProviderRequest,
    ReasoningEffort, StopReason, TransportDisposition, TransportEventPayload, TransportInvocation,
    TransportOutcome, TransportResult, frame_bytes_for_payload, provider_request_sha256,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// The loopback endpoint a claude connector listens on.
pub const DEFAULT_ENDPOINT: &str = "127.0.0.1:4110";
/// The payload bound the connector's own `config init` defaults to.
pub const PAYLOAD_BYTES: usize = 1 << 20;
const MAX_KEY_BYTES: usize = 1024;
pub const MAX_SYSTEM_BYTES: usize = 64 * 1024;

pub struct AskArgs {
    pub endpoint: SocketAddr,
    pub caller_id: String,
    pub key_file: std::path::PathBuf,
    pub model: String,
    pub instructions: String,
    pub effort: Option<ReasoningEffort>,
    pub max_output_tokens: u32,
    pub timeout: Duration,
    pub prompt: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AskError {
    #[error("the prompt on stdin is empty")]
    EmptyPrompt,
    #[error("the prompt on stdin is larger than the {PAYLOAD_BYTES} byte payload bound")]
    PromptTooLarge,
    #[error("the instructions are empty")]
    EmptyInstructions,
    #[error("the connection key file cannot be read")]
    KeyUnreadable,
    #[error("the connection key file is not text")]
    KeyEncoding,
    #[error("the connection key file is not a regular file")]
    KeyNotRegular,
    #[error("the connection key file is readable by group or world (chmod 600)")]
    KeyExposed,
    #[error("the instructions file cannot be read as text from a regular file")]
    SystemUnreadable,
    #[error("the instructions file is larger than {MAX_SYSTEM_BYTES} bytes")]
    SystemTooLarge,
    #[error("standard input cannot be read")]
    StdinRead,
    #[error("standard input is not UTF-8 text")]
    StdinNotText,
    #[error("the answer cannot be written to standard output")]
    StdoutWrite,
    #[error("nothing is listening at the connector endpoint")]
    NotListening,
    #[error(
        "the connector closed the connection without answering (key, caller or frame not accepted)"
    )]
    ClosedWithoutAnswer,
    #[error("the connection key file is empty or longer than {MAX_KEY_BYTES} bytes")]
    KeyLength,
    #[error("the connection key is not usable as a key (surrounding whitespace?)")]
    KeyUnusable,
    #[error("the request is invalid for the connector contract")]
    Request,
    #[error("timed out waiting for the connector")]
    Timeout,
    #[error("the connector connection failed: {0}")]
    Connection(std::io::ErrorKind),
    #[error("the connector answer was not accepted (wrong key, caller or tampered frame): {0}")]
    Transport(model_connector::ServiceError),
    #[error("the request exceeded a frame bound")]
    FrameSize,
    #[error("the connector refused the request: {0:?}")]
    Refused(model_connector::Refusal),
    #[error("the provider failed: {0:?}")]
    Failed(FailureKind),
    #[error("the answer stopped as {0:?}, not a completed text")]
    NotCompleted(StopReason),
    #[error("the answer carried a tool call, which this command never requests")]
    ToolCall,
    #[error("the answer is empty")]
    EmptyAnswer,
}

enum ReadFailure {
    Unreadable,
    NotRegular,
    TooLarge,
    Exposed,
}

/// Opens `path` without blocking (a FIFO must not hang the open), requires the
/// opened file to be a regular file (a symlink is followed and its target
/// judged), optionally refuses one readable by group or world, and reads at
/// most `cap` bytes, failing if there are more.
fn read_regular(path: &Path, cap: usize, private: bool) -> Result<Zeroizing<Vec<u8>>, ReadFailure> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| ReadFailure::Unreadable)?;
    let metadata = file.metadata().map_err(|_| ReadFailure::Unreadable)?;
    if !metadata.is_file() {
        return Err(ReadFailure::NotRegular);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && metadata.permissions().mode() & 0o077 != 0 {
            return Err(ReadFailure::Exposed);
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadFailure::Unreadable)?;
    if bytes.len() > cap {
        return Err(ReadFailure::TooLarge);
    }
    Ok(bytes)
}

/// Reads the key as the connector reads its own key file (the text without the
/// trailing line ending). The bytes are zeroized on drop and never shown.
pub fn read_key(path: &Path) -> Result<Zeroizing<String>, AskError> {
    let raw = read_regular(path, MAX_KEY_BYTES, true).map_err(|failure| match failure {
        ReadFailure::Unreadable => AskError::KeyUnreadable,
        ReadFailure::NotRegular => AskError::KeyNotRegular,
        ReadFailure::TooLarge => AskError::KeyLength,
        ReadFailure::Exposed => AskError::KeyExposed,
    })?;
    let text = std::str::from_utf8(raw.as_slice()).map_err(|_| AskError::KeyEncoding)?;
    let key = Zeroizing::new(text.trim_end_matches(['\r', '\n']).to_string());
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(AskError::KeyLength);
    }
    if key.trim() != key.as_str() {
        return Err(AskError::KeyUnusable);
    }
    Ok(key)
}

/// The instructions file: a regular file of at most [`MAX_SYSTEM_BYTES`] of text.
pub fn read_system_file(path: &Path) -> Result<String, AskError> {
    let raw = read_regular(path, MAX_SYSTEM_BYTES, false).map_err(|failure| match failure {
        ReadFailure::TooLarge => AskError::SystemTooLarge,
        _ => AskError::SystemUnreadable,
    })?;
    String::from_utf8(raw.to_vec()).map_err(|_| AskError::SystemUnreadable)
}

fn fresh_id(prefix: &str) -> String {
    let mut nonce = [0_u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}")
}

/// The one invocation `ask` ever sends: instructions, one user text, no tools.
pub fn build_invocation(args: &AskArgs) -> Result<TransportInvocation, AskError> {
    if args.prompt.trim().is_empty() {
        return Err(AskError::EmptyPrompt);
    }
    if args.prompt.len() > PAYLOAD_BYTES {
        return Err(AskError::PromptTooLarge);
    }
    if args.instructions.trim().is_empty() {
        return Err(AskError::EmptyInstructions);
    }
    let mut request = ProviderRequest::new(
        fresh_id("ask"),
        fresh_id("ask-conversation"),
        args.model.clone(),
        args.instructions.clone(),
        args.max_output_tokens,
    );
    request.input = vec![InputItem::UserText {
        text: args.prompt.clone(),
    }];
    request.reasoning_effort = args.effort;
    let digest = provider_request_sha256(&request).map_err(|_| AskError::Request)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let invocation =
        TransportInvocation::new(args.caller_id.clone(), now + 120_000, digest, request)
            .map_err(|_| AskError::Request)?;
    invocation
        .validate(now, 300_000)
        .map_err(|_| AskError::Request)?;
    Ok(invocation)
}

/// The answer text of a result, or the one cause it is not an answer.
pub fn answer_text(result: &TransportResult) -> Result<String, AskError> {
    let (events, receipt) = match &result.disposition {
        TransportDisposition::Refused(reason) => return Err(AskError::Refused(reason.clone())),
        TransportDisposition::Transported { events, receipt } => (events, receipt),
    };
    match &receipt.outcome {
        TransportOutcome::Failed { kind, .. } => return Err(AskError::Failed(*kind)),
        TransportOutcome::Completed { stop_reason, .. } => {
            if !matches!(stop_reason, StopReason::EndTurn | StopReason::StopSequence) {
                return Err(AskError::NotCompleted(*stop_reason));
            }
        }
    }
    let mut text = String::new();
    for event in events {
        match &event.payload {
            TransportEventPayload::TextDelta { text: delta } => text.push_str(delta),
            TransportEventPayload::ToolCall { .. } => return Err(AskError::ToolCall),
            TransportEventPayload::ReasoningState { .. } => {}
        }
    }
    if text.trim().is_empty() {
        return Err(AskError::EmptyAnswer);
    }
    Ok(text)
}

pub fn ask(args: &AskArgs) -> Result<String, AskError> {
    let invocation = build_invocation(args)?;
    let key = read_key(&args.key_file)?;
    let client = ConnectorClient::new(
        args.endpoint,
        key.as_str(),
        frame_bytes_for_payload(PAYLOAD_BYTES),
        Some(args.timeout),
    )
    .map_err(|error| match error {
        ConnectorClientError::Transport(_) => AskError::KeyUnusable,
        _ => AskError::Request,
    })?;
    let result = client.execute(&invocation).map_err(|error| match error {
        ConnectorClientError::Connection(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            AskError::Timeout
        }
        ConnectorClientError::Connection(io) => match io.kind() {
            std::io::ErrorKind::ConnectionRefused => AskError::NotListening,
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe => AskError::ClosedWithoutAnswer,
            kind => AskError::Connection(kind),
        },
        ConnectorClientError::Transport(error) => AskError::Transport(error),
        ConnectorClientError::FrameSize => AskError::FrameSize,
        ConnectorClientError::InvalidConfig | ConnectorClientError::RequestIdTooLong => {
            AskError::Request
        }
    })?;
    answer_text(&result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClaudeCodeConfig, ClaudeCodeLimits};
    use crate::handle::{SessionStore, plan};
    use model_connector::ToolDefinition;

    struct NoSessions;
    impl SessionStore for NoSessions {
        fn exists(&self, _: &str) -> bool {
            false
        }
    }

    fn args() -> AskArgs {
        AskArgs {
            endpoint: DEFAULT_ENDPOINT.parse().unwrap(),
            caller_id: "c".into(),
            key_file: "/nonexistent".into(),
            model: "m".into(),
            instructions: "i".into(),
            effort: None,
            max_output_tokens: 16,
            timeout: Duration::from_secs(1),
            prompt: "p".into(),
        }
    }

    /// The claude backend's own planner accepts what `ask` builds and refuses
    /// the same request once a tool is forced into it.
    #[test]
    fn the_backend_planner_refuses_a_forced_tool_and_accepts_the_asked_request() {
        let config = ClaudeCodeConfig {
            claude_binary: "/claude".into(),
            claude_binary_sha256: [0; 32],
            work_dir: "/w".into(),
            config_dir: "/c".into(),
            prompt_dir: "/p".into(),
            token_credential: "t".into(),
            handle_secret_credential: "h".into(),
            instance: "i".into(),
            limits: ClaudeCodeLimits {
                deadline: Duration::from_secs(1),
                max_line_bytes: 1024,
                max_total_bytes: 4096,
                stderr_tail_bytes: 64,
            },
        };
        let mut request = build_invocation(&args()).unwrap().request;
        let secret = [7_u8; 32];
        assert!(plan(&request, &config, &secret, "c", &NoSessions).is_ok());
        request.tools.push(ToolDefinition {
            name: "t".into(),
            description: "d".into(),
            parameters_json: "{}".into(),
        });
        assert!(plan(&request, &config, &secret, "c", &NoSessions).is_err());
    }
}
