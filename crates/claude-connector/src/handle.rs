//! The reasoning state of this backend and the decision it drives: resume the
//! CLI session a handle names, or start a fresh one seeded with the caller's
//! transcript. The session is a cache of the caller's transcript; the
//! transcript is the truth.

use std::path::PathBuf;

use hmac::{Hmac, Mac};
use model_connector::{InputItem, ProviderRequest};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::{ClaudeCodeConfig, PROVIDER};

/// The state this backend hands a caller inside `ReasoningState`. A new
/// variant is a new version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum ClaudeCodeHandle {
    /// The session a finished turn left behind. `prefix_sha256` is the
    /// HMAC-SHA-256, keyed with the connector's handle secret, of the caller
    /// that minted the handle, the instructions, the model, this session and
    /// instance, and every transcript item that precedes this handle. Another caller, or anyone
    /// without the secret, cannot produce or satisfy it.
    Ended {
        session_id: String,
        instance: String,
        prefix_sha256: [u8; 32],
    },
}

impl ClaudeCodeHandle {
    pub(crate) fn encode(&self) -> Vec<u8> {
        rmp_serde::to_vec_named(self).expect("a handle of strings and bytes encodes")
    }

    fn decode(state: &[u8]) -> Option<Self> {
        rmp_serde::from_slice(state).ok()
    }
}

/// The smallest handle secret the connector accepts, in bytes.
pub const MIN_SECRET_BYTES: usize = 32;

/// Everything a handle's tag binds: the minting caller, the instructions, the
/// model, the session and instance the handle names, and the transcript items
/// before the handle. Swapping any of them into a valid handle breaks the tag.
pub(crate) struct Binding<'a> {
    pub(crate) caller: &'a str,
    pub(crate) instructions: &'a str,
    pub(crate) model: &'a str,
    pub(crate) session_id: &'a str,
    pub(crate) instance: &'a str,
    pub(crate) items: &'a [InputItem],
}

fn prefix_mac(secret: &[u8], binding: &Binding<'_>) -> Hmac<Sha256> {
    let bytes = rmp_serde::to_vec_named(&(
        binding.caller,
        binding.instructions,
        binding.model,
        binding.session_id,
        binding.instance,
        binding.items,
    ))
    .expect("strings and bytes encode");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("an HMAC key has any length");
    mac.update(&bytes);
    mac
}

/// The tag a handle carries: keyed named MessagePack of its [`Binding`].
pub(crate) fn prefix_digest(secret: &[u8], binding: &Binding<'_>) -> [u8; 32] {
    prefix_mac(secret, binding).finalize().into_bytes().into()
}

fn prefix_matches(secret: &[u8], binding: &Binding<'_>, tag: &[u8; 32]) -> bool {
    prefix_mac(secret, binding).verify_slice(tag).is_ok()
}

/// Whether the CLI's session store still holds a session.
pub trait SessionStore: Send + Sync {
    fn exists(&self, session_id: &str) -> bool;
}

/// Looks for `<config_dir>/projects/*/<session_id>.jsonl`. A session id that
/// is not a canonical UUID never names a path.
pub struct FsSessionStore {
    config_dir: PathBuf,
}

impl FsSessionStore {
    pub fn new(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }
}

fn is_canonical_uuid(id: &str) -> bool {
    id.len() == 36
        && id.char_indices().all(|(at, c)| match at {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
        })
}

impl SessionStore for FsSessionStore {
    fn exists(&self, session_id: &str) -> bool {
        if !is_canonical_uuid(session_id) {
            return false;
        }
        let Ok(projects) = std::fs::read_dir(self.config_dir.join("projects")) else {
            return false;
        };
        projects
            .flatten()
            .any(|project| project.path().join(format!("{session_id}.jsonl")).is_file())
    }
}

/// Why a request cannot be answered by this backend; the text is the failure
/// message and names what lifts it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PlanError {
    #[error("claude-code: tools are not supported by this backend yet")]
    Tools,
    #[error("claude-code: tool results are not supported by this backend yet")]
    ToolResult,
    #[error("claude-code: the request ends without user text")]
    NoUserText,
    #[error("claude-code: the request carries a reasoning state this backend cannot read")]
    UndecodableHandle,
}

/// How a call reaches the CLI. `blocks` are the text blocks of the one user
/// message the child is given.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    Resume {
        session_id: String,
        blocks: Vec<String>,
    },
    Seed {
        blocks: Vec<String>,
    },
}

impl Plan {
    pub(crate) fn blocks(&self) -> &[String] {
        match self {
            Plan::Resume { blocks, .. } | Plan::Seed { blocks } => blocks,
        }
    }
}

pub(crate) fn plan(
    request: &ProviderRequest,
    config: &ClaudeCodeConfig,
    secret: &[u8],
    caller: &str,
    sessions: &dyn SessionStore,
) -> Result<Plan, PlanError> {
    if !request.tools.is_empty() {
        return Err(PlanError::Tools);
    }
    let input = &request.input;
    let run_start = input
        .iter()
        .rposition(|item| {
            !matches!(
                item,
                InputItem::UserText { .. } | InputItem::ToolResult { .. }
            )
        })
        .map_or(0, |at| at + 1);
    let run = &input[run_start..];
    if run
        .iter()
        .any(|item| matches!(item, InputItem::ToolResult { .. }))
    {
        return Err(PlanError::ToolResult);
    }
    let user_blocks: Vec<String> = run
        .iter()
        .filter_map(|item| match item {
            InputItem::UserText { text } => Some(text.clone()),
            _ => None,
        })
        .collect();
    if user_blocks.is_empty() {
        return Err(PlanError::NoUserText);
    }

    let last_own = input.iter().rposition(
        |item| matches!(item, InputItem::ReasoningState { provider, .. } if provider == PROVIDER),
    );
    if let Some(at) = last_own {
        let InputItem::ReasoningState { state, .. } = &input[at] else {
            unreachable!("rposition matched a reasoning state");
        };
        let Some(ClaudeCodeHandle::Ended {
            session_id,
            instance,
            prefix_sha256,
        }) = ClaudeCodeHandle::decode(state)
        else {
            return Err(PlanError::UndecodableHandle);
        };
        let tail_is_user_text = input[at + 1..]
            .iter()
            .all(|item| matches!(item, InputItem::UserText { .. }));
        let resumable = instance == config.instance
            && tail_is_user_text
            && prefix_matches(
                secret,
                &Binding {
                    caller,
                    instructions: &request.instructions,
                    model: &request.model,
                    session_id: &session_id,
                    instance: &instance,
                    items: &input[..at],
                },
                &prefix_sha256,
            )
            && sessions.exists(&session_id);
        if resumable {
            return Ok(Plan::Resume {
                session_id,
                blocks: user_blocks,
            });
        }
    }

    let mut blocks = Vec::new();
    if let Some(transcript) = render_transcript(&input[..run_start]) {
        blocks.push(transcript);
    }
    blocks.extend(user_blocks);
    Ok(Plan::Seed { blocks })
}

/// The earlier conversation as one deterministic text, or `None` when nothing
/// of it is renderable. Reasoning states are omitted.
fn render_transcript(items: &[InputItem]) -> Option<String> {
    let groups: Vec<String> = items
        .iter()
        .filter_map(|item| match item {
            InputItem::UserText { text } => Some(format!("[user]\n{text}")),
            InputItem::AssistantText { text } => Some(format!("[assistant]\n{text}")),
            InputItem::ToolCall {
                call_id,
                name,
                arguments,
            } => Some(format!("[tool_call name={name} id={call_id}]\n{arguments}")),
            InputItem::ToolResult { call_id, output } => {
                Some(format!("[tool_result id={call_id}]\n{output}"))
            }
            InputItem::ReasoningState { .. } => None,
        })
        .collect();
    if groups.is_empty() {
        return None;
    }
    Some(format!(
        "The conversation so far, replayed as text because the earlier session cannot be continued:\n\n{}",
        groups.join("\n\n")
    ))
}

#[derive(Serialize)]
struct UserLine<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    message: UserMessage<'a>,
    parent_tool_use_id: Option<&'a str>,
}

#[derive(Serialize)]
struct UserMessage<'a> {
    role: &'static str,
    content: Vec<TextBlock<'a>>,
}

#[derive(Serialize)]
struct TextBlock<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    text: &'a str,
}

/// The child's whole stdin: exactly one stream-json user line. Several lines
/// would queue several turns.
pub(crate) fn stdin_bytes(blocks: &[String]) -> Vec<u8> {
    let line = UserLine {
        kind: "user",
        message: UserMessage {
            role: "user",
            content: blocks
                .iter()
                .map(|text| TextBlock { kind: "text", text })
                .collect(),
        },
        parent_tool_use_id: None,
    };
    let mut bytes = serde_json::to_vec(&line).expect("typed strings encode");
    bytes.push(b'\n');
    bytes
}
