//! Reading the CLI's stream-json output. The format is foreign and moves with
//! the CLI, so every struct here ignores fields it does not name.

use std::collections::BTreeMap;

use model_connector::{FailureKind, PlanQuota, StopReason, Usage};
use serde::Deserialize;
use serde_json::Value;

use crate::quota::QuotaCell;

/// The tool the CLI gives the model to deliver an answer that must match a
/// `--json-schema`. Its call is the structured output, not a tool exchange.
const STRUCTURED_OUTPUT_TOOL: &str = "StructuredOutput";

/// A call that cannot complete, with the stage that failed. `usage` is `None`
/// (unknown) unless a result event reported it or the
/// call never reached the provider (zero).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub kind: FailureKind,
    pub message: &'static str,
    pub usage: Option<Usage>,
}

impl Failure {
    /// A failure after the child ran: what the provider billed is unknown, so
    /// the usage is unknown.
    pub(crate) fn cost_unknown(kind: FailureKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            usage: None,
        }
    }

    /// A failure before anything was sent to the provider: it bills nothing.
    pub(crate) fn never_reached(kind: FailureKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            usage: Some(sum_usage(std::iter::empty())),
        }
    }
}

/// What the stream said, once its result event arrived.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Finished {
    pub session_id: String,
    /// The non-empty text blocks, in order.
    pub texts: Vec<String>,
    /// The id of the last assistant message.
    pub message_id: Option<String>,
    pub stop_reason: StopReason,
    pub usage: Usage,
}

pub(crate) enum Step {
    More,
    Done(Box<Result<Finished, Failure>>),
}

#[derive(Deserialize)]
struct Line {
    #[serde(rename = "type")]
    kind: String,
    subtype: Option<String>,
    session_id: Option<String>,
    model: Option<String>,
    message: Option<Message>,
    /// Read by hand: the shape moves with the CLI, and a field that changes
    /// type must cost the quota reading, never the call.
    rate_limit_info: Option<Value>,
    is_error: Option<bool>,
    stop_reason: Option<String>,
    api_error_status: Option<Value>,
    /// Milliseconds spent in API calls; zero means no call was made.
    duration_api_ms: Option<u64>,
    result: Option<Value>,
    errors: Option<Value>,
    /// The answer to a `--json-schema` request, an object.
    structured_output: Option<Value>,
    /// What this turn alone consumed. `modelUsage` is deliberately not read:
    /// on a resumed session it carries every earlier turn too.
    model_usage_since_last_result: Option<Value>,
}

#[derive(Deserialize)]
struct Message {
    id: Option<String>,
    content: Option<Vec<Block>>,
}

#[derive(Deserialize)]
struct Block {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
    name: Option<String>,
}

/// One model's entry. The four counts are required: an entry that lacks one
/// is a shape this reader does not know, and unknown usage is never zero.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelUsage {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
    cache_creation_input_tokens: u64,
    thinking_tokens: Option<u64>,
}

/// One call's stream, line by line.
pub(crate) struct StreamState<'a> {
    model: &'a str,
    /// Whether the request carried an output schema, so the answer is the
    /// result's structured output.
    structured: bool,
    /// Whether that schema's top type admits an object (absent counts): the
    /// structured output must be an object, never a bare scalar or array.
    schema_top_is_object: bool,
    quota: &'a QuotaCell,
    session_id: Option<String>,
    texts: Vec<String>,
    message_id: Option<String>,
    plan_rejected: bool,
}

impl<'a> StreamState<'a> {
    /// `schema` is the request's output schema text, when it carried one.
    pub(crate) fn new(model: &'a str, schema: Option<&str>, quota: &'a QuotaCell) -> Self {
        let top = schema
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .and_then(|schema| schema.get("type").cloned());
        Self {
            model,
            structured: schema.is_some(),
            schema_top_is_object: top.is_none_or(|top| top.as_str() == Some("object")),
            quota,
            session_id: None,
            texts: Vec::new(),
            message_id: None,
            plan_rejected: false,
        }
    }

    pub(crate) fn feed(&mut self, raw: &[u8]) -> Step {
        let Ok(line) = serde_json::from_slice::<Line>(raw) else {
            return fail(
                FailureKind::Provider,
                "claude-code: a stream line did not parse",
            );
        };
        match line.kind.as_str() {
            "system" => match line.subtype.as_deref() {
                Some("init") => {
                    if line.model.as_deref() != Some(self.model) {
                        return fail(
                            FailureKind::Provider,
                            "claude-code: the session model differs from the request",
                        );
                    }
                    self.session_id = line.session_id;
                    Step::More
                }
                Some("compact_boundary") => fail(
                    FailureKind::Provider,
                    "claude-code: the session was compacted",
                ),
                _ => Step::More,
            },
            "assistant" => self.assistant(line.message),
            "rate_limit_event" => {
                if let Some(info) = &line.rate_limit_info {
                    self.plan_rejected |=
                        info.get("status").and_then(Value::as_str) == Some("rejected");
                    self.quota.observe(plan_windows(info));
                }
                Step::More
            }
            "result" => Step::Done(Box::new(self.result(line))),
            _ => Step::More,
        }
    }

    fn assistant(&mut self, message: Option<Message>) -> Step {
        let Some(message) = message else {
            return Step::More;
        };
        if message.id.is_some() {
            self.message_id = message.id;
        }
        for block in message.content.unwrap_or_default() {
            match block.kind.as_str() {
                "text" => {
                    if let Some(text) = block.text.filter(|text| !text.is_empty()) {
                        self.texts.push(text);
                    }
                }
                "tool_use"
                    if self.structured && block.name.as_deref() == Some(STRUCTURED_OUTPUT_TOOL) => {
                }
                "tool_use" => {
                    return fail(
                        FailureKind::Provider,
                        "claude-code: the model called a tool in a tool-less turn",
                    );
                }
                _ => {}
            }
        }
        Step::More
    }

    fn result(&mut self, line: Line) -> Result<Finished, Failure> {
        let success = line.subtype.as_deref() == Some("success") && line.is_error == Some(false);
        let door_refusal = !success
            && matches!(
                line.api_error_status.as_ref().and_then(Value::as_u64),
                Some(401 | 403 | 429)
            );
        // The CLI found no credential and never called the API: an error with
        // no status and no API time at all.
        let no_call = !success
            && line.duration_api_ms == Some(0)
            && line.api_error_status.as_ref().is_none_or(Value::is_null);
        let usage = read_usage(
            line.model_usage_since_last_result,
            door_refusal || no_call,
            no_call,
        );
        if !success {
            return Err(Failure {
                kind: self.error_kind(&line.api_error_status, &line.result, &line.errors),
                message: "claude-code: the result reported an error",
                usage,
            });
        }
        let Some(usage) = usage else {
            return Err(Failure {
                kind: FailureKind::Provider,
                message: "claude-code: the result did not report usable usage",
                usage: None,
            });
        };
        let mut texts = std::mem::take(&mut self.texts);
        if self.structured {
            // The answer is the structured output alone; any prose around the
            // tool call is not part of it.
            let Some(output) = line
                .structured_output
                .filter(|value| value.is_object() && self.schema_top_is_object)
            else {
                return Err(Failure {
                    kind: FailureKind::Provider,
                    message: "claude-code: a schema was sent and the result carried no structured output object",
                    usage: Some(usage),
                });
            };
            texts = vec![output.to_string()];
        }
        let stop_reason = match line.stop_reason.as_deref() {
            Some("end_turn") => StopReason::EndTurn,
            // The structured-output tool call is how such a turn ends.
            Some("tool_use") if self.structured => StopReason::EndTurn,
            Some("max_tokens") => StopReason::MaxOutputTokens,
            Some("stop_sequence") => StopReason::StopSequence,
            Some("refusal") => StopReason::Refusal,
            Some("model_context_window_exceeded") => StopReason::ContextWindow,
            _ => {
                return Err(Failure {
                    kind: FailureKind::Provider,
                    message: "claude-code: the result has an unknown stop reason",
                    usage: Some(usage),
                });
            }
        };
        let Some(session_id) = self.session_id.take() else {
            return Err(Failure {
                kind: FailureKind::Provider,
                message: "claude-code: the stream never announced its session",
                usage: Some(usage),
            });
        };
        Ok(Finished {
            session_id,
            texts,
            message_id: self.message_id.take(),
            stop_reason,
            usage,
        })
    }

    fn error_kind(
        &self,
        status: &Option<Value>,
        result: &Option<Value>,
        errors: &Option<Value>,
    ) -> FailureKind {
        let status = status.as_ref().and_then(Value::as_u64);
        let names_rate_limit = [result, errors].into_iter().flatten().any(|value| {
            let text = value.to_string().to_lowercase();
            text.contains("rate limit") || text.contains("rate_limit")
        });
        match status {
            _ if self.plan_rejected || names_rate_limit || status == Some(429) => {
                FailureKind::RateLimited
            }
            Some(401 | 403) => FailureKind::Authentication,
            Some(400) => FailureKind::InvalidRequest,
            Some(500..=599) => FailureKind::Unavailable,
            _ => FailureKind::Provider,
        }
    }
}

/// The plan windows one `rate_limit_event` reports under
/// `rate_limit_info.unifiedWindows`: utilization as a fraction of the window,
/// reset as unix seconds. A window missing any of its three fields is skipped;
/// an unknown reading is never zero.
fn plan_windows(info: &Value) -> Vec<PlanQuota> {
    let Some(windows) = info.get("unifiedWindows").and_then(Value::as_object) else {
        return Vec::new();
    };
    windows
        .iter()
        .filter_map(|(window, reading)| {
            let utilization = reading.get("utilization")?.as_f64()?;
            let resets_at = reading.get("resetsAt")?.as_u64()?;
            let status = reading.get("status")?.as_str()?;
            if !utilization.is_finite() || utilization < 0.0 {
                return None;
            }
            Some(PlanQuota {
                window: window.clone(),
                // `as` saturates a float at the integer's bounds.
                utilization_permille: Some((utilization * 1000.0).round() as u32),
                resets_at_unix_ms: resets_at.saturating_mul(1000),
                status: status.to_string(),
                // Stamped by the cell that keeps it.
                observed_at_unix_ms: 0,
            })
        })
        .collect()
}

fn fail(kind: FailureKind, message: &'static str) -> Step {
    Step::Done(Box::new(Err(Failure::cost_unknown(kind, message))))
}

/// What this turn consumed, summed over every model it used (harness side
/// calls included), or `None` when the result does not say: the field absent,
/// of another shape, or empty. An empty report is believed only where the
/// provider cannot have billed (`empty_is_zero`: a refusal at the door, 401,
/// 403 or 429, or a call never made); elsewhere the CLI also zeroes usage on
/// crashes after real work. A call never made (`absent_is_zero`) may also
/// omit the field. `None` is unknown usage.
fn read_usage(reported: Option<Value>, empty_is_zero: bool, absent_is_zero: bool) -> Option<Usage> {
    let Some(reported) = reported else {
        return absent_is_zero.then(|| sum_usage(std::iter::empty()));
    };
    let models: BTreeMap<String, ModelUsage> = serde_json::from_value(reported).ok()?;
    if models.is_empty() {
        return empty_is_zero.then(|| sum_usage(std::iter::empty()));
    }
    Some(sum_usage(models.into_values()))
}

fn sum_usage(models: impl Iterator<Item = ModelUsage>) -> Usage {
    let mut usage = Usage {
        input_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        output_tokens: 0,
        reasoning_tokens: None,
    };
    for model in models {
        usage.input_tokens = usage.input_tokens.saturating_add(model.input_tokens);
        usage.cache_read_tokens = usage
            .cache_read_tokens
            .saturating_add(model.cache_read_input_tokens);
        usage.cache_write_tokens = usage
            .cache_write_tokens
            .saturating_add(model.cache_creation_input_tokens);
        usage.output_tokens = usage.output_tokens.saturating_add(model.output_tokens);
        if let Some(thinking) = model.thinking_tokens {
            usage.reasoning_tokens =
                Some(usage.reasoning_tokens.unwrap_or(0).saturating_add(thinking));
        }
    }
    usage
}
