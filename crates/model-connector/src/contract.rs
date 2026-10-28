use std::collections::HashSet;

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::envelope::ServiceError;

pub const PROVIDER_REQUEST_SCHEMA_ID: &str = "gamecult.model.provider_request.v3";
pub const INVOCATION_SCHEMA_ID: &str = "gamecult.model.transport_invocation.v3";
pub const RESULT_SCHEMA_ID: &str = "gamecult.model.transport_result.v3";
pub const RECEIPT_SCHEMA_ID: &str = "gamecult.model.transport_receipt.v3";
pub const ENVELOPE_SCHEMA_ID: &str = "gamecult.model.transport_envelope.v3";

#[derive(Clone, PartialEq, Eq)]
pub struct TransportKey(pub(crate) [u8; 32]);

impl TransportKey {
    pub fn from_connection_secret(secret: &str) -> Result<Self, ServiceError> {
        if secret.trim().is_empty() || secret.trim() != secret {
            return Err(ServiceError::InvalidAdmission);
        }
        Ok(Self(Sha256::digest(secret.as_bytes()).into()))
    }
}

impl Drop for TransportKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    pub schema_id: String,
    pub request_id: String,
    pub conversation_id: String,
    pub model: String,
    pub instructions: String,
    pub input: Vec<InputItem>,
    pub reasoning_effort: Option<ReasoningEffort>,
    pub cache_retention: Option<CacheRetention>,
    pub tools: Vec<ToolDefinition>,
    pub tool_choice: ToolChoice,
    pub parallel_tool_calls: bool,
    pub output_schema_json: Option<String>,
    pub max_output_tokens: u32,
}

impl ProviderRequest {
    pub fn new(
        request_id: impl Into<String>,
        conversation_id: impl Into<String>,
        model: impl Into<String>,
        instructions: impl Into<String>,
        max_output_tokens: u32,
    ) -> Self {
        Self {
            schema_id: PROVIDER_REQUEST_SCHEMA_ID.to_string(),
            request_id: request_id.into(),
            conversation_id: conversation_id.into(),
            model: model.into(),
            instructions: instructions.into(),
            input: Vec::new(),
            reasoning_effort: None,
            cache_retention: None,
            tools: Vec::new(),
            tool_choice: ToolChoice::Auto,
            parallel_tool_calls: false,
            output_schema_json: None,
            max_output_tokens,
        }
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_id != PROVIDER_REQUEST_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        require_id(&self.request_id, "request_id")?;
        require_id(&self.conversation_id, "conversation_id")?;
        require_id(&self.model, "model")?;
        require_content(&self.instructions, "instructions")?;
        if self.max_output_tokens == 0 {
            return Err(ContractError::Invalid("max_output_tokens"));
        }
        if let Some(schema) = &self.output_schema_json {
            require_content(schema, "output_schema_json")?;
            require_json_object(schema, "output_schema_json")?;
        }

        if self.tools.is_empty() && self.tool_choice == ToolChoice::Required {
            return Err(ContractError::Invalid("tool_choice"));
        }

        let mut tool_names = HashSet::new();
        for tool in &self.tools {
            require_provider_name(&tool.name, "tool.name")?;
            require_content(&tool.description, "tool.description")?;
            require_content(&tool.parameters_json, "tool.parameters_json")?;
            require_json_object(&tool.parameters_json, "tool.parameters_json")?;
            if !tool_names.insert(tool.name.as_str()) {
                return Err(ContractError::DuplicateTool(tool.name.clone()));
            }
        }
        for item in &self.input {
            match item {
                InputItem::UserText { text } | InputItem::AssistantText { text } => {
                    require_content(text, "input.text")?;
                }
                InputItem::ToolCall {
                    call_id,
                    name,
                    arguments,
                } => {
                    require_provider_call_id(call_id, "input.call_id")?;
                    require_provider_name(name, "input.tool_name")?;
                    require_content(arguments, "input.arguments")?;
                }
                InputItem::ToolResult { call_id, output } => {
                    require_provider_call_id(call_id, "input.call_id")?;
                    require_content(output, "input.output")?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolChoice {
    Auto,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CacheRetention {
    Short,
    Long,
}

/// Why a provider stopped producing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxOutputTokens,
    StopSequence,
    Refusal,
    ContextWindow,
}

/// What kind of failure a provider reported. `ResultSize` is the connector's own
/// stand-in for a result whose sealed frame cannot be carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    ResultSize,
    InvalidRequest,
    Authentication,
    RateLimited,
    Unavailable,
    Timeout,
    Provider,
}

/// Token accounting for one completed request. Cache reads and writes are
/// counted apart from plain input; `reasoning_tokens` is absent when the
/// provider does not report it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum InputItem {
    UserText {
        text: String,
    },
    AssistantText {
        text: String,
    },
    ToolCall {
        call_id: String,
        name: String,
        arguments: String,
    },
    ToolResult {
        call_id: String,
        output: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransportInvocation {
    pub schema_id: String,
    pub caller_runtime_id: String,
    pub expires_at_unix_ms: u64,
    pub native_request_sha256: [u8; 32],
    pub provider_request_sha256: [u8; 32],
    pub request: ProviderRequest,
}

impl TransportInvocation {
    pub fn new(
        caller_runtime_id: impl Into<String>,
        expires_at_unix_ms: u64,
        native_request_sha256: [u8; 32],
        request: ProviderRequest,
    ) -> Result<Self, ContractError> {
        let provider_request_sha256 = provider_request_sha256(&request)?;
        Ok(Self {
            schema_id: INVOCATION_SCHEMA_ID.to_string(),
            caller_runtime_id: caller_runtime_id.into(),
            expires_at_unix_ms,
            native_request_sha256,
            provider_request_sha256,
            request,
        })
    }

    pub fn validate(&self, now_unix_ms: u64, max_expiry_skew_ms: u64) -> Result<(), ContractError> {
        if self.schema_id != INVOCATION_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        require_id(&self.caller_runtime_id, "caller_runtime_id")?;
        if self.native_request_sha256 == [0; 32] {
            return Err(ContractError::Invalid("native_request_sha256"));
        }
        self.request.validate()?;
        if self.provider_request_sha256 != provider_request_sha256(&self.request)? {
            return Err(ContractError::ProviderDigest);
        }
        if self.expires_at_unix_ms < now_unix_ms
            || self.expires_at_unix_ms > now_unix_ms.saturating_add(max_expiry_skew_ms)
        {
            return Err(ContractError::Expiry);
        }
        Ok(())
    }

    pub fn request_id(&self) -> &str {
        &self.request.request_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransportResult {
    pub schema_id: String,
    pub request_id: String,
    pub caller_runtime_id: String,
    pub disposition: TransportDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum TransportDisposition {
    Refused(Refusal),
    Transported {
        events: Vec<TransportEvent>,
        receipt: Box<TransportReceipt>,
    },
}

impl TransportResult {
    pub fn refused(invocation: &TransportInvocation, reason: Refusal) -> Self {
        Self {
            schema_id: RESULT_SCHEMA_ID.to_string(),
            request_id: invocation.request_id().to_string(),
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            disposition: TransportDisposition::Refused(reason),
        }
    }

    pub fn transported(
        invocation: &TransportInvocation,
        events: Vec<TransportEvent>,
        receipt: TransportReceipt,
    ) -> Self {
        Self {
            schema_id: RESULT_SCHEMA_ID.to_string(),
            request_id: invocation.request_id().to_string(),
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            disposition: TransportDisposition::Transported {
                events,
                receipt: Box::new(receipt),
            },
        }
    }

    pub fn validate_against(&self, invocation: &TransportInvocation) -> Result<(), ContractError> {
        if self.schema_id != RESULT_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        if self.request_id != invocation.request_id()
            || self.caller_runtime_id != invocation.caller_runtime_id
        {
            return Err(ContractError::Identity);
        }

        if let TransportDisposition::Transported { events, receipt } = &self.disposition {
            for (expected, event) in events.iter().enumerate() {
                if event.sequence != expected as u64 {
                    return Err(ContractError::EventSequence);
                }
                event.validate()?;
            }
            receipt.validate_against(invocation)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum TransportEventPayload {
    TextDelta {
        text: String,
    },
    ToolCall {
        call_id: String,
        name: String,
        arguments: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransportEvent {
    pub sequence: u64,
    pub payload: TransportEventPayload,
}

impl TransportEvent {
    fn validate(&self) -> Result<(), ContractError> {
        match &self.payload {
            TransportEventPayload::TextDelta { text } => require_content(text, "event.text"),
            TransportEventPayload::ToolCall {
                call_id,
                name,
                arguments,
            } => {
                require_id(call_id, "event.call_id")?;
                require_id(name, "event.tool_name")?;
                require_content(arguments, "event.arguments")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransportReceipt {
    pub schema_id: String,
    pub request_id: String,
    pub caller_runtime_id: String,
    pub native_request_sha256: [u8; 32],
    pub provider_request_sha256: [u8; 32],
    pub model: String,
    pub provider: String,
    pub outcome: TransportOutcome,
}

impl TransportReceipt {
    pub fn validate_against(&self, invocation: &TransportInvocation) -> Result<(), ContractError> {
        if self.schema_id != RECEIPT_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        if self.request_id != invocation.request_id()
            || self.caller_runtime_id != invocation.caller_runtime_id
            || self.model != invocation.request.model
        {
            return Err(ContractError::Identity);
        }
        if self.provider_request_sha256 != invocation.provider_request_sha256 {
            return Err(ContractError::ProviderDigest);
        }
        if self.native_request_sha256 != invocation.native_request_sha256 {
            return Err(ContractError::NativeDigest);
        }
        require_id(&self.provider, "receipt.provider")?;
        match &self.outcome {
            TransportOutcome::Completed {
                provider_response_id: Some(value),
                ..
            } => require_id(value, "receipt.provider_response_id")?,
            TransportOutcome::Failed { message, .. } => {
                require_content(message, "receipt.failure_message")?;
            }
            TransportOutcome::Completed {
                provider_response_id: None,
                ..
            } => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum TransportOutcome {
    Completed {
        provider_response_id: Option<String>,
        stop_reason: StopReason,
        usage: Usage,
    },
    Failed {
        kind: FailureKind,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Refusal {
    Expired,
    IdentitySubstitution,
    ProviderDigestSubstitution,
    ModelNotAllowed,
    OutputBound,
    PayloadBound,
    Capacity,
    InFlight,
    Indeterminate,
    ReplayConflict,
    Malformed,
}

/// The one wire codec of every v3 document: named MessagePack (struct fields
/// are keyed by name), with unknown fields refused by the types themselves.
pub(crate) fn wire_encode<T: Serialize + ?Sized>(document: &T) -> Result<Vec<u8>, ContractError> {
    rmp_serde::to_vec_named(document).map_err(|_| ContractError::Encoding)
}

pub(crate) fn wire_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ContractError> {
    rmp_serde::from_slice(bytes).map_err(|_| ContractError::Encoding)
}

pub fn canonical_provider_request_bytes(
    request: &ProviderRequest,
) -> Result<Vec<u8>, ContractError> {
    request.validate()?;
    wire_encode(request)
}

pub fn provider_request_sha256(request: &ProviderRequest) -> Result<[u8; 32], ContractError> {
    Ok(Sha256::digest(canonical_provider_request_bytes(request)?).into())
}

pub fn canonical_invocation_bytes(
    invocation: &TransportInvocation,
) -> Result<Vec<u8>, ContractError> {
    invocation.request.validate()?;
    if invocation.provider_request_sha256 != provider_request_sha256(&invocation.request)? {
        return Err(ContractError::ProviderDigest);
    }
    wire_encode(invocation)
}

pub(crate) fn require_id(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn require_content(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty() {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn require_json_object(value: &str, field: &'static str) -> Result<(), ContractError> {
    if !matches!(
        serde_json::from_str::<serde_json::Value>(value),
        Ok(serde_json::Value::Object(_))
    ) {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn require_provider_name(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn require_provider_call_id(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("unexpected schema")]
    Schema,
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("duplicate tool {0:?}")]
    DuplicateTool(String),
    #[error("request identity substitution")]
    Identity,
    #[error("provider request digest substitution")]
    ProviderDigest,
    #[error("native request digest substitution")]
    NativeDigest,
    #[error("invocation expiry is outside the admitted horizon")]
    Expiry,
    #[error("transport event sequence is not contiguous")]
    EventSequence,
    #[error("wire encoding failed")]
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fixtures::*;

    #[test]
    fn provider_digest_is_stable_and_content_addressed() {
        let original = request();
        let same = original.clone();
        assert_eq!(
            provider_request_sha256(&original).unwrap(),
            provider_request_sha256(&same).unwrap()
        );
        let mut changed = original.clone();
        changed.instructions.push_str(" Changed.");
        assert_ne!(
            provider_request_sha256(&original).unwrap(),
            provider_request_sha256(&changed).unwrap()
        );
    }

    #[test]
    fn provider_contract_refuses_transport_side_fixup_pressure() {
        let mut request = request();
        request.output_schema_json = Some(r#"{"type":"object"}"#.to_string());
        assert_eq!(request.validate(), Ok(()));
        request.output_schema_json = Some("[]".to_string());
        assert_eq!(
            request.validate(),
            Err(ContractError::Invalid("output_schema_json"))
        );

        request.output_schema_json = None;
        request.input.push(InputItem::ToolResult {
            call_id: "x".repeat(65),
            output: "evidence".to_string(),
        });
        assert_eq!(
            request.validate(),
            Err(ContractError::Invalid("input.call_id"))
        );
    }

    #[test]
    fn invocation_refuses_provider_request_substitution() {
        let mut invocation = invocation();
        invocation.request.model = "substituted".to_string();
        assert_eq!(
            invocation.validate(1_000, 2_000),
            Err(ContractError::ProviderDigest)
        );
    }

    #[test]
    fn invocation_refuses_expired_or_blank_native_provenance() {
        let mut invocation = invocation();
        assert_eq!(
            invocation.validate(2_001, 2_000),
            Err(ContractError::Expiry)
        );
        invocation.expires_at_unix_ms = 2_500;
        invocation.native_request_sha256 = [0; 32];
        assert_eq!(
            invocation.validate(2_001, 2_000),
            Err(ContractError::Invalid("native_request_sha256"))
        );
    }

    #[test]
    fn typed_tool_round_survives_messagepack() {
        let invocation = invocation();
        let bytes = wire_encode(&invocation).unwrap();
        let decoded: TransportInvocation = wire_decode(&bytes).unwrap();
        assert_eq!(decoded, invocation);
        assert!(matches!(
            decoded.request.tools.as_slice(),
            [ToolDefinition { name, .. }] if name == "read_source"
        ));
    }

    #[test]
    fn transported_result_binds_identity_digest_and_event_order() {
        let invocation = invocation();
        let result = TransportResult::transported(
            &invocation,
            vec![TransportEvent {
                sequence: 0,
                payload: TransportEventPayload::ToolCall {
                    call_id: "call-1".to_string(),
                    name: "read_source".to_string(),
                    arguments: "{}".to_string(),
                },
            }],
            receipt(&invocation),
        );
        assert_eq!(result.validate_against(&invocation), Ok(()));

        let mut reordered = result;
        let TransportDisposition::Transported { events, .. } = &mut reordered.disposition else {
            unreachable!()
        };
        events[0].sequence = 1;
        assert_eq!(
            reordered.validate_against(&invocation),
            Err(ContractError::EventSequence)
        );
    }

    #[test]
    fn receipt_refuses_caller_substitution() {
        let invocation = invocation();
        let mut substituted_caller = receipt(&invocation);
        substituted_caller.caller_runtime_id = "ghostlight-dungeon-yggdrasil".to_string();
        assert_eq!(
            substituted_caller.validate_against(&invocation),
            Err(ContractError::Identity)
        );

        let mut substituted_native_basis = receipt(&invocation);
        substituted_native_basis.native_request_sha256 = [8; 32];
        assert_eq!(
            substituted_native_basis.validate_against(&invocation),
            Err(ContractError::NativeDigest)
        );
    }

    #[test]
    fn v3_documents_carry_their_v3_ids() {
        assert_eq!(
            [
                PROVIDER_REQUEST_SCHEMA_ID,
                INVOCATION_SCHEMA_ID,
                RESULT_SCHEMA_ID,
                RECEIPT_SCHEMA_ID,
                ENVELOPE_SCHEMA_ID
            ],
            [
                "gamecult.model.provider_request.v3",
                "gamecult.model.transport_invocation.v3",
                "gamecult.model.transport_result.v3",
                "gamecult.model.transport_receipt.v3",
                "gamecult.model.transport_envelope.v3"
            ]
        );
        let invocation = invocation();
        let result = TransportResult::transported(&invocation, Vec::new(), receipt(&invocation));
        let TransportDisposition::Transported { receipt: sent, .. } = &result.disposition else {
            unreachable!()
        };
        assert_eq!(invocation.request.schema_id, PROVIDER_REQUEST_SCHEMA_ID);
        assert_eq!(invocation.schema_id, INVOCATION_SCHEMA_ID);
        assert_eq!(result.schema_id, RESULT_SCHEMA_ID);
        assert_eq!(sent.schema_id, RECEIPT_SCHEMA_ID);

        let v2 = |name: &str| format!("{}{name}.v2", concat!("gamecult.", "codex."));
        let mut request = invocation.request.clone();
        request.schema_id = v2("provider_request");
        assert_eq!(request.validate(), Err(ContractError::Schema));
        let mut stale = invocation.clone();
        stale.schema_id = v2("transport_invocation");
        assert_eq!(stale.validate(1_000, 2_000), Err(ContractError::Schema));
        let mut stale = result.clone();
        stale.schema_id = v2("transport_result");
        assert_eq!(
            stale.validate_against(&invocation),
            Err(ContractError::Schema)
        );
        let mut stale = (**sent).clone();
        stale.schema_id = v2("transport_receipt");
        assert_eq!(
            stale.validate_against(&invocation),
            Err(ContractError::Schema)
        );
    }

    /// `document` re-encoded as a named map with one more key at its top level.
    fn with_extra_key<T: Serialize>(document: &T) -> Vec<u8> {
        let bytes = wire_encode(document).unwrap();
        let mut value = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap();
        let rmpv::Value::Map(entries) = &mut value else {
            panic!("a v3 document is a named map");
        };
        entries.push((rmpv::Value::from("unexpected_field"), rmpv::Value::from(1)));
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &value).unwrap();
        out
    }

    #[test]
    fn an_unknown_field_is_refused_not_dropped() {
        let invocation = invocation();
        let result = TransportResult::transported(&invocation, Vec::new(), receipt(&invocation));
        let TransportDisposition::Transported { receipt: sent, .. } = &result.disposition else {
            unreachable!()
        };
        let envelope = crate::envelope::encrypt_invocation(
            &invocation,
            &security("epiphany-distinct-test-key"),
        )
        .unwrap();
        assert!(wire_decode::<ProviderRequest>(&wire_encode(&invocation.request).unwrap()).is_ok());
        assert!(wire_decode::<ProviderRequest>(&with_extra_key(&invocation.request)).is_err());
        assert!(wire_decode::<TransportInvocation>(&with_extra_key(&invocation)).is_err());
        assert!(wire_decode::<TransportResult>(&with_extra_key(&result)).is_err());
        assert!(wire_decode::<TransportReceipt>(&with_extra_key(&**sent)).is_err());
        assert!(
            wire_decode::<crate::envelope::TransportEnvelope>(&wire_encode(&envelope).unwrap())
                .is_ok()
        );
        assert!(
            wire_decode::<crate::envelope::TransportEnvelope>(&with_extra_key(&envelope)).is_err()
        );
    }

    #[test]
    fn max_output_tokens_is_required() {
        let mut request = request();
        assert_eq!(request.validate(), Ok(()));
        request.max_output_tokens = 0;
        assert_eq!(
            request.validate(),
            Err(ContractError::Invalid("max_output_tokens"))
        );
    }

    #[test]
    fn outcomes_are_typed() {
        let invocation = invocation();
        for stop_reason in [
            StopReason::EndTurn,
            StopReason::ToolUse,
            StopReason::MaxOutputTokens,
            StopReason::StopSequence,
            StopReason::Refusal,
            StopReason::ContextWindow,
        ] {
            let mut sent = receipt(&invocation);
            sent.outcome = TransportOutcome::Completed {
                provider_response_id: None,
                stop_reason,
                usage: Usage {
                    input_tokens: 1,
                    cache_read_tokens: 2,
                    cache_write_tokens: 3,
                    output_tokens: 4,
                    reasoning_tokens: None,
                },
            };
            let decoded: TransportReceipt = wire_decode(&wire_encode(&sent).unwrap()).unwrap();
            assert_eq!(decoded, sent);
        }
        for kind in [
            FailureKind::ResultSize,
            FailureKind::InvalidRequest,
            FailureKind::Authentication,
            FailureKind::RateLimited,
            FailureKind::Unavailable,
            FailureKind::Timeout,
            FailureKind::Provider,
        ] {
            let mut sent = receipt(&invocation);
            sent.outcome = TransportOutcome::Failed {
                kind,
                message: "failed".to_string(),
            };
            assert_eq!(sent.validate_against(&invocation), Ok(()));
            let decoded: TransportReceipt = wire_decode(&wire_encode(&sent).unwrap()).unwrap();
            assert_eq!(decoded, sent);
        }
        let mut blank = receipt(&invocation);
        blank.outcome = TransportOutcome::Failed {
            kind: FailureKind::Provider,
            message: String::new(),
        };
        assert_eq!(
            blank.validate_against(&invocation),
            Err(ContractError::Invalid("receipt.failure_message"))
        );
    }

    #[test]
    fn validate_against_refuses_each_identity_field() {
        let invocation = invocation();
        let result = TransportResult::transported(&invocation, Vec::new(), receipt(&invocation));
        assert_eq!(result.validate_against(&invocation), Ok(()));
        let mut other_request = result.clone();
        other_request.request_id = "request-2".to_string();
        let mut other_caller = result.clone();
        other_caller.caller_runtime_id = "ghostlight-dungeon-yggdrasil".to_string();
        for changed in [other_request, other_caller] {
            assert_eq!(
                changed.validate_against(&invocation),
                Err(ContractError::Identity)
            );
        }

        let good = receipt(&invocation);
        let mut other_request = good.clone();
        other_request.request_id = "request-2".to_string();
        let mut other_caller = good.clone();
        other_caller.caller_runtime_id = "ghostlight-dungeon-yggdrasil".to_string();
        let mut other_model = good.clone();
        other_model.model = "another-model".to_string();
        for changed in [other_request, other_caller, other_model] {
            assert_eq!(
                changed.validate_against(&invocation),
                Err(ContractError::Identity)
            );
        }
    }
}
