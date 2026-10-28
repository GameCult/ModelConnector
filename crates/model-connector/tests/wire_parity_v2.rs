//! The lift is wire-identical to CodexConnector fd7cec4, the v2 library
//! Ghostlight pins. Deleted by cut connector-contract-v3, which changes the wire.

use codex_connector as v2;
use model_connector as kit;
use serde::Serialize;
use serde::de::DeserializeOwned;

const KEY: &str = "parity-distinct-test-key";
const CALLER: &str = "parity-caller";

/// Moves a value across the two crates by its MessagePack bytes, the shape the wire carries.
fn cross<T: Serialize, U: DeserializeOwned>(value: &T) -> U {
    rmp_serde::from_slice(&rmp_serde::to_vec(value).unwrap()).unwrap()
}

fn bytes<T: Serialize>(value: &T) -> Vec<u8> {
    rmp_serde::to_vec(value).unwrap()
}

fn kit_request() -> kit::ProviderRequest {
    let mut request =
        kit::ProviderRequest::new("request-1", "conversation-1", "gpt-5.4", "Be exact.");
    request.input = vec![
        kit::InputItem::UserText {
            text: "state".to_string(),
        },
        kit::InputItem::AssistantText {
            text: "reply".to_string(),
        },
        kit::InputItem::ToolCall {
            call_id: "call-1".to_string(),
            name: "read_source".to_string(),
            arguments: "{}".to_string(),
        },
        kit::InputItem::ToolResult {
            call_id: "call-1".to_string(),
            output: "ok".to_string(),
        },
    ];
    request.tools = vec![kit::ToolDefinition {
        name: "read_source".to_string(),
        description: "Read one admitted source.".to_string(),
        parameters_json: r#"{"type":"object"}"#.to_string(),
    }];
    request.tool_choice = kit::ToolChoice::Required;
    request.reasoning_effort = Some("high".to_string());
    request.parallel_tool_calls = true;
    request.max_output_tokens = Some(512);
    request.prompt_cache_key = Some("cache-1".to_string());
    request
}

fn v2_request() -> v2::CodexProviderRequest {
    let mut request =
        v2::CodexProviderRequest::new("request-1", "conversation-1", "gpt-5.4", "Be exact.");
    request.input = vec![
        v2::CodexInputItem::UserText {
            text: "state".to_string(),
        },
        v2::CodexInputItem::AssistantText {
            text: "reply".to_string(),
        },
        v2::CodexInputItem::ToolCall {
            call_id: "call-1".to_string(),
            name: "read_source".to_string(),
            arguments: "{}".to_string(),
        },
        v2::CodexInputItem::ToolResult {
            call_id: "call-1".to_string(),
            output: "ok".to_string(),
        },
    ];
    request.tools = vec![v2::CodexToolDefinition {
        name: "read_source".to_string(),
        description: "Read one admitted source.".to_string(),
        parameters_json: r#"{"type":"object"}"#.to_string(),
    }];
    request.tool_choice = v2::CodexToolChoice::Required;
    request.reasoning_effort = Some("high".to_string());
    request.parallel_tool_calls = true;
    request.max_output_tokens = Some(512);
    request.prompt_cache_key = Some("cache-1".to_string());
    request
}

fn kit_invocation() -> kit::TransportInvocation {
    kit::TransportInvocation::new(CALLER, 2_000, [7; 32], kit_request()).unwrap()
}

fn v2_invocation() -> v2::CodexTransportInvocation {
    v2::CodexTransportInvocation::new(CALLER, 2_000, [7; 32], v2_request()).unwrap()
}

fn kit_result(invocation: &kit::TransportInvocation) -> kit::TransportResult {
    let receipt = kit::TransportReceipt {
        schema_id: kit::RECEIPT_SCHEMA_ID.to_string(),
        request_id: invocation.request_id().to_string(),
        caller_runtime_id: invocation.caller_runtime_id.clone(),
        native_request_sha256: invocation.native_request_sha256,
        provider_request_sha256: invocation.provider_request_sha256,
        model: invocation.request.model.clone(),
        transport: "parity-sse".to_string(),
        outcome: kit::TransportOutcome::Completed {
            provider_response_id: Some("response-1".to_string()),
            input_tokens: Some(10),
            output_tokens: Some(3),
            reasoning_output_tokens: Some(1),
            cached_input_tokens: None,
        },
    };
    kit::TransportResult::transported(
        invocation,
        vec![
            kit::TransportEvent {
                sequence: 0,
                payload: kit::TransportEventPayload::TextDelta {
                    text: "hello".to_string(),
                },
            },
            kit::TransportEvent {
                sequence: 1,
                payload: kit::TransportEventPayload::ToolCall {
                    call_id: "call-2".to_string(),
                    name: "read_source".to_string(),
                    arguments: "{}".to_string(),
                },
            },
        ],
        receipt,
    )
}

fn v2_result(invocation: &v2::CodexTransportInvocation) -> v2::CodexTransportResult {
    let receipt = v2::CodexTransportReceipt {
        schema_id: v2::RECEIPT_SCHEMA_ID.to_string(),
        request_id: invocation.request_id().to_string(),
        caller_runtime_id: invocation.caller_runtime_id.clone(),
        native_request_sha256: invocation.native_request_sha256,
        provider_request_sha256: invocation.provider_request_sha256,
        model: invocation.request.model.clone(),
        transport: "parity-sse".to_string(),
        outcome: v2::CodexTransportOutcome::Completed {
            provider_response_id: Some("response-1".to_string()),
            input_tokens: Some(10),
            output_tokens: Some(3),
            reasoning_output_tokens: Some(1),
            cached_input_tokens: None,
        },
    };
    v2::CodexTransportResult::transported(
        invocation,
        vec![
            v2::CodexTransportEvent {
                sequence: 0,
                payload: v2::CodexTransportEventPayload::TextDelta {
                    text: "hello".to_string(),
                },
            },
            v2::CodexTransportEvent {
                sequence: 1,
                payload: v2::CodexTransportEventPayload::ToolCall {
                    call_id: "call-2".to_string(),
                    name: "read_source".to_string(),
                    arguments: "{}".to_string(),
                },
            },
        ],
        receipt,
    )
}

fn kit_key() -> kit::TransportKey {
    kit::TransportKey::from_connection_secret(KEY).unwrap()
}

fn v2_key() -> v2::CodexTransportKey {
    v2::CodexTransportKey::from_connection_secret(KEY).unwrap()
}

#[test]
fn schema_ids_are_the_v2_ids() {
    assert_eq!(
        kit::PROVIDER_REQUEST_SCHEMA_ID,
        v2::PROVIDER_REQUEST_SCHEMA_ID
    );
    assert_eq!(kit::INVOCATION_SCHEMA_ID, v2::INVOCATION_SCHEMA_ID);
    assert_eq!(kit::RESULT_SCHEMA_ID, v2::RESULT_SCHEMA_ID);
    assert_eq!(kit::RECEIPT_SCHEMA_ID, v2::RECEIPT_SCHEMA_ID);
    assert_eq!(kit::ENVELOPE_SCHEMA_ID, v2::ENVELOPE_SCHEMA_ID);
}

#[test]
fn canonical_bytes_and_provider_digest_match_v2() {
    let from_kit = kit_invocation();
    let from_v2 = v2_invocation();
    assert_eq!(bytes(&from_kit), bytes(&from_v2));
    assert_eq!(
        kit::canonical_invocation_bytes(&from_kit).unwrap(),
        v2::canonical_invocation_bytes(&from_v2).unwrap()
    );
    assert_eq!(
        kit::canonical_provider_request_bytes(&from_kit.request).unwrap(),
        v2::canonical_provider_request_bytes(&from_v2.request).unwrap()
    );
    assert_eq!(
        kit::provider_request_sha256(&from_kit.request).unwrap(),
        v2::provider_request_sha256(&from_v2.request).unwrap()
    );
}

#[test]
fn kit_invocation_decrypts_and_validates_under_v2() {
    let sent = kit_invocation();
    let envelope = kit::encrypt_invocation(&sent, &kit_key()).unwrap();
    let received = v2::decrypt_invocation(&cross(&envelope), &v2_key()).unwrap();
    assert_eq!(bytes(&received), bytes(&sent));
}

#[test]
fn v2_invocation_decrypts_and_validates_under_kit() {
    let sent = v2_invocation();
    let envelope = v2::encrypt_invocation(&sent, &v2_key()).unwrap();
    let received = kit::decrypt_invocation(&cross(&envelope), &kit_key()).unwrap();
    assert_eq!(bytes(&received), bytes(&sent));
}

#[test]
fn kit_result_decrypts_and_validates_under_v2() {
    let sent = kit_result(&kit_invocation());
    let envelope = kit::encrypt_result(&sent, &kit_key()).unwrap();
    let received = v2::decrypt_result(&cross(&envelope), &v2_key(), &v2_invocation()).unwrap();
    assert_eq!(bytes(&received), bytes(&sent));
}

#[test]
fn v2_result_decrypts_and_validates_under_kit() {
    let sent = v2_result(&v2_invocation());
    let envelope = v2::encrypt_result(&sent, &v2_key()).unwrap();
    let received = kit::decrypt_result(&cross(&envelope), &kit_key(), &kit_invocation()).unwrap();
    assert_eq!(bytes(&received), bytes(&sent));
}
