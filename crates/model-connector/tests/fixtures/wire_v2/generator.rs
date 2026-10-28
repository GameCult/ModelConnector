//! Generator of the golden v2 wire fixtures beside it. It is not compiled by this
//! workspace: it was run once, as an example of CodexConnector at commit
//! fd7cec4176f4e3f9a5aaa75e77ba10ce5e1522f8 (see README.md here for the command).
//! It prints one `FIXTURE <name> <hex>` line per file.

use codex_connector as v2;
use serde::Serialize;

const KEY: &str = "parity-distinct-test-key";
const CALLER: &str = "parity-caller";

fn bytes<T: Serialize>(value: &T) -> Vec<u8> {
    rmp_serde::to_vec(value).unwrap()
}

fn emit(name: &str, data: &[u8]) {
    let hex: String = data.iter().map(|byte| format!("{byte:02x}")).collect();
    println!("FIXTURE {name} {hex}");
}

fn request(choice: v2::CodexToolChoice) -> v2::CodexProviderRequest {
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
    request.tool_choice = choice;
    request.reasoning_effort = Some("high".to_string());
    request.parallel_tool_calls = true;
    request.max_output_tokens = Some(512);
    request.prompt_cache_key = Some("cache-1".to_string());
    request
}

fn invocation(choice: v2::CodexToolChoice) -> v2::CodexTransportInvocation {
    v2::CodexTransportInvocation::new(CALLER, 2_000, [7; 32], request(choice)).unwrap()
}

fn receipt(
    invocation: &v2::CodexTransportInvocation,
    outcome: v2::CodexTransportOutcome,
) -> v2::CodexTransportReceipt {
    v2::CodexTransportReceipt {
        schema_id: v2::RECEIPT_SCHEMA_ID.to_string(),
        request_id: invocation.request_id().to_string(),
        caller_runtime_id: invocation.caller_runtime_id.clone(),
        native_request_sha256: invocation.native_request_sha256,
        provider_request_sha256: invocation.provider_request_sha256,
        model: invocation.request.model.clone(),
        transport: "parity-sse".to_string(),
        outcome,
    }
}

fn main() {
    let key = v2::CodexTransportKey::from_connection_secret(KEY).unwrap();
    let auto = invocation(v2::CodexToolChoice::Auto);
    let required = invocation(v2::CodexToolChoice::Required);
    emit("invocation_auto.mp", &bytes(&auto));
    emit("invocation_required.mp", &bytes(&required));
    emit(
        "canonical_invocation.bin",
        &v2::canonical_invocation_bytes(&required).unwrap(),
    );
    emit(
        "canonical_provider_request.bin",
        &v2::canonical_provider_request_bytes(&required.request).unwrap(),
    );
    emit(
        "provider_request_sha256.bin",
        &v2::provider_request_sha256(&required.request).unwrap(),
    );
    emit(
        "envelope_invocation.mp",
        &bytes(&v2::encrypt_invocation(&required, &key).unwrap()),
    );

    let completed = v2::CodexTransportResult::transported(
        &required,
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
        receipt(
            &required,
            v2::CodexTransportOutcome::Completed {
                provider_response_id: Some("response-1".to_string()),
                input_tokens: Some(10),
                output_tokens: Some(3),
                reasoning_output_tokens: Some(1),
                cached_input_tokens: Some(4),
            },
        ),
    );
    emit("result_transported.mp", &bytes(&completed));
    emit(
        "envelope_result_transported.mp",
        &bytes(&v2::encrypt_result(&completed, &key).unwrap()),
    );

    let failed = v2::CodexTransportResult::transported(
        &required,
        Vec::new(),
        receipt(
            &required,
            v2::CodexTransportOutcome::Failed {
                failure_kind: "result_size".to_string(),
                message: "provider result exceeded its byte bound".to_string(),
            },
        ),
    );
    emit("result_failed.mp", &bytes(&failed));
    emit(
        "envelope_result_failed.mp",
        &bytes(&v2::encrypt_result(&failed, &key).unwrap()),
    );

    use v2::CodexRefusal as R;
    let refusals = [
        ("expired", R::Expired),
        ("identity_substitution", R::IdentitySubstitution),
        ("provider_digest_substitution", R::ProviderDigestSubstitution),
        ("policy", R::Policy),
        ("capacity", R::Capacity),
        ("in_flight", R::InFlight),
        ("indeterminate", R::Indeterminate),
        ("replay_conflict", R::ReplayConflict),
        ("malformed", R::Malformed),
    ];
    for (name, refusal) in refusals {
        let refused = v2::CodexTransportResult::refused(&required, refusal);
        emit(&format!("result_refused_{name}.mp"), &bytes(&refused));
        if name == "replay_conflict" {
            emit(
                "envelope_result_refused_replay_conflict.mp",
                &bytes(&v2::encrypt_result(&refused, &key).unwrap()),
            );
        }
    }
}
