//! The kit speaks the v2 wire of CodexConnector fd7cec4, the library Ghostlight pins.
//! The golden bytes in `fixtures/wire_v2` were produced by that library (see its README);
//! nothing of it is linked here. Deleted with the fixtures by cut connector-contract-v3,
//! which changes the wire.

use model_connector as kit;
use serde::Serialize;
use serde::de::DeserializeOwned;

const KEY: &str = "parity-distinct-test-key";
const CALLER: &str = "parity-caller";

macro_rules! golden {
    ($name:literal) => {
        include_bytes!(concat!("fixtures/wire_v2/", $name)) as &[u8]
    };
}

fn bytes<T: Serialize>(value: &T) -> Vec<u8> {
    rmp_serde::to_vec(value).unwrap()
}

/// The value serializes to the golden bytes and the golden bytes decode back to it.
fn assert_wire<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
    name: &str,
    value: &T,
    golden: &[u8],
) {
    assert_eq!(bytes(value), golden, "{name}: serialized bytes");
    let decoded: T = rmp_serde::from_slice(golden).unwrap();
    assert_eq!(&decoded, value, "{name}: decoded value");
}

fn request(choice: kit::ToolChoice) -> kit::ProviderRequest {
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
    request.tool_choice = choice;
    request.reasoning_effort = Some("high".to_string());
    request.parallel_tool_calls = true;
    request.max_output_tokens = Some(512);
    request.prompt_cache_key = Some("cache-1".to_string());
    request
}

fn invocation(choice: kit::ToolChoice) -> kit::TransportInvocation {
    kit::TransportInvocation::new(CALLER, 2_000, [7; 32], request(choice)).unwrap()
}

fn receipt(
    invocation: &kit::TransportInvocation,
    outcome: kit::TransportOutcome,
) -> kit::TransportReceipt {
    kit::TransportReceipt {
        schema_id: kit::RECEIPT_SCHEMA_ID.to_string(),
        request_id: invocation.request_id().to_string(),
        caller_runtime_id: invocation.caller_runtime_id.clone(),
        native_request_sha256: invocation.native_request_sha256,
        provider_request_sha256: invocation.provider_request_sha256,
        model: invocation.request.model.clone(),
        transport: "parity-sse".to_string(),
        outcome,
    }
}

fn completed(invocation: &kit::TransportInvocation) -> kit::TransportResult {
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
        receipt(
            invocation,
            kit::TransportOutcome::Completed {
                provider_response_id: Some("response-1".to_string()),
                input_tokens: Some(10),
                output_tokens: Some(3),
                reasoning_output_tokens: Some(1),
                cached_input_tokens: Some(4),
            },
        ),
    )
}

fn failed(invocation: &kit::TransportInvocation) -> kit::TransportResult {
    kit::TransportResult::transported(
        invocation,
        Vec::new(),
        receipt(
            invocation,
            kit::TransportOutcome::Failed {
                failure_kind: "result_size".to_string(),
                message: "provider result exceeded its byte bound".to_string(),
            },
        ),
    )
}

fn key() -> kit::TransportKey {
    kit::TransportKey::from_connection_secret(KEY).unwrap()
}

fn refusals() -> [(&'static str, kit::Refusal, &'static [u8]); 9] {
    use kit::Refusal as R;
    [
        ("expired", R::Expired, golden!("result_refused_expired.mp")),
        (
            "identity_substitution",
            R::IdentitySubstitution,
            golden!("result_refused_identity_substitution.mp"),
        ),
        (
            "provider_digest_substitution",
            R::ProviderDigestSubstitution,
            golden!("result_refused_provider_digest_substitution.mp"),
        ),
        ("policy", R::Policy, golden!("result_refused_policy.mp")),
        (
            "capacity",
            R::Capacity,
            golden!("result_refused_capacity.mp"),
        ),
        (
            "in_flight",
            R::InFlight,
            golden!("result_refused_in_flight.mp"),
        ),
        (
            "indeterminate",
            R::Indeterminate,
            golden!("result_refused_indeterminate.mp"),
        ),
        (
            "replay_conflict",
            R::ReplayConflict,
            golden!("result_refused_replay_conflict.mp"),
        ),
        (
            "malformed",
            R::Malformed,
            golden!("result_refused_malformed.mp"),
        ),
    ]
}

#[test]
fn schema_ids_are_the_v2_ids() {
    assert_eq!(
        kit::PROVIDER_REQUEST_SCHEMA_ID,
        "gamecult.codex.provider_request.v2"
    );
    assert_eq!(
        kit::INVOCATION_SCHEMA_ID,
        "gamecult.codex.transport_invocation.v2"
    );
    assert_eq!(kit::RESULT_SCHEMA_ID, "gamecult.codex.transport_result.v2");
    assert_eq!(
        kit::RECEIPT_SCHEMA_ID,
        "gamecult.codex.transport_receipt.v2"
    );
    assert_eq!(
        kit::ENVELOPE_SCHEMA_ID,
        "gamecult.codex.transport_envelope.v2"
    );
}

#[test]
fn invocations_carry_the_v2_bytes_for_each_tool_choice() {
    assert_wire(
        "auto",
        &invocation(kit::ToolChoice::Auto),
        golden!("invocation_auto.mp"),
    );
    assert_wire(
        "required",
        &invocation(kit::ToolChoice::Required),
        golden!("invocation_required.mp"),
    );
}

#[test]
fn results_carry_the_v2_bytes_for_success_and_failure() {
    let invocation = invocation(kit::ToolChoice::Required);
    assert_wire(
        "transported",
        &completed(&invocation),
        golden!("result_transported.mp"),
    );
    assert_wire("failed", &failed(&invocation), golden!("result_failed.mp"));
}

#[test]
fn every_refusal_carries_its_v2_bytes() {
    let invocation = invocation(kit::ToolChoice::Required);
    for (name, refusal, golden) in refusals() {
        assert_wire(
            name,
            &kit::TransportResult::refused(&invocation, refusal),
            golden,
        );
    }
}

#[test]
fn canonical_bytes_and_provider_digest_are_the_v2_bytes() {
    let invocation = invocation(kit::ToolChoice::Required);
    assert_eq!(
        kit::canonical_invocation_bytes(&invocation).unwrap(),
        golden!("canonical_invocation.bin")
    );
    assert_eq!(
        kit::canonical_provider_request_bytes(&invocation.request).unwrap(),
        golden!("canonical_provider_request.bin")
    );
    assert_eq!(
        kit::provider_request_sha256(&invocation.request)
            .unwrap()
            .as_slice(),
        golden!("provider_request_sha256.bin")
    );
}

#[test]
fn v2_sealed_envelopes_decrypt_and_validate_under_the_kit() {
    let invocation = invocation(kit::ToolChoice::Required);
    let envelope: kit::TransportEnvelope =
        rmp_serde::from_slice(golden!("envelope_invocation.mp")).unwrap();
    let received = kit::decrypt_invocation(&envelope, &key()).unwrap();
    assert_eq!(bytes(&received), bytes(&invocation));

    let results = [
        (
            golden!("envelope_result_transported.mp"),
            completed(&invocation),
        ),
        (golden!("envelope_result_failed.mp"), failed(&invocation)),
        (
            golden!("envelope_result_refused_replay_conflict.mp"),
            kit::TransportResult::refused(&invocation, kit::Refusal::ReplayConflict),
        ),
    ];
    for (sealed, expected) in results {
        let envelope: kit::TransportEnvelope = rmp_serde::from_slice(sealed).unwrap();
        let received = kit::decrypt_result(&envelope, &key(), &invocation).unwrap();
        assert_eq!(bytes(&received), bytes(&expected));
    }
}

#[test]
fn kit_sealed_envelopes_have_the_v2_shape() {
    let invocation = invocation(kit::ToolChoice::Required);
    let golden: kit::TransportEnvelope =
        rmp_serde::from_slice(golden!("envelope_invocation.mp")).unwrap();
    let sealed = kit::encrypt_invocation(&invocation, &key()).unwrap();
    assert_eq!(sealed.schema_id, golden.schema_id);
    assert_eq!(sealed.caller_runtime_id, golden.caller_runtime_id);
    assert_eq!(sealed.request_id, golden.request_id);
    assert_eq!(sealed.message_kind, golden.message_kind);
    assert_eq!(sealed.ciphertext.len(), golden.ciphertext.len());
    assert_ne!(sealed.nonce, golden.nonce, "nonces are fresh per seal");

    let golden: kit::TransportEnvelope =
        rmp_serde::from_slice(golden!("envelope_result_transported.mp")).unwrap();
    let sealed = kit::encrypt_result(&completed(&invocation), &key()).unwrap();
    assert_eq!(sealed.message_kind, golden.message_kind);
    assert_eq!(sealed.ciphertext.len(), golden.ciphertext.len());
}
