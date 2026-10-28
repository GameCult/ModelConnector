//! Pins the bytes of the v3 wire so a drift is a failing test. The fixtures in
//! `fixtures/wire_v3` are produced by this file (see its README); they pin the
//! kit against itself and are not a second contract: the types in
//! `model_connector::contract` own the shape.

use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cultnet_rs::{
    CultNetMessage, CultNetWireContract, decode_cultnet_message_from_slice,
    encode_cultnet_message_to_vec,
};
use model_connector::*;
use serde::Serialize;
use serde::de::DeserializeOwned;

const KEY: &str = "golden-distinct-test-key";
const CALLER: &str = "golden-caller";
const REGENERATE: &str = "WIRE_V3_REGENERATE";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wire_v3")
}

fn named<T: Serialize>(value: &T) -> Vec<u8> {
    rmp_serde::to_vec_named(value).unwrap()
}

/// The value serializes to the committed bytes and the committed bytes decode
/// back to it. With `WIRE_V3_REGENERATE` set, the committed bytes are rewritten
/// from the value first.
fn assert_wire<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
    name: &str,
    value: &T,
) {
    let path = fixtures().join(name);
    if std::env::var_os(REGENERATE).is_some() {
        std::fs::create_dir_all(fixtures()).unwrap();
        std::fs::write(&path, named(value)).unwrap();
    }
    let golden = std::fs::read(&path).unwrap_or_else(|_| panic!("{name}: fixture is missing"));
    assert_eq!(named(value), golden, "{name}: serialized bytes");
    let decoded: T = rmp_serde::from_slice(&golden).unwrap();
    assert_eq!(&decoded, value, "{name}: decoded value");
}

fn request() -> ProviderRequest {
    let mut request = ProviderRequest::new(
        "golden-request",
        "golden-conversation",
        "claude-opus-4-5",
        "Return the typed result.",
        8_192,
    );
    request.input = vec![
        InputItem::UserText {
            text: "Projected state".to_string(),
        },
        InputItem::ToolCall {
            call_id: "call-1".to_string(),
            name: "read_source".to_string(),
            arguments: "{}".to_string(),
        },
        InputItem::ToolResult {
            call_id: "call-1".to_string(),
            output: "evidence".to_string(),
        },
    ];
    request.reasoning_effort = Some(ReasoningEffort::High);
    request.cache_retention = Some(CacheRetention::Short);
    request.tools = vec![ToolDefinition {
        name: "read_source".to_string(),
        description: "Read one admitted source.".to_string(),
        parameters_json: r#"{"type":"object"}"#.to_string(),
    }];
    request.tool_choice = ToolChoice::Required;
    request.parallel_tool_calls = true;
    request.output_schema_json = Some(r#"{"type":"object"}"#.to_string());
    request
}

fn invocation() -> TransportInvocation {
    TransportInvocation::new(CALLER, 1_800_000_000_000, [7; 32], 5_000_000, request()).unwrap()
}

fn receipt(outcome: TransportOutcome) -> TransportReceipt {
    let invocation = invocation();
    TransportReceipt {
        schema_id: RECEIPT_SCHEMA_ID.to_string(),
        request_id: invocation.request_id().to_string(),
        caller_runtime_id: CALLER.to_string(),
        native_request_sha256: invocation.native_request_sha256,
        provider_request_sha256: invocation.provider_request_sha256,
        model: invocation.request.model.clone(),
        provider: "anthropic-messages".to_string(),
        foreign_reasoning_dropped: 2,
        cost_micro_usd: 1_234_567,
        outcome,
    }
}

fn completed() -> TransportOutcome {
    TransportOutcome::Completed {
        provider_response_id: Some("msg-1".to_string()),
        stop_reason: StopReason::ToolUse,
        usage: Usage {
            input_tokens: 120,
            cache_read_tokens: 40,
            cache_write_tokens: 8,
            output_tokens: 33,
            reasoning_tokens: Some(12),
        },
    }
}

#[test]
fn wire_golden_v3() {
    let invocation = invocation();
    assert_wire("provider_request.mp", &invocation.request);
    assert_wire("transport_invocation.mp", &invocation);

    // The reasoning bytes are all >= 0x80 so a byte-array encoding cannot pass
    // for MessagePack bin.
    let reasoning = || (0x80..=0xff_u8).collect::<Vec<u8>>();
    assert_wire(
        "input_reasoning_state.mp",
        &InputItem::ReasoningState {
            provider: "anthropic-messages".to_string(),
            model: "claude-opus-4-5".to_string(),
            state: reasoning(),
        },
    );

    let transported = TransportResult {
        schema_id: RESULT_SCHEMA_ID.to_string(),
        request_id: invocation.request_id().to_string(),
        caller_runtime_id: CALLER.to_string(),
        disposition: TransportDisposition::Transported {
            events: vec![
                TransportEvent {
                    sequence: 0,
                    payload: TransportEventPayload::TextDelta {
                        text: "thinking".to_string(),
                    },
                },
                TransportEvent {
                    sequence: 1,
                    payload: TransportEventPayload::ReasoningState { state: reasoning() },
                },
                TransportEvent {
                    sequence: 2,
                    payload: TransportEventPayload::ToolCall {
                        call_id: "call-2".to_string(),
                        name: "read_source".to_string(),
                        arguments: "{}".to_string(),
                    },
                },
            ],
            receipt: Box::new(receipt(completed())),
        },
    };
    assert_eq!(transported.validate_against(&invocation), Ok(()));
    assert_wire("transport_result_transported.mp", &transported);

    let refused = TransportResult::refused(&invocation, Refusal::OutputBound);
    assert_wire("transport_result_refused.mp", &refused);

    let failed = receipt(TransportOutcome::Failed {
        kind: FailureKind::RateLimited,
        message: "provider asked to slow down".to_string(),
        usage: Some(Usage {
            input_tokens: 120,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            output_tokens: 0,
            reasoning_tokens: None,
        }),
    });
    assert_eq!(failed.validate_against(&invocation), Ok(()));
    assert_wire("transport_receipt_failed.mp", &failed);

    let envelope = TransportEnvelope {
        schema_id: ENVELOPE_SCHEMA_ID.to_string(),
        caller_runtime_id: CALLER.to_string(),
        request_id: "golden-request".to_string(),
        message_kind: EnvelopeKind::Invocation,
        nonce: [0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xff],
        ciphertext: (0..40_u8).map(|byte| byte.wrapping_mul(7)).collect(),
    };
    assert_wire("transport_envelope.mp", &envelope);
}

/// The committed carriage frame is a `cultnet.operation_request.v0` for the
/// connector, read here with CultNet itself and not the kit's own carriage code.
/// Its payload is the base64 of a sealed envelope that decrypts under the
/// fixed key to the golden invocation.
#[test]
fn the_golden_carriage_frame_decrypts_and_validates_under_the_fixed_key() {
    let path = fixtures().join("carriage_invocation.frame");
    let key = TransportKey::from_connection_secret(KEY).unwrap();
    let invocation = invocation();
    if std::env::var_os(REGENERATE).is_some() {
        let envelope = encrypt_invocation(&invocation, &key).unwrap();
        let message = CultNetMessage::OperationRequest {
            message_id: envelope.request_id.clone(),
            service_id: CONNECTOR_SERVICE_ID.to_string(),
            operation: INVOKE_OPERATION.to_string(),
            payload_schema: ENVELOPE_SCHEMA_ID.to_string(),
            payload_encoding: "messagepack-base64".to_string(),
            payload: STANDARD.encode(named(&envelope)),
            source_runtime_id: None,
            target_runtime_id: None,
        };
        std::fs::write(
            &path,
            encode_cultnet_message_to_vec(&message, CultNetWireContract::CultNetSchemaV0).unwrap(),
        )
        .unwrap();
    }
    let frame = std::fs::read(&path).expect("carriage_invocation.frame is missing");
    let CultNetMessage::OperationRequest {
        message_id,
        service_id,
        operation,
        payload_schema,
        payload,
        ..
    } = decode_cultnet_message_from_slice(&frame, CultNetWireContract::CultNetSchemaV0).unwrap()
    else {
        panic!("the golden frame is a CultNet operation request");
    };
    assert_eq!(service_id, "gamecult.model.connector");
    assert_eq!(operation, "invoke");
    assert_eq!(payload_schema, "gamecult.model.transport_envelope.v3");
    assert_eq!(message_id, invocation.request_id());
    let envelope: TransportEnvelope =
        rmp_serde::from_slice(&STANDARD.decode(payload).unwrap()).unwrap();
    assert_eq!(envelope.request_id, message_id);
    let decrypted = decrypt_invocation(&envelope, &key).unwrap();
    assert_eq!(decrypted, invocation);
    assert_eq!(decrypted.validate(1_799_999_999_000, 5_000), Ok(()));
}

/// The reasoning bytes travel as MessagePack `bin` (0xc4 length marker), never
/// as an array of integers.
#[test]
fn reasoning_state_is_messagepack_bin() {
    let golden = std::fs::read(fixtures().join("input_reasoning_state.mp")).unwrap();
    let marker = golden.windows(3).any(|window| window == [0xc4, 0x80, 0x80]);
    assert!(marker, "state must be a bin 8 of 128 bytes starting 0x80");
}
