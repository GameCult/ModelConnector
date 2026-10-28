//! `schemas/` at the repository root publishes one JSON Schema per v3 document,
//! generated from the types. This test regenerates them and fails on any
//! difference; run it with `MODEL_CONNECTOR_REGENERATE_SCHEMAS=1` to rewrite the
//! files from the types.

use std::path::{Path, PathBuf};

use model_connector::*;
use schemars::{JsonSchema, schema_for};

const REGENERATE: &str = "MODEL_CONNECTOR_REGENERATE_SCHEMAS";

fn render<T: JsonSchema>() -> String {
    let mut text = serde_json::to_string_pretty(&schema_for!(T)).unwrap();
    text.push('\n');
    text
}

fn schemas_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas")
}

#[test]
fn published_schemas_are_the_types() {
    let documents = [
        ("provider_request", render::<ProviderRequest>()),
        ("transport_invocation", render::<TransportInvocation>()),
        ("transport_result", render::<TransportResult>()),
        ("transport_receipt", render::<TransportReceipt>()),
        ("transport_envelope", render::<TransportEnvelope>()),
    ];
    let dir = schemas_dir();
    if std::env::var_os(REGENERATE).is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in &documents {
            std::fs::write(dir.join(format!("{name}.json")), text).unwrap();
        }
    }
    for (name, text) in &documents {
        let committed = std::fs::read_to_string(dir.join(format!("{name}.json")))
            .unwrap_or_else(|_| panic!("schemas/{name}.json is missing"));
        assert_eq!(&committed, text, "schemas/{name}.json is not the type's");
    }
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    on_disk.sort();
    let mut expected: Vec<String> = documents
        .iter()
        .map(|(name, _)| format!("{name}.json"))
        .collect();
    expected.sort();
    assert_eq!(
        on_disk, expected,
        "schemas/ holds exactly the five documents"
    );
}

#[test]
fn a_published_schema_refuses_an_unknown_field() {
    let schema = serde_json::to_value(schema_for!(ProviderRequest)).unwrap();
    assert_eq!(schema["additionalProperties"], serde_json::json!(false));
    let required = schema["required"].as_array().unwrap();
    assert!(required.contains(&serde_json::json!("max_output_tokens")));
}

/// The schema and the wire agree on the ciphertext: the schema says binary, not
/// an array of integers, and the encoder writes MessagePack `bin`.
#[test]
fn the_published_ciphertext_is_what_the_wire_sends() {
    let schema = serde_json::to_value(schema_for!(TransportEnvelope)).unwrap();
    let ciphertext = &schema["properties"]["ciphertext"];
    assert_eq!(ciphertext["type"], "string");
    assert_eq!(ciphertext["format"], "binary");
    assert!(ciphertext.get("items").is_none());
    let published = std::fs::read_to_string(schemas_dir().join("transport_envelope.json")).unwrap();
    let published: serde_json::Value = serde_json::from_str(&published).unwrap();
    assert_eq!(&published["properties"]["ciphertext"], ciphertext);

    let envelope = TransportEnvelope {
        schema_id: "gamecult.model.transport_envelope.v3".to_string(),
        caller_runtime_id: "caller".to_string(),
        request_id: "request".to_string(),
        message_kind: EnvelopeKind::Invocation,
        nonce: [1; 12],
        ciphertext: vec![9; 40],
    };
    let sent =
        rmpv::decode::read_value(&mut rmp_serde::to_vec_named(&envelope).unwrap().as_slice())
            .unwrap();
    let rmpv::Value::Map(entries) = sent else {
        panic!("the envelope is a named map");
    };
    let (_, wire) = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("ciphertext"))
        .unwrap();
    assert!(matches!(wire, rmpv::Value::Binary(bytes) if bytes.len() == 40));
}
