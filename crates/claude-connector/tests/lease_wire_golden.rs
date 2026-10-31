//! Pins the bytes of the lease protocol v2: every frame a lease client sends
//! or receives. The fixtures in `fixtures/lease_v2` are the contract's bytes
//! for other implementations (Huginn's lease client vendors them and tests
//! against the same bytes); the types in `claude_connector::lease` own the
//! shape. Regenerate with `LEASE_V2_REGENERATE=1`, then review the diff.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use claude_connector::{
    LeaseGranted, LeaseMessage, LeaseRefusalKind, LeaseRefused, LeaseRequest, decode_frame,
    encode_frame,
};
use model_connector::PlanQuota;

const REGENERATE: &str = "LEASE_V2_REGENERATE";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lease_v2")
}

fn assert_frame(name: &str, message: &LeaseMessage) {
    let path = fixtures().join(name);
    let bytes = encode_frame(message);
    if std::env::var_os(REGENERATE).is_some() {
        std::fs::create_dir_all(fixtures()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
    }
    let committed = std::fs::read(&path).unwrap_or_else(|_| panic!("{name} is missing"));
    assert_eq!(committed, bytes, "{name} is not what the types encode");
    assert_eq!(decode_frame(&committed).as_ref(), Some(message), "{name}");
}

#[test]
fn the_request_frame_is_pinned() {
    assert_frame(
        "request.bin",
        &LeaseMessage::ClaudeLeaseRequest(LeaseRequest {
            expires_at_unix_ms: 1_793_307_000_000,
        }),
    );
}

#[test]
fn every_refusal_frame_is_pinned_with_its_kind_as_a_pascal_case_string() {
    let kinds = [
        (
            "refusal_unknown_caller.bin",
            LeaseRefusalKind::UnknownCaller,
            "UnknownCaller",
        ),
        ("refusal_expired.bin", LeaseRefusalKind::Expired, "Expired"),
        ("refusal_busy.bin", LeaseRefusalKind::Busy, "Busy"),
        (
            "refusal_provider_rejected.bin",
            LeaseRefusalKind::ProviderRejected,
            "ProviderRejected",
        ),
    ];
    for (name, kind, spelled) in kinds {
        let message = LeaseMessage::ClaudeLeaseRefusal(LeaseRefused {
            kind,
            detail: "the reason".to_string(),
        });
        assert_frame(name, &message);
        // The kind travels as the variant's name, which other runtimes read.
        let bytes = encode_frame(&message);
        let value: rmpv::Value = rmp_serde::from_slice(&bytes[4..]).unwrap();
        let rmpv::Value::Map(outer) = value else {
            panic!("a frame is a map")
        };
        let rmpv::Value::Map(inner) = &outer[1].1 else {
            panic!("the value is a map")
        };
        assert_eq!(inner[0].0.as_str(), Some("kind"));
        assert_eq!(inner[0].1.as_str(), Some(spelled));
    }
}

#[test]
fn a_grant_with_both_usage_windows_is_pinned() {
    let window = |name: &str, permille, status: &str, resets| PlanQuota {
        window: name.to_string(),
        utilization_permille: Some(permille),
        resets_at_unix_ms: resets,
        status: status.to_string(),
        observed_at_unix_ms: 1_793_300_000_000,
    };
    assert_frame(
        "grant.bin",
        &LeaseMessage::ClaudeLeaseGrant(LeaseGranted {
            lease_id: "lease:0123456789abcdef0123456789abcdef".to_string(),
            plan_quota: vec![
                window("five_hour", 420, "allowed", 1_793_307_000_000),
                window("seven_day", 999, "allowed_warning", 1_793_800_000_000),
            ],
        }),
    );
}
