//! Shared fixtures for the carried contract, envelope, client and service tests.
use crate::contract::*;

#[cfg(feature = "daemon")]
use crate::service::*;

#[cfg(feature = "daemon")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "daemon")]
static TEST_STORE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "daemon")]
pub(crate) struct TestStore {
    pub(crate) root: std::path::PathBuf,
    pub(crate) path: std::path::PathBuf,
}

#[cfg(feature = "daemon")]
impl TestStore {
    pub(crate) fn new() -> Self {
        let sequence = TEST_STORE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "model-connector-replay-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("replay.cc");
        Self { root, path }
    }
}

#[cfg(feature = "daemon")]
impl Drop for TestStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn request() -> ProviderRequest {
    let mut request = ProviderRequest::new(
        "request-1",
        "conversation-1",
        "gpt-5.4",
        "Return the typed result.",
        4_096,
    );
    request.input.push(InputItem::UserText {
        text: "Projected state".to_string(),
    });
    request.tools.push(ToolDefinition {
        name: "read_source".to_string(),
        description: "Read one admitted source.".to_string(),
        parameters_json: r#"{"type":"object"}"#.to_string(),
    });
    request
}

pub(crate) fn invocation() -> TransportInvocation {
    TransportInvocation::new("epiphany-yggdrasil", 2_000, [7; 32], request()).unwrap()
}

pub(crate) fn receipt(invocation: &TransportInvocation) -> TransportReceipt {
    TransportReceipt {
        schema_id: RECEIPT_SCHEMA_ID.to_string(),
        request_id: invocation.request_id().to_string(),
        caller_runtime_id: invocation.caller_runtime_id.clone(),
        native_request_sha256: invocation.native_request_sha256,
        provider_request_sha256: invocation.provider_request_sha256,
        model: invocation.request.model.clone(),
        provider: "fixture-sse".to_string(),
        foreign_reasoning_dropped: 0,
        outcome: TransportOutcome::Completed {
            provider_response_id: Some("response-1".to_string()),
            stop_reason: StopReason::EndTurn,
            usage: Usage {
                input_tokens: 10,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                output_tokens: 3,
                reasoning_tokens: Some(1),
            },
        },
    }
}
#[cfg(feature = "daemon")]
pub(crate) fn caller(
    caller_runtime_id: &str,
    key: &str,
    max_concurrent_requests: usize,
) -> CallerAdmission {
    CallerAdmission::new(
        caller_runtime_id,
        key,
        1,
        ["gpt-5.4".to_string()],
        max_concurrent_requests,
        64 * 1024,
        32_768,
    )
    .unwrap()
}

#[cfg(feature = "daemon")]
pub(crate) fn open_service(store: &TestStore, max_concurrent_requests: usize) -> TransportService {
    TransportService::open(
        &store.path,
        "fixture-sse",
        [
            caller(
                "epiphany-yggdrasil",
                "epiphany-distinct-test-key",
                max_concurrent_requests,
            ),
            caller(
                "ghostlight-yggdrasil",
                "ghostlight-distinct-test-key",
                max_concurrent_requests,
            ),
        ],
        5_000,
    )
    .unwrap()
}

pub(crate) fn security(key: &str) -> TransportKey {
    TransportKey::from_connection_secret(key).unwrap()
}

#[cfg(feature = "daemon")]
pub(crate) fn invocation_for(caller_runtime_id: &str, request_id: &str) -> TransportInvocation {
    let mut request = request();
    request.request_id = request_id.to_string();
    TransportInvocation::new(caller_runtime_id, 2_000, [7; 32], request).unwrap()
}
