//! Shared fixtures for the carried contract, envelope, client and service tests.
use crate::contract::*;

#[cfg(feature = "daemon")]
use crate::service::*;

#[cfg(feature = "daemon")]
use std::collections::BTreeMap;
#[cfg(feature = "daemon")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "daemon")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "daemon")]
use cultcache_rs::{CacheBackingStore, CultCacheEnvelope, PushAllOptions};

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

/// An in-memory ledger that accepts a fixed number of writes and then refuses
/// every one, so a test can make the replay store fail where it chooses. A
/// store reopened from it sees what was written, like a restart.
#[cfg(feature = "daemon")]
pub(crate) struct FlakyStore {
    held: Arc<Mutex<BTreeMap<String, CultCacheEnvelope>>>,
    pushes_allowed: AtomicUsize,
}

#[cfg(feature = "daemon")]
impl FlakyStore {
    pub(crate) fn new(pushes_allowed: usize) -> Self {
        Self {
            held: Arc::default(),
            pushes_allowed: AtomicUsize::new(pushes_allowed),
        }
    }

    /// A store over the same records that accepts `pushes_allowed` more writes.
    pub(crate) fn reopened(&self, pushes_allowed: usize) -> Self {
        Self {
            held: self.held.clone(),
            pushes_allowed: AtomicUsize::new(pushes_allowed),
        }
    }
}

#[cfg(feature = "daemon")]
impl CacheBackingStore for FlakyStore {
    fn pull_all(&self) -> anyhow::Result<Vec<CultCacheEnvelope>> {
        Ok(self.held.lock().unwrap().values().cloned().collect())
    }

    fn push(&mut self, entry: &CultCacheEnvelope) -> anyhow::Result<()> {
        let allowed = self.pushes_allowed.load(Ordering::SeqCst);
        if allowed == 0 {
            return Err(anyhow::anyhow!("ledger write refused"));
        }
        self.pushes_allowed.store(allowed - 1, Ordering::SeqCst);
        self.held
            .lock()
            .unwrap()
            .insert(entry.key.clone(), entry.clone());
        Ok(())
    }

    fn delete(&mut self, entry: &CultCacheEnvelope) -> anyhow::Result<()> {
        self.held.lock().unwrap().remove(&entry.key);
        Ok(())
    }

    fn push_all(
        &mut self,
        entries: &[CultCacheEnvelope],
        _options: PushAllOptions,
    ) -> anyhow::Result<()> {
        *self.held.lock().unwrap() = entries
            .iter()
            .map(|entry| (entry.key.clone(), entry.clone()))
            .collect();
        Ok(())
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

/// Generous next to the fixture request's worst case (about 64,000), so it
/// binds only in the tests that are about spend.
pub(crate) const MAX_COST: u64 = 10_000_000;

/// What the fixture usage (10 input and 3 output tokens) costs under
/// [`fixture_price`]: 10 x 3,000,000 + 3 x 15,000,000 = 75,000,000 / 1e6.
pub(crate) const FIXTURE_USAGE_COST: u64 = 75;

pub(crate) fn invocation() -> TransportInvocation {
    TransportInvocation::new("epiphany-yggdrasil", 2_000, [7; 32], MAX_COST, request()).unwrap()
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
        cost_micro_usd: FIXTURE_USAGE_COST,
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
/// A price with a distinct nonzero rate per class, so a swapped rate changes a cost.
#[cfg(feature = "daemon")]
pub(crate) fn fixture_price() -> ModelPrice {
    ModelPrice {
        rates: Rates {
            input: 3_000_000,
            cache_write_short: 3_750_000,
            cache_write_long: 6_000_000,
            cache_read: 300_000,
            output: 15_000_000,
        },
        long_context: None,
        overhead_tokens: 100,
    }
}

#[cfg(feature = "daemon")]
pub(crate) fn fixture_prices() -> PriceTable {
    PriceTable::from([("gpt-5.4".to_string(), fixture_price())])
}

/// Far above anything a fixture request reserves: the ceiling binds only in
/// the tests that are about it.
#[cfg(feature = "daemon")]
pub(crate) const CEILING: u64 = 1 << 40;
#[cfg(feature = "daemon")]
pub(crate) const WINDOW_MS: u64 = 3_600_000;

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
        CEILING,
        WINDOW_MS,
    )
    .unwrap()
}

#[cfg(feature = "daemon")]
pub(crate) fn open_service(store: &TestStore, max_concurrent_requests: usize) -> TransportService {
    TransportService::open(
        &store.path,
        "fixture-sse",
        fixture_prices(),
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
    TransportInvocation::new(caller_runtime_id, 2_000, [7; 32], MAX_COST, request).unwrap()
}
