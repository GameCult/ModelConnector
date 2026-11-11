# ModelConnector

The connector kit for GameCult minds: one typed, encrypted, replay-safe contract
between a caller that needs a model turn and a daemon that holds the provider
credential, so no project wires its own provider calls.

The connector meters nothing in dollars. It holds the subscription token, lends it, and
publishes the plan's usage windows (`usage_readout`, `claude_usage_readout` on the lease socket, and `plan_quota` on every lease grant) for the
minds to read and decide their own burn. The one usage-derived refusal is the provider's own
(`ProviderRejected`), repeated until its reset.

Status: the `model-connector` crate and the `claude-connector` backend crate and binary are live
(`claude-connector serve|config|ask`); an OpenAI-compatible connector is not written.

## Entry points

Crate `crates/model-connector`:

- `src/contract.rs` - the v4 wire contract (`gamecult.model.*.v4`): `ProviderRequest`, `TransportInvocation`,
  `TransportResult`, `TransportReceipt`, the typed `StopReason`, `FailureKind` and `Refusal`,
  `InputItem::ReasoningState` (a provider's opaque reasoning block, replayed by callers
  verbatim via `TransportResult::transcript_items`; the service refuses another provider's
  state in the in-flight tool exchange and drops it from earlier turns),
  and the canonical byte and digest functions that bind a result to its request. Every
  document is named MessagePack with unknown fields refused.
- `src/envelope.rs` - the AES-256-GCM `TransportEnvelope` (binary ciphertext), its
  identity-binding AAD, the length-prefixed framing, and the CultNet carriage: each frame is a
  `cultnet.operation_request.v0` / `operation_response.v0` for service
  `gamecult.model.connector`, operation `invoke` (or `usage_readout`), its `message_id` the
  request id and its payload the base64 of the sealed envelope. `usage_readout` answers a
  `UsageReadout` (`gamecult.model.usage_readout.v1`): the backend's plan quota windows, each with
  utilization, reset, status and age;
  `ConnectorClient::usage_readout` asks.
- `schemas/` - one JSON Schema per v4 document, generated from the types.
- `src/client.rs` - `ConnectorClient`, the one-request caller side.
- `src/service.rs` (feature `daemon`) - `TransportService`: caller admission, durable
  replay (a retried request is answered byte-identically and the provider runs once),
  in-flight and capacity refusals.
- `src/serve.rs` (feature `daemon`) - `serve()`, the loopback accept loop, over the
  `ProviderBackend` trait. A connector binary implements `ProviderBackend` for its
  provider and calls `serve`; the kit names no provider.

Crate `crates/claude-connector` (library and the `claude-connector` binary that wires it to `serve`):

- `ClaudeCodeBackend` implements `ProviderBackend` for provider `claude-code` by driving the
  unmodified `claude` binary, one child per call, in print stream-json mode with no tools, no MCP
  servers, no settings sources and the system prompt replaced. Tool-less turns only: a request
  with tools or a final tool result is refused before any spawn. A request's output schema goes
  to the CLI as `--json-schema` and the result's structured output is the one assistant text.
- Reasoning state is a session handle (`ClaudeCodeHandle`) authenticated with a connector secret
  and bound to the caller it was minted for; a handle that cannot be proven to match the request
  and its caller re-seeds from the caller's transcript, and every resume forks.
- `ProcessPort` is the one OS seam (`StdProcessPort`, unix, kills the child's whole process
  group); `SessionStore` and `StderrSink` are the other ports. `ClaudeCodeConfig` is what the
  binary hands in; the credential is read from a systemd credential and reaches the child on a
  pipe (`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`), never in an environment. `QuotaCell` keeps the
  plan windows the CLI's `rate_limit_event`s report, for the usage readout and the lease grant.

## Asking for one no-tools completion

`claude-connector ask` is a caller of a running connector for a Mind's Self run: the prompt is all
of stdin, the answer text is stdout.

```
claude-connector ask --caller-id ID --connection-key-file FILE --model MODEL (--system TEXT | --system-file FILE) [--endpoint HOST:PORT] [--effort low|medium|high|max] [--max-output-tokens N] [--timeout-secs N] < prompt > answer
```

Defaults: endpoint `127.0.0.1:4110`, 8192 output tokens, 300 s. The key is read from the file (the
same text the connector reads for the caller; never argv or environment). There is no tools flag,
no working-directory flag and no other endpoint: the request is built by `ProviderRequest::new`
(no tools) and the model child's cwd and environment stay the connector's. Any failure (refused,
over a cap, model not allowed, wrong key or caller, timeout, provider failure, empty answer, empty
stdin) exits nonzero with one `claude-connector: <cause>` line on stderr and nothing on stdout;
the line never carries the key, the prompt or the provider's message. Each run uses a fresh request
id. Code: `crates/claude-connector/src/ask.rs`; tests: `crates/claude-connector/tests/ask.rs`.

Frame arithmetic is public in `src/envelope.rs`, measured on the carriage frame: `frame_bytes_for_payload(n)` is the frame a
caller payload bound of `n` needs, `payload_bytes_for_frame(frame)` is the largest payload bound
a frame allows, and `MAX_IDENTITY_BYTES` (256) bounds caller ids, request ids and model names.
`serve` refuses a frame/payload pair that violates them (`ServeError::FrameBound` states the frame
needed); the smallest legal frame is `frame_bytes_for_payload(MIN_PAYLOAD_BYTES)`. A request id past
the bound is refused on the wire as `Refusal::Malformed`, the reply echoing the id (the connection is dropped only if that reply cannot fit the frame); `ConnectorClient` refuses such an id locally with `RequestIdTooLong`.

The default feature set compiles contract, envelope and client only. The kit speaks v4
only: a v2 frame gets no answer.

## Verify

```
cargo test --locked --workspace
cargo test --locked --workspace --features model-connector/daemon
```

`crates/model-connector/tests/wire_golden_v4.rs` pins the v4 documents and one sealed carriage
frame to the fixtures in `crates/model-connector/tests/fixtures/wire_v4` (regenerate with
`WIRE_V4_REGENERATE=1`; see the fixtures' README), and
`crates/model-connector/tests/published_schemas.rs` fails when `schemas/` differs from the types
(`MODEL_CONNECTOR_REGENERATE_SCHEMAS=1` rewrites it).

## Provenance and license

AGPL-3.0-only. See `LICENSE`.

The contract, envelope, client, replay service and serve loop were lifted from
[CodexConnector](https://github.com/GameCult/CodexConnector) at fd7cec4, formerly
PolyForm Noncommercial. Its sole copyright holder relicensed the lifted material as
AGPL-3.0-only for this repository.
