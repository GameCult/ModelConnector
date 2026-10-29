# ModelConnector

The connector kit for GameCult minds: one typed, encrypted, replay-safe contract
between a caller that needs a model turn and a daemon that holds the provider
credential, so no project wires its own provider calls.

Status: the `model-connector` crate and the `claude-connector` backend crate are live. No
connector binary exists yet (the Claude connector binary is first, then an OpenAI-compatible one).

## Entry points

Crate `crates/model-connector`:

- `src/contract.rs` - the v3 wire contract (`gamecult.model.*.v3`): `ProviderRequest`, `TransportInvocation`,
  `TransportResult`, `TransportReceipt`, the typed `StopReason`, `FailureKind` and `Refusal`,
  `InputItem::ReasoningState` (a provider's opaque reasoning block, replayed by callers
  verbatim via `TransportResult::transcript_items`; the service refuses another provider's
  state in the in-flight tool exchange and drops it from earlier turns),
  and the canonical byte and digest functions that bind a result to its request. Every
  document is named MessagePack with unknown fields refused.
- `src/envelope.rs` - the AES-256-GCM `TransportEnvelope` (binary ciphertext), its
  identity-binding AAD, the length-prefixed framing, and the CultNet carriage: each frame is a
  `cultnet.operation_request.v0` / `operation_response.v0` for service
  `gamecult.model.connector`, operation `invoke` (or `spend_readout`), its `message_id` the
  request id and its payload the base64 of the sealed envelope. `spend_readout` answers a
  `SpendReadout` (`gamecult.model.spend_readout.v1`): each caller's spent and reserved
  micro-USD against its ceiling in its current window, and the backend's plan quota;
  `ConnectorClient::spend_readout` asks.
- `schemas/` - one JSON Schema per v3 document, generated from the types.
- `src/client.rs` - `ConnectorClient`, the one-request caller side.
- `src/service.rs` (feature `daemon`) - `TransportService`: caller admission, durable
  replay (a retried request is answered byte-identically and the provider runs once),
  in-flight and capacity refusals.
- `src/serve.rs` (feature `daemon`) - `serve()`, the loopback accept loop, over the
  `ProviderBackend` trait. A connector binary implements `ProviderBackend` for its
  provider and calls `serve`; the kit names no provider.

Crate `crates/claude-connector` (library only; the binary that wires it to `serve` is not written):

- `ClaudeCodeBackend` implements `ProviderBackend` for provider `claude-code` by driving the
  unmodified `claude` binary, one child per call, in print stream-json mode with no tools, no MCP
  servers, no settings sources and the system prompt replaced. Tool-less turns only: a request
  with tools or a final tool result is refused before any spawn. A request's output schema goes
  to the CLI as `--json-schema` and the result's structured output is the one assistant text.
- Reasoning state is a session handle (`ClaudeCodeHandle`); a handle that cannot be proven to
  match the request re-seeds from the caller's transcript, and every resume forks.
- `ProcessPort` is the one OS seam (`StdProcessPort`, unix, kills the child's whole process
  group); `SessionStore` and `StderrSink` are the other ports. `ClaudeCodeConfig` is what the
  binary hands in; the credential is read from a systemd credential and reaches the child on a
  pipe (`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`), never in an environment. `QuotaCell` keeps the
  plan windows the CLI's `rate_limit_event`s report, for the spend readout.

Frame arithmetic is public in `src/envelope.rs`, measured on the carriage frame: `frame_bytes_for_payload(n)` is the frame a
caller payload bound of `n` needs, `payload_bytes_for_frame(frame)` is the largest payload bound
a frame allows, and `MAX_IDENTITY_BYTES` (256) bounds caller ids, request ids and model names.
`serve` refuses a frame/payload pair that violates them (`ServeError::FrameBound` states the frame
needed); the smallest legal frame is `frame_bytes_for_payload(MIN_PAYLOAD_BYTES)`. A request id past
the bound is refused on the wire as `Refusal::Malformed`, the reply echoing the id (the connection is dropped only if that reply cannot fit the frame); `ConnectorClient` refuses such an id locally with `RequestIdTooLong`.

The default feature set compiles contract, envelope and client only. The kit speaks v3
only: a v2 frame gets no answer.

## Verify

```
cargo test --locked --workspace
cargo test --locked --workspace --features model-connector/daemon
```

`crates/model-connector/tests/wire_golden_v3.rs` pins the v3 documents and one sealed carriage
frame to the fixtures in `crates/model-connector/tests/fixtures/wire_v3` (regenerate with
`WIRE_V3_REGENERATE=1`; see the fixtures' README), and
`crates/model-connector/tests/published_schemas.rs` fails when `schemas/` differs from the types
(`MODEL_CONNECTOR_REGENERATE_SCHEMAS=1` rewrites it).

## Provenance and license

AGPL-3.0-only. See `LICENSE`.

The contract, envelope, client, replay service and serve loop were lifted from
[CodexConnector](https://github.com/GameCult/CodexConnector) at fd7cec4, formerly
PolyForm Noncommercial. Its sole copyright holder relicensed the lifted material as
AGPL-3.0-only for this repository.
