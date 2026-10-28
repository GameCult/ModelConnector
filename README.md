# ModelConnector

The connector kit for GameCult minds: one typed, encrypted, replay-safe contract
between a caller that needs a model turn and a daemon that holds the provider
credential, so no project wires its own provider calls.

Status: the `model-connector` crate is live. No connector binary exists yet
(the Claude connector is first, then an OpenAI-compatible one).

## Entry points

Crate `crates/model-connector`:

- `src/contract.rs` - the v2 wire contract: `ProviderRequest`, `TransportInvocation`,
  `TransportResult`, `TransportReceipt`, `Refusal`, and the canonical byte and digest
  functions that bind a result to its request.
- `src/envelope.rs` - the AES-256-GCM `TransportEnvelope`, its identity-binding AAD, and
  the length-prefixed framing.
- `src/client.rs` - `ConnectorClient`, the one-request caller side.
- `src/service.rs` (feature `daemon`) - `TransportService`: caller admission, durable
  replay (a retried request is answered byte-identically and the provider runs once),
  in-flight and capacity refusals.
- `src/serve.rs` (feature `daemon`) - `serve()`, the loopback accept loop, over the
  `ProviderBackend` trait. A connector binary implements `ProviderBackend` for its
  provider and calls `serve`; the kit names no provider.

Frame arithmetic is public in `src/envelope.rs`: `frame_bytes_for_payload(n)` is the frame a
caller payload bound of `n` needs, `payload_bytes_for_frame(frame)` is the largest payload bound
a frame allows, and `MAX_IDENTITY_BYTES` (256) bounds caller ids, request ids and model names.
`serve` refuses a frame/payload pair that violates them (`ServeError::FrameBound` states the frame
needed); the smallest legal frame is `frame_bytes_for_payload(MIN_PAYLOAD_BYTES)`. A request id past
the bound is refused on the wire as `Refusal::Malformed`, the reply naming it by its SHA-256.

The default feature set compiles contract, envelope and client only. Schema ids are
still `gamecult.codex.*.v2`; renaming them changes the wire and belongs to a later
contract version.

## Verify

```
cargo test --locked --workspace
cargo test --locked --workspace --features model-connector/daemon
```

`tests/wire_parity_v2.rs` pins the kit byte-for-byte to CodexConnector fd7cec4 in both
directions (it fetches that revision as a dev-dependency).

## Provenance and license

AGPL-3.0-only. See `LICENSE`.

The contract, envelope, client, replay service and serve loop were lifted from
[CodexConnector](https://github.com/GameCult/CodexConnector) at fd7cec4, formerly
PolyForm Noncommercial. Its sole copyright holder relicensed the lifted material as
AGPL-3.0-only for this repository.
