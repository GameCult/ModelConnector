# wire_v3 fixtures

The named-MessagePack bytes of the v3 documents and one sealed carriage frame,
produced by the kit at the revision that added them. They pin drift; the types in
`src/contract.rs` own the shape, and `schemas/` publishes it.

- `provider_request.mp`, `transport_invocation.mp`, `transport_result_transported.mp`,
  `transport_result_refused.mp`, `transport_receipt_failed.mp`, `transport_envelope.mp`:
  the plaintext documents.
- `carriage_invocation.frame`: a `cultnet.operation_request.v0` for service
  `gamecult.model.connector`, operation `invoke`, whose payload is the base64 of an envelope
  sealed under the fixed test key in `tests/wire_golden_v3.rs`.

Generator: `tests/wire_golden_v3.rs` itself. Run it with `WIRE_V3_REGENERATE=1` to rewrite
the files from the kit, then review the diff: a changed byte is a wire change.
