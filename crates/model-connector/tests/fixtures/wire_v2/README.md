# Golden v2 wire fixtures

Bytes of the v2 connector wire, produced once by CodexConnector at commit
`fd7cec4176f4e3f9a5aaa75e77ba10ce5e1522f8`. Ghostlight pins CodexConnector
`68fe94b`, not that commit; `src/lib.rs`, the whole v2 wire, is identical in
both, so these bytes are Ghostlight's wire. They are pinned by `tests/wire_golden_v2.rs`, so the kit cannot drift from
them. No CodexConnector code or dependency is part of this repository.

Generator: `generator.rs` (not compiled here). Command, run in a clone of
CodexConnector at that commit:

    cp <ModelConnector>/crates/model-connector/tests/fixtures/wire_v2/generator.rs examples/gen_wire_v2.rs
    cargo run --locked -q --example gen_wire_v2

It prints `FIXTURE <name> <hex>` lines; each file is the hex decoded. It was
run on Yggdrasil through the verify container with codex-connector at that
commit as a dev-dependency of the kit at d1d28f0 (same source). The `.mp`
files are rmp-serde output; `envelope_*` files carry random nonces and
AES-256-GCM ciphertext sealed under the connection key
`parity-distinct-test-key`. Regenerating changes the envelopes' bytes; the
plaintext fixtures must regenerate byte-identically.
