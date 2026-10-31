# lease_v2 fixtures

The exact bytes of the claude lease protocol v2: each file is one whole frame (a u32
big-endian length, then the named-MessagePack map `{kind, value}`).

- `request.bin`: `claude_lease_request`.
- `refusal_unknown_caller.bin`, `refusal_expired.bin`, `refusal_busy.bin`,
  `refusal_provider_rejected.bin`: `claude_lease_refusal`; `kind` is the variant name as a
  PascalCase string.
- `grant.bin`: `claude_lease_grant` with `lease_id` and `plan_quota` carrying `five_hour` and
  `seven_day` windows (utilization_permille, resets_at_unix_ms, status, observed_at_unix_ms).
  On the wire the grant travels with one SCM_RIGHTS fd; the file holds the frame only.

Huginn's lease client vendors these files from this repository and tests against the same
bytes. Generator: `tests/lease_wire_golden.rs`; run it with `LEASE_V2_REGENERATE=1`, then
review the diff: a changed byte is a wire change.
