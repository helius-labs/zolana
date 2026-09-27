# Bytes Invariants

Covers `Bytes<N>` of `src/circuit/builtins/types/bytes.rs`: `constant`, the
`TryFrom<CircuitVar>` and `TryFrom<Bytes>` conversions, `bytes`, and its `Assert` and
`Select` impls. The `hash_bytes` gadget is in `gadgets.md`. Invariants every builtin
shares live in `cross-cutting.md`. ID prefix: `INV-BYTES`; the tests live in
`tests/unit/bytes/`. No invariant is extracted yet: run [`PROMPT.md`](PROMPT.md) for this
area.
