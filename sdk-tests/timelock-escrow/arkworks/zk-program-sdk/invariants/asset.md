# Asset Invariants

Covers `Asset` of `src/circuit/protocol/asset.rs`: `hash`, `sol`, `constant`, and its
`Assert` and `Select` impls, against the native `zolana-hasher` and `zolana-transaction`
values. Invariants every type shares live in `cross-cutting.md`. ID prefix: `INV-ASSET`;
the tests live in `tests/unit/protocol/asset/`. No invariant is extracted yet: run
[`PROMPT.md`](PROMPT.md) for this area.
