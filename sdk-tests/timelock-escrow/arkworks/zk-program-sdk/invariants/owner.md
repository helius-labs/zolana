# Owner Invariants

Covers `OwnerKey` and `Owner` of `src/circuit/protocol/owner.rs`: `identity`, `hash`, the
tag check, `DataHash`, and their `Assert` and `Select` impls, against the native
`zolana-keypair` owner hash. Invariants every type shares live in `cross-cutting.md`. ID
prefix: `INV-OWNER`; the tests live in `tests/unit/protocol/owner/`. No invariant is
extracted yet: run [`PROMPT.md`](PROMPT.md) for this area.
