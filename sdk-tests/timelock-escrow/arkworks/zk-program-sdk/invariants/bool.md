# Bool Invariants

Covers `Bool` of `src/circuit/builtins/types/boolean.rs`: `constant`,
`TryFrom<CircuitVar>`, `not`, `and`, `or`, `xor`, `nand`, `implies`, `all`, `any`,
`select`, the `assert_*` methods and its `Assert` and `Select` impls. Invariants every
builtin shares live in `cross-cutting.md`. ID prefix: `INV-BOOL`; the tests live in
`tests/unit/bool/`. No invariant is extracted yet: run [`PROMPT.md`](PROMPT.md) for this
area.
