# Assert and Select Invariants

Covers the `Assert` and `Select` traits of `src/circuit/builtins/ops/`: the trait-level
helpers and the `CircuitVar` and array impls. The impls for `Bool`, `Uint`, `Bytes` and
the protocol types are in their own files. Invariants every builtin shares live in
`cross-cutting.md`. ID prefixes: `INV-ASSERT`, `INV-SELECT`; the tests live in
`tests/unit/ops/`. No invariant is extracted yet: run [`PROMPT.md`](PROMPT.md) for this
area.

## Assert (`is_equal`, `assert_equal`, `assert_equal_if`, `assert_not_equal`, `all_equal`, `assert_all_equal`, `assert_all_equal_if`, `assert_equal_unless`)

`INV-ASSERT`

## Select (`select` on `CircuitVar` and arrays)

`INV-SELECT`
