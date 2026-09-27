# Uint Invariants

Covers `Uint<BITS>` of `src/circuit/builtins/types/uint.rs`: construction and the
conversions between widths and from `Bool`, arithmetic and the checked operations,
comparisons and range checks, `div_rem`, and its `Assert` and `Select` impls. Invariants
every builtin shares live in `cross-cutting.md`. ID prefix: `INV-UINT`; the tests live in
`tests/unit/uint/`. No invariant is extracted yet: run [`PROMPT.md`](PROMPT.md) for this
area.
