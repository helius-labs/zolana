# Gadget Invariants

Covers the gadgets of `src/circuit/builtins/gadgets/`. Invariants every builtin shares
live in `cross-cutting.md`. ID prefixes: `INV-POSEIDON`, `INV-HASH-BYTES`,
`INV-HASH-CHAIN`, `INV-MEMBER`, `INV-INDEX`; the tests live in `tests/unit/gadgets/`. No
invariant is extracted yet: run [`PROMPT.md`](PROMPT.md) for this area.

## Poseidon (`poseidon`)

`INV-POSEIDON`

## Byte hashing (`hash_bytes`)

`INV-HASH-BYTES`

## Hash chain (`nonzero_hash_chain`)

`INV-HASH-CHAIN`

## Membership (`is_in`, `assert_in`)

`INV-MEMBER`

## Indexing (`one_hot`, `select_index`)

`INV-INDEX`
