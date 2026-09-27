# Transaction Invariants

Covers `TxContext`, `ConfidentialTransaction::check` and `PublicInputs` of
`src/circuit/protocol/transaction.rs`: the output blindings, `private_tx_hash`,
`transaction_hash`, the public hash and the value balance, against the native
`zolana-transaction` `FinalizedTransaction`. Invariants every type shares live in
`cross-cutting.md`. ID prefix: `INV-TX`; the tests live in
`tests/unit/protocol/transaction/`. No invariant is extracted yet: run
[`PROMPT.md`](PROMPT.md) for this area.
