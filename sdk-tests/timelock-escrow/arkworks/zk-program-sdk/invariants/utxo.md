# Utxo Invariants

Covers `src/circuit/protocol/utxo/`, against the native `zolana-keypair` and
`zolana-transaction` values. Invariants every type shares live in `cross-cutting.md`. ID
prefixes: `INV-UTXO`, `INV-LEDGER`, `INV-TOKEN`, `INV-DATA`; the tests live in
`tests/unit/protocol/{utxo,ledger,token,data}/`. No invariant is extracted yet: run
[`PROMPT.md`](PROMPT.md) for this area.

## Utxo (`hash`, the nullifier, `SpentInput`, `dummy`)

`INV-UTXO`

## Balance (`transfer`, `transfer_all`, `deposit`, `withdraw`, `withdraw_all` on `TokenUtxo` and `DataUtxo`)

`INV-LEDGER`

## TokenUtxo (`new_init`, `new_mut`, `new_burn`, dummies, change)

`INV-TOKEN`

## DataUtxo (`DataUtxo`, `UtxoData`, `checked_utxo_data`)

`INV-DATA`
