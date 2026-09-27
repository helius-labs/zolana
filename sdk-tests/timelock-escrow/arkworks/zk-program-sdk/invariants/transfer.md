# PublicTransfer Invariants

Covers `PublicTransfer` of `src/circuit/protocol/transfer.rs`: `hash`, against the native
`PublicTransfer::hash` and `transaction_hash` of `src/program/transfer.rs`. Invariants every
type shares live in `cross-cutting.md`. ID prefix: `INV-TRANSFER`; the tests live in
`tests/unit/protocol/transfer/`.

The circuit `PublicTransfer` and its `hash` are `pub(crate)`: a transfer is created only by
`Balance::deposit` and `withdraw` and hashed only inside `ConfidentialTransaction::check`, so
no public fixture can instantiate it. Its R1CS rows, soundness, setup/proving shape, snarkjs
interop and Picus run are therefore covered through the transaction flows in
`transaction.md` (`INV-TX`, W8), not here. This file covers the native reference those flows
are compared against, `program::PublicTransfer::hash` and `program::transaction_hash`,
against a reference written out from `zolana-hasher` in `tests/unit/protocol/transfer/vectors.rs`
(`hash_bytes`, `right_align`, `Poseidon::hashv`), and pins that the public builtins the
circuit's `hash` composes (`Asset::constant(..).hash()`, `constant`, `Bytes::hash_bytes`,
`poseidon`) give the native hash on constants. The vectors deposit and withdraw SOL and USDC,
with amounts 0, 1, 2^32 and 2^64 - 1, the zero account, an account of 255s, and a mint equal
to the account.

## PublicTransfer (`hash`, `transaction_hash`)

### Native equivalence
- [x] **INV-TRANSFER-01: the transfer hash is Poseidon of the asset hash, amount, direction and account hash**
  - Covered by: `tests/unit/protocol/transfer/native.rs` `the_transfer_hash_is_poseidon_of_asset_hash_amount_direction_and_account_hash`; `tests/unit/protocol/transfer/properties.rs` `every_transfer_hashes_to_the_reference_hash` (property)
  - Kind: native equivalence
  - Statement: for every transfer vector and every random transfer, `PublicTransfer::hash` is exactly `Poseidon(hash_bytes(mint), right_align(amount as 8 big-endian bytes), right_align([is_deposit as u8]), hash_bytes(account))`.
  - Location: `src/program/transfer.rs:12-25` (`fn hash`), `src/program/transfer.rs:40-46` (`fn integer`)
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/transfer/native.rs`, `tests/unit/protocol/transfer/properties.rs`

- [x] **INV-TRANSFER-02: the public builtins the circuit hash composes give the native hash on constants**
  - Covered by: `tests/unit/protocol/transfer/native.rs` `the_public_builtins_the_circuit_transfer_hash_composes_give_the_native_hash_on_constants`
  - Kind: native equivalence
  - Statement: for every transfer vector, the value of `poseidon([Asset::constant(mint).hash(), constant(amount), constant(is_deposit), Bytes::constant(account).hash_bytes()])` is exactly `PublicTransfer::hash`.
  - Location: `src/circuit/protocol/transfer.rs:14-23` (`fn hash`, crate-private), `src/program/transfer.rs:12-25`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/transfer/native.rs`

### Semantics
- [x] **INV-TRANSFER-03: every single field change changes the transfer hash**
  - Covered by: `tests/unit/protocol/transfer/native.rs` `every_single_field_change_changes_the_transfer_hash`
  - Kind: semantics
  - Statement: for every transfer vector and each change of exactly one of the mint, the direction, the amount (lowest bit flipped) and the account, the changed transfer's hash is exactly the reference hash of the change and differs from the original's.
  - Location: `src/program/transfer.rs:12-25`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/transfer/native.rs`

- [x] **INV-TRANSFER-04: with no transfer the transaction hash is the private hash**
  - Covered by: `tests/unit/protocol/transfer/native.rs` `with_no_transfer_the_transaction_hash_is_the_private_hash`; `tests/unit/protocol/transfer/properties.rs` `every_transaction_hash_is_the_chain_definition` (property)
  - Kind: semantics
  - Statement: for every private hash, `transaction_hash(private, [])` is exactly `Ok(private)`.
  - Location: `src/program/transfer.rs:27-38` (`fn transaction_hash`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/protocol/transfer/native.rs`, `tests/unit/protocol/transfer/properties.rs`

- [x] **INV-TRANSFER-05: the transaction hash chains the transfer hashes from zero, then hashes with the private hash**
  - Covered by: `tests/unit/protocol/transfer/native.rs` `the_transaction_hash_chains_the_transfer_hashes_from_zero_then_hashes_with_the_private_hash`; `tests/unit/protocol/transfer/properties.rs` `every_transaction_hash_is_the_chain_definition` (property)
  - Kind: semantics
  - Statement: for every non-empty prefix of the transfer vectors and every random list of 1 to 3 transfers with a canonical private hash, `transaction_hash` is exactly `Poseidon(private, c_n)` where `c_0 = 0` and `c_i = Poseidon(c_{i-1}, hash(transfer_i))`.
  - Location: `src/program/transfer.rs:27-38`
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/transfer/native.rs`, `tests/unit/protocol/transfer/properties.rs`

- [x] **INV-TRANSFER-06: the transaction hash depends on the transfer order and the private hash**
  - Covered by: `tests/unit/protocol/transfer/native.rs` `the_transaction_hash_depends_on_the_transfer_order_and_the_private_hash`
  - Kind: semantics
  - Statement: for two distinct transfers, swapping their order changes the transaction hash, so does changing the private hash, and one transfer's transaction hash differs from the private hash.
  - Location: `src/program/transfer.rs:27-38`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/transfer/native.rs`

### Error
- [x] **INV-TRANSFER-07: a private hash of at least p is refused exactly when a transfer is chained to it**
  - Covered by: `tests/unit/protocol/transfer/native.rs` `a_private_hash_of_at_least_p_is_refused_exactly_when_a_transfer_is_chained_to_it`
  - Kind: error
  - Statement: for the private hash equal to the big-endian bytes of p, `transaction_hash` with no transfer returns exactly `Ok(p)` unchecked, and with one transfer exactly the hasher error "Poseidon hasher error: Input is larger than the modulus of the prime field.".
  - Location: `src/program/transfer.rs:27-38`
  - Error: `HasherError` (native)
  - Severity: Medium
  - Suggested test: negative; `tests/unit/protocol/transfer/native.rs`

## Summary

- Total: 7 (Critical 2, High 4, Medium 1); covered 7, partial 0; findings: none.
- `INSUFFICIENT_INFO`: none. The Constraint, Completeness, Soundness, Shape and Interop cells
  of the circuit `PublicTransfer::hash` stay with `transaction.md` (W8): it is crate-private
  and reachable only through `ConfidentialTransaction::check`.
