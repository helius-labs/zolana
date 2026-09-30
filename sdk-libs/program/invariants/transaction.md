# Transaction Invariants

Covers `TxContext`, `ConfidentialTransaction::check` and `PublicInputs` of
`src/circuit/protocol/transaction.rs`: the output blindings, `private_tx_hash`,
`transaction_hash`, the public hash and the value balance, against the native
`zolana-transaction` `FinalizedTransaction`. Invariants every type shares live in
`cross-cutting.md`. ID prefix: `INV-TX`; the tests live in
`tests/unit/protocol/transaction/`.

`tests/unit/protocol/transaction/fixtures.rs` holds the fixtures. The program shapes are
`Circuit`s that build a transaction and `check` it:

- `Refresh`: one input returned whole as change.
- `Payment`: three input slots, the last a dummy, and a payment to a public recipient.
- `Fund`: a token input funds a counter data input whose count goes up by one.
- `Settle`: a deposit and a withdrawal on one input.
- `Swept<ALL>`: a burned input, withdrawn whole when `ALL`.
- `Forgotten`: a payment whose destination is never added.
- `Unspent`: a new data UTXO funded by a deposit, with nothing spent.

`Asserted<P>` wraps a shape and asserts the three hashes `check` returns against the native
`Expected` values:

- "the private transaction hash is the native one"
- "the transaction hash is the native one"
- "the public hash is the native one"

`Checked<P>` runs a shape's `check` alone. The native reference (`reference.rs`) rebuilds every
shape with `zolana_transaction::ConfidentialTransaction` (blinding seed, output tree, outputs,
settlements, canonical padding, `finalize`), then hashes it:

- the private transaction hash with `padding_independent_private_tx_hash`
- the transaction hash with `program::transaction_hash`
- the public hash with Poseidon over the public fields and the transaction hash

The wallets (`wallets.rs`) are deterministic keypairs and blindings.

### Native equivalence

- [x] **INV-TX-01: every shape reproduces the native private transaction, transaction and public hashes**
  - Covered by: `tests/unit/protocol/transaction/native.rs` `every_shape_reproduces_the_native_private_transaction_and_public_hashes`; `tests/unit/protocol/transaction/properties.rs` `every_random_payment_reproduces_the_native_hashes` (property); `tests/unit/protocol/transaction/properties.rs` `every_random_seed_and_output_tree_reproduces_the_native_hashes` (property)
  - Kind: native equivalence
  - Statement: the native run of `Asserted` returns exactly `Ok(())` for four refreshes, three payments, two fundings, two settlements and a sweep, for every random payment split and amount, and for every random blinding seed, output tree and first-input latest tree: `check`'s output blindings, commitments, input and output hash chains, private blinding, transfer chain and public hash all equal the native `FinalizedTransaction`'s.
  - Location: `src/circuit/protocol/transaction.rs:182-251` (`fn check`), `src/circuit/protocol/transaction.rs:43-77` (the blindings), `src/circuit/protocol/transaction.rs:258-271` (`fn transaction_hash`)
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/transaction/native.rs`, `tests/unit/protocol/transaction/properties.rs`

- [x] **INV-TX-02: the output tree is the context's tree, else the first input's latest tree**
  - Covered by: `tests/unit/protocol/transaction/native.rs` `every_shape_reproduces_the_native_private_transaction_and_public_hashes`; `tests/unit/protocol/transaction/native.rs` `the_hashes_bind_the_blinding_seed_the_output_tree_the_transfers_and_the_public_inputs`
  - Kind: native equivalence
  - Statement: a refresh into tree 0 or 2 by context, into the first input's latest tree 7 with no context tree, and into tree 2 over the latest tree 7 each reproduce the native hashes; the reference built with tree 7 for the last one breaks exactly the private transaction hash rule.
  - Location: `src/circuit/protocol/transaction.rs:23-36` (`fn output_tree_id`)
  - Severity: Critical
  - Suggested test: positive + negative; `tests/unit/protocol/transaction/native.rs`

- [x] **INV-TX-03: each hash binds exactly its own part of the transaction**
  - Covered by: `tests/unit/protocol/transaction/native.rs` `the_hashes_bind_the_blinding_seed_the_output_tree_the_transfers_and_the_public_inputs`
  - Kind: native equivalence
  - Statement: against the reference with another blinding seed, a refresh breaks exactly the private transaction hash rule; with another settlement account, a settlement breaks exactly the transaction hash rule, its private hash still matching; with another recipient in the public fields, a payment breaks exactly the public hash rule.
  - Location: `src/circuit/protocol/transaction.rs:232-239`, `src/circuit/protocol/transaction.rs:258-271` (`fn transaction_hash`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/transaction/native.rs`

- [x] **INV-TX-04: each hash that differs from the native one breaks exactly its rule**
  - Covered by: `tests/unit/protocol/transaction/native.rs` `each_hash_that_differs_from_the_native_one_breaks_exactly_its_rule`
  - Kind: native equivalence
  - Statement: for the SOL refresh, the native private transaction, transaction or public hash increased by 1 returns exactly `RuleBroken` with that hash's rule, located in the fixture's file.
  - Location: `src/circuit/protocol/transaction.rs:104-116` (the `CheckedTransaction` accessors)
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/transaction/native.rs`

- [x] **INV-TX-05: the public hash is the program's PublicInputs hash of the transaction hash**
  - Covered by: `tests/unit/protocol/transaction/native.rs` `every_shape_reproduces_the_native_private_transaction_and_public_hashes`
  - Kind: native equivalence
  - Statement: for `NoFields` (Poseidon of the transaction hash alone) and `Recipient` (Poseidon of the recipient's owner hash and the transaction hash), `check`'s public hash is exactly the native Poseidon over the same fields.
  - Location: `src/circuit/protocol/transaction.rs:79-81` (`trait PublicInputs`), `src/circuit/protocol/transaction.rs:239`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/transaction/native.rs`

- [x] **INV-TX-22: only a trailing token output of zero becomes an empty slot**
  - Covered by: `tests/unit/protocol/transaction/native.rs` `only_a_trailing_token_output_of_zero_becomes_an_empty_slot`; `tests/unit/protocol/transaction/native.rs` `every_shape_reproduces_the_native_private_transaction_and_public_hashes`; `macros/tests/scenarios/s01_sol_payment.rs` `sol_payment_of_the_whole_balance_leaves_an_empty_change`
  - Kind: native equivalence
  - Statement: the finalized transaction has exactly one output slot per `check` output, in order. A `TokenUtxos` output of zero that only empty outputs follow is an ownerless empty UTXO: the zero payment of "7 + 0 SOL pays 0" and the zero change of "9 USDC deposits 1 and withdraws all 10". A zero change that a real output follows keeps its owner at amount 0, since dummies come last: "1 + 2 USDC pays 3" and "40 SOL moves all 40 into a counter holding 2". Every nonzero token output keeps its owner and amount, and a data output keeps its owner at a zero balance (a counter funded with 0). The empty slot commits as the dummy UTXO under its slot's derived blinding and adds 0 to the private output chain, so the private transaction hash stays the native one (INV-TX-01).
  - Location: `src/circuit/protocol/utxo/output.rs` (`Output::is_empty`, `Output::hash`), `src/circuit/protocol/transaction.rs` (`CheckedOutput::private_hash`), `src/client/utxo.rs` (`output_utxos`)
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/transaction/native.rs`

### Constraint

- [x] **INV-TX-06: every shape has exactly its pinned size and digest**
  - Covered by: `tests/unit/protocol/transaction/r1cs.rs` `every_shape_has_exactly_the_pinned_size_and_digest`
  - Kind: constraint
  - Statement: `Asserted` over a refresh, a payment, a funding and a settlement has exactly 4134, 9624, 8853 and 6404 constraints over 4141, 9630, 8861 and 6410 variables, with the R1CS sha256 digests pinned in the test. Each `TokenUtxos` output adds a zero test for its emptiness; a data output adds none.
  - Location: `src/circuit/protocol/transaction.rs:182-251` (`fn check`)
  - Severity: High
  - Suggested test: positive (digest); `tests/unit/protocol/transaction/r1cs.rs`

- [x] **INV-TX-07: the value and tree rules own rows exactly where a value is variable**
  - Covered by: `tests/unit/protocol/transaction/r1cs.rs` `the_balance_and_tree_rules_own_rows_only_where_a_value_is_variable`
  - Kind: constraint
  - Statement: "value leaves the transaction: a utxo was not added" owns exactly one row in a payment and a funding, whose transfers move a variable amount, and none in a refresh or a settlement, whose transferred total is the constant 0; the output tree rule owns exactly one row in every shape.
  - Location: `src/circuit/protocol/transaction.rs:195-203`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/transaction/r1cs.rs`

### Completeness

- [x] **INV-TX-08: every refresh and one of each other shape checks exactly its pinned count**
  - Covered by: `tests/unit/protocol/transaction/r1cs.rs` `every_refresh_and_one_of_each_other_shape_checks_exactly_the_pinned_count`
  - Kind: completeness
  - Statement: `check_constraints` returns exactly `Ok(4134)` for all four refreshes, whichever output tree they select, and exactly `Ok(9624)`, `Ok(8853)` and `Ok(6404)` for a payment, a funding and a settlement: the setup matrices over the placeholder and the proving matrices agree.
  - Location: `src/prover/synthesis.rs` (`fn check`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/transaction/r1cs.rs`

### Soundness

- [x] **INV-TX-09: only the first nullifier enters the program circuit, and the other spend values are carried**
  - Covered by: `tests/unit/protocol/transaction/r1cs.rs` `only_the_first_nullifier_enters_the_program_circuit_and_the_rest_are_carried`
  - Kind: soundness
  - Statement: in a payment, tampering the first input's nullifier breaks a row of "a poseidon hash" (the blindings), and its latest tree a row of "the transaction's outputs and hashes"; tampering the second or third input's nullifier or latest tree leaves every row satisfied, because the shielded pool circuit checks them.
  - Location: `src/circuit/protocol/transaction.rs:199-205`, `src/circuit/protocol/utxo/input.rs:24-30` (`SpentInput`)
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/transaction/r1cs.rs`

- [x] **INV-TX-10: each tampered hash claim breaks exactly its rule**
  - Covered by: `tests/unit/protocol/transaction/r1cs.rs` `each_tampered_hash_claim_breaks_exactly_its_rule`
  - Kind: soundness
  - Statement: for the SOL refresh, tampering the private transaction, transaction and public hash claims breaks exactly their own rules inside their own rows.
  - Location: `src/circuit/protocol/transaction.rs:182-251` (`fn check`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/transaction/r1cs.rs`

- [x] **INV-TX-11: a tampered context breaks its range, booleanity or output rows**
  - Covered by: `tests/unit/protocol/transaction/r1cs.rs` `a_tampered_context_breaks_its_range_or_booleanity_row`
  - Kind: soundness
  - Statement: in a payment, tampering the output tree id breaks exactly the u16 range rule and the "uses the output tree" flag (1 to 2) exactly the bool rule; in a refresh that uses the first input's latest tree, flipping the flag to 1 breaks a row of "the transaction's outputs and hashes".
  - Location: `src/conversion/transaction.rs:4-14`, `src/circuit/protocol/transaction.rs:23-36` (`fn output_tree_id`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/transaction/r1cs.rs`

- [x] **INV-TX-12: no variable is free, and only carried spend values are tolerated**
  - Covered by: `tests/unit/protocol/transaction/r1cs.rs` `no_variable_is_free_and_only_carried_spend_values_are_tolerated`
  - Kind: soundness
  - Statement: `check_private_variables` reports no free variable for a refresh, a payment, a funding and a settlement, and exactly 0, 7, 2 and 0 tolerated ones.
  - Location: `src/prover/synthesis.rs` (`fn unconstrained_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/transaction/r1cs.rs`

- [ ] **INV-TX-13: Picus proves a whole transaction deterministic**
  - Partial coverage: `tests/unit/protocol/transaction/picus.rs` `picus_finds_no_counterexample_for_a_whole_refresh_within_its_limit` runs Picus on the refresh's Picus export, bounded at 30 s, and asserts only that it finds no counterexample: the run ends `Unknown` (the Poseidon rounds and byte checks exceed the bound), so INV-TX-10 to -12 are the hermetic substitutes.
  - Kind: soundness
  - Statement: Picus reports exactly Safe for the refresh's Picus export.
  - Location: `src/circuit/protocol/transaction.rs`
  - Severity: Medium
  - Suggested test: external (Picus); `tests/unit/protocol/transaction/picus.rs`

- [x] **INV-TX-23: a prover cannot flip whether a token output is empty**
  - Covered by: `tests/unit/protocol/transaction/r1cs.rs` `a_prover_cannot_flip_whether_a_token_output_is_empty_and_only_a_zero_amounts_hint_is_free`
  - Kind: soundness
  - Statement: in the payment with change 100 and the payment with change 0, tampering the emptiness bit of either token output breaks a row of "an equality test", and so does tampering the equality hint of a nonzero amount. Only the hint of the zero change leaves every row satisfied: `0 * hint = 0` holds for any hint, and the bit it would have to flip stays constrained.
  - Location: `src/circuit/protocol/utxo/output.rs` (`Output::is_empty`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/transaction/r1cs.rs`

### Error

- [x] **INV-TX-14: a malformed transaction breaks exactly its rule**
  - Covered by: `tests/unit/protocol/transaction/native.rs` `a_malformed_transaction_breaks_exactly_its_rule`
  - Kind: error
  - Statement: natively, located in the fixture's file, each of these returns exactly `RuleBroken`: a forgotten destination with "value leaves the transaction: a utxo was not added"; a deposit alone with "a transaction spends at least one input"; neither a context tree nor a latest tree with the output tree rule; a counter at 2^64 - 1 with "the counter overflows"; a burned input left holding its balance with "a burned token utxo leaves a balance".
  - Location: `src/circuit/protocol/transaction.rs:182-203` (`fn check`), `src/circuit/protocol/utxo/token.rs:69-83` (`fn change`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/transaction/native.rs`

- [x] **INV-TX-15: the prover refuses value that leaves the transaction**
  - Covered by: `tests/unit/protocol/transaction/r1cs.rs` `the_prover_refuses_value_that_leaves_the_transaction`
  - Kind: error
  - Statement: `check_constraints` of the forgotten payment returns exactly `CircuitError.RuleBroken` before any proof: the prover refuses to synthesize a transaction that leaks value.
  - Location: `src/circuit/protocol/transaction.rs:195-198`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/transaction/r1cs.rs`

### Interop

- [x] **INV-TX-16: snarkjs accepts every honest refresh and rejects each tampered hash claim**
  - Covered by: `tests/unit/protocol/transaction/external.rs` `snarkjs_accepts_every_honest_refresh_and_rejects_each_tampered_hash_claim`
  - Kind: interop
  - Statement: for every refresh, `snarkjs wtns check` accepts the refresh R1CS with the honest assignment and rejects it with each of the three hash claims increased by 1.
  - Location: `src/prover/snarkjs.rs` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/transaction/external.rs`

- [x] **INV-TX-17: snarkjs proves and verifies a whole refresh**
  - Covered by: `tests/unit/protocol/transaction/external.rs` `snarkjs_proves_and_verifies_a_whole_refresh`
  - Kind: interop
  - Statement: snarkjs Groth16 setup over a throwaway ptau, prove and verify accept the refresh R1CS with the assignment of the 2^64 - 1 USDC refresh, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/transaction/external.rs`

INV-TX summary: 17 (Critical 7, High 9, Medium 1); covered 16, partial 1 (INV-TX-13, Picus
`Unknown` within its bound).

- [x] **INV-TX-18: payment interoperability**
  - Covered by: `tests/unit/protocol/transaction/external.rs` `snarkjs_proves_a_payment_with_dummy_padding_and_rejects_changed_hashes`
  - Kind: interop
  - Statement: for the payment with two real inputs and a padded dummy, snarkjs accepts the exported witness, refuses each of its three hash claims increased by one, and verifies a Groth16 proof with no public signals.
  - Location: `src/circuit/protocol/transaction.rs` (`ConfidentialTransaction::check`), `src/prover/snarkjs.rs`
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/transaction/external.rs`

- [x] **INV-TX-19: data update interoperability**
  - Covered by: `tests/unit/protocol/transaction/external.rs` `snarkjs_proves_a_data_utxo_update_and_rejects_changed_hashes`
  - Kind: interop
  - Statement: for the counter update funded by a token input, snarkjs accepts the exported witness, refuses each of its three hash claims increased by one, and verifies a Groth16 proof with no public signals.
  - Location: `src/circuit/protocol/transaction.rs` (`ConfidentialTransaction::check`), `src/prover/snarkjs.rs`
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/transaction/external.rs`

- [x] **INV-TX-20: public transfer interoperability**
  - Covered by: `tests/unit/protocol/transaction/external.rs` `snarkjs_proves_public_deposit_and_withdrawal_and_rejects_changed_hashes`
  - Kind: interop
  - Statement: for the transaction containing a public deposit and withdrawal, snarkjs accepts the exported witness, refuses each of its three hash claims increased by one, and verifies a Groth16 proof with no public signals.
  - Location: `src/circuit/protocol/transaction.rs` (`ConfidentialTransaction::check`), `src/prover/snarkjs.rs`
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/transaction/external.rs`

- [ ] **INV-TX-21: Picus proves data updates and public settlements deterministic**
  - Partial coverage: `tests/unit/protocol/transaction/picus.rs` `picus_checks_a_data_update_and_public_settlements_within_their_limits` rejects Unsafe under a 30-second bound per circuit, accepting Unknown without claiming a determinism proof.
  - Kind: soundness
  - Statement: Picus reports exactly Safe for both the funding and settlement Picus exports.
  - Location: `src/circuit/protocol/transaction.rs` (`ConfidentialTransaction::check`)
  - Severity: Medium
  - Suggested test: external (Picus); `tests/unit/protocol/transaction/picus.rs`
