# Cross-Cutting Invariants

Invariants that hold for every builtin and every fixture. Each entry lists the builtins it
applies to; the per-builtin files reference these IDs instead of duplicating them. For now
the only builtin is `CircuitVar +`, whose fixtures cover every entry below.

## Native and R1CS runs

- [x] **INV-XC-01: the native and R1CS runs agree**
  - Covered by: `tests/unit/circuit_var/add/native.rs` `every_valid_vector_holds_natively_in_every_form`; `tests/unit/circuit_var/add/r1cs.rs` `the_proving_rows_accept_the_honest_sum_and_name_the_rule_for_another`; `tests/unit/circuit_var/add/properties.rs` `a_wrong_sum_is_refused_natively_and_in_r1cs` (property)
  - Kind: soundness
  - Affects: `CircuitVar +` (all nine operand forms)
  - Statement: for every fixture and every input, the native run returns Ok exactly when the proving assignment of that input satisfies every proving row: every valid vector passes both runs, and every wrong output fails both.
  - Location: `src/prover/synthesis.rs:302-357` (`impl Statement` for `Circuit` and `Constraints`: one circuit type, run natively and in R1CS)
  - Severity: Critical
  - Suggested test: positive + negative + property; `tests/unit/<type>/<op>/native.rs`, `r1cs.rs`, `properties.rs`

## Export format

- [x] **INV-XC-02: the exports are iden3 files that the reader and snarkjs parse**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_plus_b_exports_exactly_the_golden_row_and_header`; `tests/unit/circuit_var/add/r1cs.rs` `the_assignment_is_the_constant_one_then_the_variable_inputs`; `tests/unit/circuit_var/add/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_witness`
  - Kind: interop
  - Affects: `CircuitVar +`
  - Statement: for every fixture, `export_r1cs` writes an iden3 `.r1cs` (version 1) and `export_assignment` an iden3 `.wtns` (version 2) over the BN254 scalar field that both the harness reader (no trailing bytes, only canonical elements) and `snarkjs wtns check` parse.
  - Location: `src/prover/snarkjs.rs:10-69` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: positive + external (snarkjs); `tests/unit/<type>/<op>/r1cs.rs`, `external.rs`

## Setup and proving shape

- [x] **INV-XC-03: every fixture's setup and proving shapes match**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `every_valid_vector_checks_one_constraint_in_every_variable_form`; `tests/unit/circuit_var/add/r1cs.rs` `a_constant_other_than_the_placeholders_builds_another_constraint`; `tests/unit/circuit_var/add/r1cs.rs` `adding_allocates_no_variable_and_adds_no_constraint`
  - Kind: shape
  - Affects: `CircuitVar +` (the six variable operand forms, the unasserted fixture, and the three constant operand forms at the placeholder's constant 0)
  - Statement: for every fixture whose constants equal its placeholder's and every honest input, `check_constraints` returns exactly `Ok(<the fixture's constraint count>)`: the setup synthesis and the proving synthesis have the same shape and the same rows.
  - Location: `src/prover/synthesis.rs:400-424` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/<type>/<op>/r1cs.rs`

## Constraint-only statement (`ZkCircuit`)

- [x] **INV-XC-04: a constraint-only circuit has no public input**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_plus_b_exports_exactly_the_golden_row_and_header`; `tests/unit/circuit_var/add/r1cs.rs` `adding_allocates_no_variable_and_adds_no_constraint`
  - Kind: constraint
  - Affects: every `ZkCircuit` fixture (`CircuitVar +`)
  - Statement: for every `ZkCircuit` fixture, the exported header has exactly 0 public inputs and 0 public outputs: the constant one is the only instance variable.
  - Location: `src/prover/synthesis.rs:334-357` (`impl Statement<NoPublicInputs>`), `src/prover/synthesis.rs:228-233` (`fn check_public_inputs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/<type>/<op>/r1cs.rs`

- [x] **INV-XC-05: a constraint-only circuit has no public hash to tamper**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_constraint_only_circuit_has_no_public_hash_to_tamper`
  - Kind: error
  - Affects: every `ZkCircuit` fixture (`CircuitVar +`)
  - Statement: for every `ZkCircuit` fixture, `check_tampered` with `Tamper::PublicHash` returns exactly `ProverError.WrongPublicInputCount`.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`)
  - Error: `ProverErrorKind::WrongPublicInputCount`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/<type>/<op>/r1cs.rs`
