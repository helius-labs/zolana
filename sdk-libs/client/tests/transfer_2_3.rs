//! End-to-end integration tests for the P256 `transfer` circuit at shape (2,3):
//! build a real witness, prove via the prover server, and cryptographically
//! verify against the committed `transfer_2_3` verifying key.
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `transfer_2_3.key` proving key available.

mod common;

use common::run_transfer;

/// Dummy inputs, real outputs: a deposit of 100 funds a 60 send to a recipient
/// and a 40 change output. Both input slots are dummy.
#[test]
fn deposit_dummy_inputs_real_outputs() {
    run_transfer(&[], 100, &[60]);
}

/// One real input + one dummy input; two real outputs (send + change) + one dummy
/// output. A real 100-value spend split into a 60 send and 40 change.
#[test]
fn one_real_one_dummy_input() {
    run_transfer(&[100], 0, &[60]);
}

/// All real inputs and outputs: two inputs (100 + 50) fully spent into three real
/// outputs — two sends (60, 50) and a 40 change.
#[test]
fn all_real_inputs_and_outputs() {
    run_transfer(&[100, 50], 0, &[60, 50]);
}
