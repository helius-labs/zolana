//! [`accepts`] with every case on its own thread: a circom witness
//! calculation compiles the wasm module each time, seconds per case for the
//! Poseidon-based references in a debug build.

#![cfg(feature = "external-tools")]

use zk_program_sdk::ZkCircuit;

use crate::harness::{
    circom::Compiled,
    equivalence::{accepts, Accepts, Case},
    fixture::Visited,
};

pub fn accepts_in_parallel<F: ZkCircuit + Sync>(
    circom: &Compiled,
    cases: &[Case<F>],
) -> Visited<Accepts> {
    std::thread::scope(|scope| {
        let runs: Vec<_> = cases
            .iter()
            .map(|case| scope.spawn(move || accepts(circom, std::slice::from_ref(case))))
            .collect();
        runs.into_iter()
            .flat_map(|run| run.join().expect("a relation case"))
            .collect()
    })
}

pub fn expected<F>(cases: &[Case<F>]) -> Visited<Accepts> {
    cases
        .iter()
        .map(|case| (case.name, Accepts::all(case.holds)))
        .collect()
}

/// Asserts that for every case, the SDK natively and in R1CS and circom by
/// its witness calculation and its R1CS all accept exactly when the case
/// holds.
pub fn assert_relation_equivalent<F: ZkCircuit + Sync>(circom: &Compiled, cases: &[Case<F>]) {
    assert_eq!(accepts_in_parallel(circom, cases), expected(cases));
}
