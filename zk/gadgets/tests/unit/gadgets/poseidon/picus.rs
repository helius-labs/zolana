#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::{
    external::compiled,
    fixtures::{every_arity, PerArity, PoseidonClaim},
    r1cs::hash_wire,
};
use crate::harness::{equivalence::picus_verdicts, picus::Verdict, WorkDir};

const LIMIT: Duration = Duration::from_secs(30);

struct HashVerdicts<'a>(&'a WorkDir);

impl PerArity for HashVerdicts<'_> {
    type Output = (Verdict, Verdict);

    fn at<const N: usize>(&self) -> (Verdict, Verdict) {
        let compiled = compiled(N);
        let hash = compiled.wire("main.hash");
        picus_verdicts::<PoseidonClaim<N>>(
            self.0,
            &format!("poseidon-{N}"),
            &[hash_wire(N)],
            &compiled,
            &[hash],
            LIMIT,
        )
    }
}

#[test]
fn picus_checks_hash_determinism_at_every_arity_with_a_bounded_timeout() {
    let work = WorkDir::new("gadgets-poseidon-picus");
    for (arity, (sdk, circom)) in every_arity(&HashVerdicts(&work)) {
        eprintln!("Poseidon({arity}) Picus: sdk={sdk:?}, circom={circom:?}");
        assert_ne!(sdk, Verdict::Unsafe, "SDK Poseidon({arity})");
        assert_ne!(circom, Verdict::Unsafe, "circom Poseidon({arity})");
    }
}
