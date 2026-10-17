#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::{external::compiled, fixtures::Chain, r1cs::chain_wire};
use crate::harness::{equivalence::picus_verdicts, picus::Verdict, WorkDir};

const LIMIT: Duration = Duration::from_secs(30);

#[test]
fn picus_checks_chain_determinism_with_a_bounded_timeout() {
    let work = WorkDir::new("gadgets-hash-chain-picus");
    fn check<const N: usize>(work: &WorkDir) {
        let compiled = compiled(N);
        let verdicts = picus_verdicts::<Chain<N>>(
            work,
            &format!("hash-chain-{N}"),
            &[chain_wire(N)],
            &compiled,
            &[compiled.wire("main.chain")],
            LIMIT,
        );
        eprintln!("Chain({N}) Picus: {verdicts:?}");
        assert_ne!(verdicts.0, Verdict::Unsafe);
        assert_ne!(verdicts.1, Verdict::Unsafe);
    }
    check::<1>(&work);
    check::<3>(&work);
}
