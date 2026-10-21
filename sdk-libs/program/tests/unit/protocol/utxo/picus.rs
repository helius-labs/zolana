#![cfg(feature = "external-tools")]

use super::fixtures::{UtxoHash, CLAIM_WIRE};
use crate::{
    harness::{
        fixture::picus_export,
        picus::{picus_wire, promote, verdict_within},
        WorkDir,
    },
    protocol::asset::picus::{no_counterexample, LIMIT},
};

#[test]
fn picus_finds_no_second_utxo_commitment_for_one_preimage() {
    let work = WorkDir::new("picus-utxo-hash");
    let r1cs = picus_export::<UtxoHash>();
    let hash = picus_wire(&r1cs, CLAIM_WIRE);
    assert!(no_counterexample(verdict_within(
        &work,
        "utxo-hash-claim",
        &promote(&r1cs, hash),
        LIMIT
    )));
}
