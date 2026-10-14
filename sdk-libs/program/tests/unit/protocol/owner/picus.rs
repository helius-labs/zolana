#![cfg(feature = "external-tools")]

use super::fixtures::{OwnerHash, CLAIM_WIRE};
use crate::{
    harness::{
        fixture::picus_export,
        picus::{picus_wire, promote, verdict_within},
        WorkDir,
    },
    protocol::asset::picus::{no_counterexample, LIMIT},
};

#[test]
fn picus_finds_no_second_owner_hash_for_one_preimage() {
    let work = WorkDir::new("picus-owner-hash");
    let r1cs = picus_export::<OwnerHash>();
    let hash = picus_wire(&r1cs, CLAIM_WIRE);
    assert!(no_counterexample(verdict_within(
        &work,
        "owner-hash-claim",
        &promote(&r1cs, hash),
        LIMIT
    )));
}
