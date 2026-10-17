//! One R1CS digest per gadget at a representative size. The size pins next to
//! each gadget catch a changed row count; these also catch a changed
//! coefficient. A changed digest means the gadget's constraints changed, which
//! changes every proving key built on it: re-derive and re-pin deliberately.

use super::{
    hash_chain::fixtures::Chain,
    index::fixtures::{OneHot, SelectIndex},
    membership::fixtures::{AssertIn, IsIn},
    poseidon::fixtures::PoseidonClaim,
};
use crate::harness::digest::r1cs_digest;

#[test]
fn every_gadget_keeps_its_r1cs() {
    assert_eq!(
        [
            ("nonzero_hash_chain/3", r1cs_digest::<Chain<3>>()),
            ("one_hot/4", r1cs_digest::<OneHot<4>>()),
            ("select_index/4", r1cs_digest::<SelectIndex<4>>()),
            ("is_in/4", r1cs_digest::<IsIn<4>>()),
            ("assert_in/4", r1cs_digest::<AssertIn<4>>()),
            ("poseidon/2", r1cs_digest::<PoseidonClaim<2>>()),
            ("poseidon/12", r1cs_digest::<PoseidonClaim<12>>()),
        ],
        [
            (
                "nonzero_hash_chain/3",
                "c4620bd015eea28bf3ddeac1f6ef533c7ab1a54f88837945cc5cc23016f658e3",
            ),
            (
                "one_hot/4",
                "443095e38d013fe628c165975595e933324ca6abc4291f2e1104932ec4cadcb7",
            ),
            (
                "select_index/4",
                "12905e7a2086536e9d5e8cdfd1053dc0ffddce707a58d6d27daccda729d66014",
            ),
            (
                "is_in/4",
                "c749712a2c7507be689356ff15b3b1370541d176fde7342c7b6f7d9a8f10f47c",
            ),
            (
                "assert_in/4",
                "c115125cd3dc191256ba0670d84ded29976aca9cb64cd1daab32f4473c3e43b5",
            ),
            (
                "poseidon/2",
                "711d50b9c43ed73114bb11dc89af6d3f0f937429ee7af463c33d449a5b10403e",
            ),
            (
                "poseidon/12",
                "ae0be81b9f06b7ce87c656e7a6ba6c35d840abbdb24e55e2c85fe59f998b645e",
            ),
        ]
        .map(|(name, digest)| (name, digest.to_string()))
    );
}
