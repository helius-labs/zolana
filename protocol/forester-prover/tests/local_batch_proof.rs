#![cfg(feature = "gnark")]

use std::path::PathBuf;
use zolana_forester_prover::{build_inputs, reference_nullifier_tree, ProverClient};
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;

#[test]
#[ignore = "requires the pinned batch_address-append_40_10.key in FORESTER_TEST_KEYS_DIR"]
fn local_batch_proof() {
    let keys = PathBuf::from(
        std::env::var_os("FORESTER_TEST_KEYS_DIR").expect("set FORESTER_TEST_KEYS_DIR"),
    );
    let values = (1..=10u64)
        .map(|number| {
            let mut value = [0u8; 32];
            value[24..].copy_from_slice(&number.to_be_bytes());
            value
        })
        .collect::<Vec<_>>();
    let mut reference = reference_nullifier_tree(40).unwrap();
    let old_root = reference.root();
    let (inputs, new_root) = build_inputs(
        &mut reference,
        1,
        40,
        create_hash_chain_4_from_slice(&values).unwrap(),
        old_root,
        &values,
    )
    .unwrap();
    let prover = ProverClient::local(keys).unwrap();
    let proof = prover.prove_batch_address_append(&inputs).unwrap();
    let proof = zolana_tree::nullifier_tree::proof::NullifierTreeProof {
        a: proof.a,
        b: proof.b,
        c: proof.c,
    };
    let mut hash = [0u8; 32];
    let bytes = inputs.public_input_hash.to_bytes_be();
    hash[32 - bytes.len()..].copy_from_slice(&bytes);
    zolana_tree::nullifier_tree::verify::verify_batch_update(10, hash, &proof).unwrap();
    hash[31] ^= 1;
    assert!(
        zolana_tree::nullifier_tree::verify::verify_batch_update(10, hash, &proof).is_err(),
        "proof must bind the batch statement"
    );
    assert_eq!(reference.root(), new_root);
}
