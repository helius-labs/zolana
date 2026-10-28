use spr_forester_prover::{build_inputs, reference_nullifier_tree, BatchAddressAppendInputs};
use spr_hasher::hash_chain::create_hash_chain_4_from_slice;
use spr_interface::instruction::NullifierTreeProof;

pub fn batch_inputs(first_value: u128) -> BatchAddressAppendInputs {
    let values = (0..10u128)
        .map(|offset| {
            let mut value = [0u8; 32];
            value[16..].copy_from_slice(&first_value.checked_add(offset).unwrap().to_be_bytes());
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
    assert_eq!(reference.root(), new_root);
    inputs
}

pub fn assert_batch_proof(inputs: &BatchAddressAppendInputs, proof: &NullifierTreeProof) {
    let proof = spr_tree::nullifier_tree::proof::NullifierTreeProof {
        a: proof.a,
        b: proof.b,
        c: proof.c,
    };
    let mut hash = [0u8; 32];
    let bytes = inputs.public_input_hash.to_bytes_be();
    hash[32 - bytes.len()..].copy_from_slice(&bytes);
    spr_tree::nullifier_tree::verify::verify_batch_update(10, hash, &proof).unwrap();
    hash[31] ^= 1;
    assert!(
        spr_tree::nullifier_tree::verify::verify_batch_update(10, hash, &proof).is_err(),
        "proof must bind the batch statement"
    );
}
