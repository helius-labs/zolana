//! Signer-run assembly unit tests, moved out of the program crate
//! (`transact/verify.rs`): payer-first dedup of owner signers, the shared
//! owner-hash cache, confidential-marked output-owner selection, and the
//! fixed-width signer hash chain's zero-suffix optimization.

use pinocchio::error::ProgramError;
use shielded_pool_program::testing::{
    fixed_signer_hash_chain, OwnerHashCache, TransactProofInputs, MAX_SIGNERS,
    SIGNER_ZERO_SUFFIX_CHAINS,
};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_hasher::{
    hash_chain::create_right_hash_chain_from_slice, primitives::hash_bytes,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{CircuitId, ResolvedOutput},
    verifying_keys::OutputOwnerMode,
};

#[test]
fn incomplete_proof_inputs_are_rejected() {
    let proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));

    assert_eq!(
        proof_inputs.ensure_complete(),
        Err(ProgramError::Custom(
            ShieldedPoolError::InvalidTransactShape as u32
        ))
    );
}

#[test]
fn owner_signers_are_first_occurrence_deduplicated_with_payer_first() {
    let payer = get_account_view([1; 32], [0; 32], true, false, false, vec![]);
    let owner_signers = vec![
        get_account_view([2; 32], [0; 32], true, false, false, vec![]),
        get_account_view([1; 32], [0; 32], true, false, false, vec![]),
        get_account_view([2; 32], [0; 32], true, false, false, vec![]),
        get_account_view([3; 32], [0; 32], true, false, false, vec![]),
    ];
    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));
    let mut owner_hashes = OwnerHashCache::new();

    proof_inputs
        .fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes)
        .unwrap();

    assert_eq!(proof_inputs.unique_owner_signer_count, 3);
    assert_eq!(
        proof_inputs.signer_pk_hashes[0],
        hash_bytes(&[1; 32]).unwrap()
    );
    assert_eq!(
        proof_inputs.signer_pk_hashes[1],
        hash_bytes(&[2; 32]).unwrap()
    );
    assert_eq!(
        proof_inputs.signer_pk_hashes[2],
        hash_bytes(&[3; 32]).unwrap()
    );
    assert_eq!(proof_inputs.signer_pk_hashes[3], [0; 32]);
}

#[test]
fn owner_hashes_are_reused_between_outputs_and_signers() {
    let utxo_hashes = [[0u8; 32]; 3];
    let outputs = [
        ResolvedOutput {
            utxo_hash: &utxo_hashes[0],
            owner_tag: [1; 32],
            data: None,
        },
        ResolvedOutput {
            utxo_hash: &utxo_hashes[1],
            owner_tag: [2; 32],
            data: None,
        },
        ResolvedOutput {
            utxo_hash: &utxo_hashes[2],
            owner_tag: [1; 32],
            data: None,
        },
    ];
    let payer = get_account_view([1; 32], [0; 32], true, false, false, vec![]);
    let owner_signers = [get_account_view(
        [3; 32],
        [0; 32],
        true,
        false,
        false,
        vec![],
    )];
    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 3, 1));
    let mut owner_hashes = OwnerHashCache::new();

    proof_inputs
        .fill_output_owner_pk_hashes(OutputOwnerMode::All, &outputs, &mut owner_hashes)
        .unwrap();
    assert_eq!(owner_hashes.len(), 2);

    proof_inputs
        .fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes)
        .unwrap();
    assert_eq!(owner_hashes.len(), 3);
    assert_eq!(
        proof_inputs.output_owner_pk_hashes[0],
        proof_inputs.signer_pk_hashes[0]
    );
    assert_eq!(
        proof_inputs.output_owner_pk_hashes[0],
        proof_inputs.output_owner_pk_hashes[2]
    );
}

#[test]
fn confidential_marked_mode_hashes_only_marked_output_tags() {
    let utxo_hashes = [[0u8; 32]; 3];
    let confidential = [1, 2, 0, 0, 0, 3, 9];
    let anonymous = [1, 2, 0, 0, 0, 2, 9];
    let malformed_length = [1, 3, 0, 0, 0, 3, 9];
    let outputs = [
        ResolvedOutput {
            utxo_hash: &utxo_hashes[0],
            owner_tag: [1; 32],
            data: Some(&confidential),
        },
        ResolvedOutput {
            utxo_hash: &utxo_hashes[1],
            owner_tag: [2; 32],
            data: Some(&anonymous),
        },
        ResolvedOutput {
            utxo_hash: &utxo_hashes[2],
            owner_tag: [3; 32],
            data: Some(&malformed_length),
        },
    ];
    let mut proof_inputs = TransactProofInputs::new(CircuitId::ZoneEddsa(1, 3, 1));
    let mut owner_hashes = OwnerHashCache::new();

    proof_inputs
        .fill_output_owner_pk_hashes(
            OutputOwnerMode::ConfidentialMarked,
            &outputs,
            &mut owner_hashes,
        )
        .unwrap();

    assert_eq!(
        proof_inputs.output_owner_pk_hashes[0],
        hash_bytes(&[1; 32]).unwrap()
    );
    assert_eq!(proof_inputs.output_owner_pk_hashes[1], [0; 32]);
    assert_eq!(proof_inputs.output_owner_pk_hashes[2], [0; 32]);
    assert_eq!(owner_hashes.len(), 1);
}

#[test]
fn zero_suffix_optimization_matches_fixed_width_right_fold() {
    for width in 1..=MAX_SIGNERS {
        for unique_count in 1..=width {
            let mut signers = vec![[0u8; 32]; width];
            for (index, signer) in signers.iter_mut().take(unique_count).enumerate() {
                signer[31] = (index + 1) as u8;
            }
            assert_eq!(
                fixed_signer_hash_chain(&signers[..unique_count], width).unwrap(),
                create_right_hash_chain_from_slice(&signers).unwrap(),
                "width={width}, unique_count={unique_count}",
            );
        }
    }
}

#[test]
fn zero_suffix_constants_cover_every_supported_width() {
    for width in 1..=MAX_SIGNERS {
        let zeros = vec![[0u8; 32]; width];
        assert_eq!(
            SIGNER_ZERO_SUFFIX_CHAINS[width - 1],
            create_right_hash_chain_from_slice(&zeros).unwrap(),
        );
    }
}

#[test]
fn fixed_signer_hash_chain_rejects_empty_signer_prefix() {
    assert_eq!(
        fixed_signer_hash_chain(&[], 1),
        Err(ProgramError::Custom(
            ShieldedPoolError::InvalidTransactShape as u32
        )),
    );
}
