//! Signer-run assembly unit tests, moved out of the program crate
//! (`transact/verify.rs`): payer-first dedup of owner signers, the shared
//! owner-hash cache, confidential-marked output-owner selection, and the
//! fixed-width signer hash chain's zero-suffix optimization.

use pinocchio::error::ProgramError;
use shielded_pool_program::testing::{
    fixed_signer_hash_chain, OwnerHashCache, TransactProofInputs, MAX_SIGNERS, MAX_UNIQUE_SIGNERS,
    SIGNER_ZERO_SUFFIX_CHAINS,
};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_hasher::{
    hash_chain::{create_hash_chain_from_slice, create_right_hash_chain_from_slice},
    primitives::hash_bytes,
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
        .fill_output_owner_chain(OutputOwnerMode::All, &outputs, &mut owner_hashes)
        .unwrap();
    assert_eq!(owner_hashes.len(), 2);

    proof_inputs
        .fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes)
        .unwrap();
    assert_eq!(owner_hashes.len(), 3);
    // Outputs 0 and 2 share the payer's tag, so the cache serves all three
    // lookups from two entries and the folded chain repeats that hash.
    let payer_owner_hash = hash_bytes(&[1; 32]).unwrap();
    assert_eq!(payer_owner_hash, proof_inputs.signer_pk_hashes[0]);
    assert_eq!(
        proof_inputs.output_owner_chain,
        create_hash_chain_from_slice(&[
            payer_owner_hash,
            hash_bytes(&[2; 32]).unwrap(),
            payer_owner_hash,
        ])
        .unwrap()
    );
    assert_eq!(proof_inputs.output_owner_count, 3);
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
    let mut proof_inputs = TransactProofInputs::new(CircuitId::RingEddsa(1, 3, 1));
    let mut owner_hashes = OwnerHashCache::new();

    proof_inputs
        .fill_output_owner_chain(
            OutputOwnerMode::ConfidentialMarked,
            &outputs,
            &mut owner_hashes,
        )
        .unwrap();

    // Only the confidential-encrypted output contributes its owner hash; the
    // other two fold an explicit zero, which is what the zero-filled slots of
    // the removed fixed-width array did.
    assert_eq!(
        proof_inputs.output_owner_chain,
        create_hash_chain_from_slice(&[hash_bytes(&[1; 32]).unwrap(), [0; 32], [0; 32]]).unwrap()
    );
    assert_eq!(proof_inputs.output_owner_count, 3);
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

/// `MAX_UNIQUE_SIGNERS` bounds the number of *distinct* owner signers the
/// program will hash, independently of the input count. It is unreachable
/// on-chain while every supported shape has fewer inputs than the bound --
/// `account.rs` rejects a longer run first -- so exercise it directly.
#[test]
fn more_unique_signers_than_the_bound_is_rejected() {
    let payer = get_account_view([1; 32], [0; 32], true, false, false, vec![]);
    // One more distinct signer than fits, on top of the payer in slot zero.
    let owner_signers: Vec<_> = (0..MAX_UNIQUE_SIGNERS as u8)
        .map(|index| get_account_view([index + 2; 32], [0; 32], true, false, false, vec![]))
        .collect();

    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));
    let mut owner_hashes = OwnerHashCache::new();
    assert_eq!(
        proof_inputs.fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes),
        Err(ProgramError::Custom(
            ShieldedPoolError::InvalidTransactShape as u32
        )),
    );
}

/// A repeated signer is deduplicated, so a run longer than the bound is fine as
/// long as its distinct prefix fits.
#[test]
fn repeated_signers_do_not_count_against_the_bound() {
    let payer = get_account_view([1; 32], [0; 32], true, false, false, vec![]);
    let repeated: Vec<_> = (0..MAX_UNIQUE_SIGNERS + 4)
        .map(|_| get_account_view([2; 32], [0; 32], true, false, false, vec![]))
        .collect();

    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));
    let mut owner_hashes = OwnerHashCache::new();
    proof_inputs
        .fill_owner_signer_hashes(&payer, &repeated, &mut owner_hashes)
        .expect("a deduplicated run inside the bound is accepted");
    assert_eq!(proof_inputs.unique_owner_signer_count, 2);
}
