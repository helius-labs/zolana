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
    hash_chain::{create_hash_chain_from_slice, create_right_hash_chain_from_slice},
    primitives::hash_bytes,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{
        CircuitId, OwnerTag, TransactIxData, TransactIxDataRef, TransactOutput, TransactProof,
    },
    verifying_keys::OutputOwnerMode,
};

fn instruction_bytes(circuit: CircuitId, outputs: Vec<TransactOutput>) -> Vec<u8> {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        tx_viewing_pk: [0; 33],
        salt: [0; 16],
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs,
        messages: Vec::new(),
        private_tx_hash: [0; 32],
        circuit,
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
    }
    .serialize()
    .unwrap()
}

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
    let ix_bytes = instruction_bytes(
        CircuitId::ConfidentialEddsa(1, 3, 1),
        vec![
            TransactOutput {
                utxo_hash: [0; 32],
                owner_tag: OwnerTag::Account(0),
                data: None,
            },
            TransactOutput {
                utxo_hash: [0; 32],
                owner_tag: OwnerTag::Inline([2; 32]),
                data: None,
            },
            TransactOutput {
                utxo_hash: [0; 32],
                owner_tag: OwnerTag::Account(0),
                data: None,
            },
        ],
    );
    let ix = TransactIxDataRef::from_bytes(&ix_bytes).unwrap();
    let output_owner_accounts = [get_account_view(
        [1; 32],
        [0; 32],
        false,
        false,
        false,
        vec![],
    )];
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
        .fill_output_owner_chain(
            OutputOwnerMode::All,
            &ix,
            &output_owner_accounts,
            &mut owner_hashes,
        )
        .unwrap();
    assert_eq!(owner_hashes.len(), 2);

    proof_inputs
        .fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes)
        .unwrap();
    assert_eq!(owner_hashes.len(), 3);
    // Outputs 0 and 2 resolve to the payer's tag, so the cache serves all three
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
    let confidential = [1, 2, 0, 0, 0, 3, 9];
    let anonymous = [1, 2, 0, 0, 0, 2, 9];
    let malformed_length = [1, 3, 0, 0, 0, 3, 9];
    let ix_bytes = instruction_bytes(
        CircuitId::RingEddsa(1, 3, 1),
        vec![
            TransactOutput {
                utxo_hash: [0; 32],
                owner_tag: OwnerTag::Inline([1; 32]),
                data: Some(confidential.to_vec()),
            },
            TransactOutput {
                utxo_hash: [0; 32],
                owner_tag: OwnerTag::Inline([2; 32]),
                data: Some(anonymous.to_vec()),
            },
            TransactOutput {
                utxo_hash: [0; 32],
                owner_tag: OwnerTag::Inline([3; 32]),
                data: Some(malformed_length.to_vec()),
            },
        ],
    );
    let ix = TransactIxDataRef::from_bytes(&ix_bytes).unwrap();
    let mut proof_inputs = TransactProofInputs::new(CircuitId::RingEddsa(1, 3, 1));
    let mut owner_hashes = OwnerHashCache::new();

    proof_inputs
        .fill_output_owner_chain(
            OutputOwnerMode::ConfidentialMarked,
            &ix,
            &[],
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

/// The storage bound is the largest circuit fold width: payer plus one signer
/// per input. The account parser rejects a longer owner-signer run first, so
/// exercise the final defensive bound directly.
#[test]
fn more_unique_signers_than_the_maximum_circuit_width_is_rejected() {
    let payer = get_account_view([1; 32], [0; 32], true, false, false, vec![]);
    // One more distinct signer than fits, on top of the payer in slot zero.
    let owner_signers: Vec<_> = (0..MAX_SIGNERS as u8)
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
    let repeated: Vec<_> = (0..MAX_SIGNERS + 4)
        .map(|_| get_account_view([2; 32], [0; 32], true, false, false, vec![]))
        .collect();

    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));
    let mut owner_hashes = OwnerHashCache::new();
    proof_inputs
        .fill_owner_signer_hashes(&payer, &repeated, &mut owner_hashes)
        .expect("a deduplicated run inside the bound is accepted");
    assert_eq!(proof_inputs.unique_owner_signer_count, 2);
}
