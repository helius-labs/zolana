//! Signer-run assembly unit tests, moved out of the program crate
//! (`transact/verify.rs`): payer-first dedup of owner signers, the shared
//! owner-hash cache, confidential-marked output-owner selection, and the
//! fixed-width signer hash chain's zero-suffix optimization.

use pinocchio::{error::ProgramError, AccountView};
use shielded_pool_program::testing::{
    fixed_signer_hash_chain, OwnerHashCache, TransactAccounts, TransactProofInputs, MAX_SIGNERS,
    SIGNER_ZERO_SUFFIX_CHAINS,
};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_hasher::{
    hash_chain::create_right_hash_chain_from_slice, primitives::solana_owner_identity,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{
        CircuitId, InputUtxo, OwnerTag, ResolvedOutput, TransactIxData, TransactIxDataRef,
        TransactOutput, TransactProof as ProofData, TreeContext,
    },
    shape::{owner_signer_slots, Shape},
    verifying_keys::OutputOwnerMode,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_transaction::instructions::transact::SPP_CONSOLIDATION_SHAPE;

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
        solana_owner_identity(&[1; 32]).unwrap()
    );
    assert_eq!(
        proof_inputs.signer_pk_hashes[1],
        solana_owner_identity(&[2; 32]).unwrap()
    );
    assert_eq!(
        proof_inputs.signer_pk_hashes[2],
        solana_owner_identity(&[3; 32]).unwrap()
    );
    assert_eq!(proof_inputs.signer_pk_hashes[3], [0; 32]);
}

#[test]
fn owner_signer_run_is_bounded_by_max_signers() {
    let payer = get_account_view([1; 32], [0; 32], true, false, false, vec![]);
    let unique_signer = |index: usize| {
        let tag = u8::try_from(index + 2).expect("signer tag fits a byte");
        get_account_view([tag; 32], [0; 32], true, false, false, vec![])
    };
    let mut owner_signers: Vec<_> = (0..MAX_SIGNERS - 1).map(unique_signer).collect();

    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));
    let mut owner_hashes = OwnerHashCache::new();
    proof_inputs
        .fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes)
        .unwrap();
    assert_eq!(
        usize::from(proof_inputs.unique_owner_signer_count),
        MAX_SIGNERS
    );

    owner_signers.push(unique_signer(MAX_SIGNERS - 1));
    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));
    let mut owner_hashes = OwnerHashCache::new();
    assert_eq!(
        proof_inputs.fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes),
        Err(ProgramError::Custom(
            ShieldedPoolError::InvalidTransactShape as u32
        ))
    );
}

#[test]
fn consolidation_shape_has_the_widest_signer_vector() {
    assert_eq!(SPP_CONSOLIDATION_SHAPE, Shape::new(36, 2));
    assert_eq!(owner_signer_slots(36), 24);
    assert_eq!(SPP_CONSOLIDATION_SHAPE.signer_width(), 25);
    assert_eq!(MAX_SIGNERS, 25);
    assert_eq!(SIGNER_ZERO_SUFFIX_CHAINS.len(), 25);
}

fn small_fe(tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(last) = out.last_mut() {
        *last = tag;
    }
    out
}

fn consolidation_ix_bytes() -> Vec<u8> {
    let circuit = CircuitId::ConfidentialEddsa(36, 2, 3);
    TransactIxData {
        expiry_unix_ts: 7,
        private_tx_hash: small_fe(0x51),
        circuit,
        tx_viewing_pk: [4u8; 33],
        salt: [6u8; 16],
        proof: ProofData::zeroed(),
        inputs: (1..=circuit.num_inputs())
            .map(|tag| InputUtxo {
                nullifier_hash: small_fe(tag),
                tree_index: 0,
            })
            .collect(),
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
        interface_transfers: vec![],
        data_hash: None,
        ring_data_hash: None,
        outputs: (100..100 + circuit.num_outputs())
            .map(|tag| TransactOutput {
                utxo_hash: small_fe(tag),
                owner_tag: OwnerTag::Inline(small_fe(tag)),
                data: None,
            })
            .collect(),
        messages: vec![],
    }
    .serialize()
    .expect("serialize transact ix")
}

/// `payer`, `output_tree`, the program, the system program, `input_tree`, one
/// nullifier PDA per input, then `owner_signer_count` distinct signers.
fn consolidation_accounts(owner_signer_count: usize) -> Vec<AccountView> {
    let pool = SHIELDED_POOL_PROGRAM_ID;
    let mut accounts = vec![
        get_account_view([1; 32], [0; 32], true, true, false, vec![]),
        get_account_view([3; 32], pool, false, true, false, vec![]),
        get_account_view(pool, [0; 32], false, false, true, vec![]),
        get_account_view([0; 32], [0; 32], false, false, true, vec![]),
        get_account_view([2; 32], pool, false, true, false, vec![]),
    ];
    accounts.extend(
        (0..36u8)
            .map(|index| get_account_view([0x10 + index; 32], pool, false, true, false, vec![])),
    );
    accounts.extend((0..owner_signer_count).map(|index| {
        let tag = u8::try_from(0x80 + index).expect("signer tag fits a byte");
        get_account_view([tag; 32], [0; 32], true, false, false, vec![])
    }));
    accounts
}

/// The account parser bounds the owner signer run by `owner_signer_slots`, not
/// by the input count: on `36x2` the 25th owner signer (the 26th unique signer
/// with the payer) is rejected before any hashing.
#[test]
fn consolidation_shape_rejects_an_owner_signer_run_past_its_slots() {
    let bytes = consolidation_ix_bytes();
    let ix = TransactIxDataRef::from_bytes(&bytes).expect("parse transact ix");
    let slots = owner_signer_slots(36);

    let mut accounts = consolidation_accounts(slots);
    let parsed = TransactAccounts::validate_and_parse(&mut accounts, &ix)
        .expect("a run filling every owner signer slot parses");
    assert_eq!(parsed.owner_signers.len(), slots);
    assert_eq!(parsed.nullifier_pdas.len(), 36);

    let mut accounts = consolidation_accounts(slots + 1);
    assert_eq!(
        TransactAccounts::validate_and_parse(&mut accounts, &ix).err(),
        Some(ProgramError::Custom(
            ShieldedPoolError::InvalidTransactShape as u32
        ))
    );
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
        .fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes)
        .unwrap();
    assert_eq!(owner_hashes.len(), 2);

    proof_inputs
        .fill_output_owner_pk_hashes(OutputOwnerMode::All, &outputs, &mut owner_hashes)
        .unwrap();
    assert_eq!(owner_hashes.len(), 3);
    assert_eq!(proof_inputs.unique_owner_signer_count, 2);
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
fn owner_signer_hashing_rejects_a_cache_populated_by_output_owners() {
    let utxo_hash = [0u8; 32];
    let outputs = [ResolvedOutput {
        utxo_hash: &utxo_hash,
        owner_tag: [2; 32],
        data: None,
    }];
    let payer = get_account_view([1; 32], [0; 32], true, false, false, vec![]);
    let owner_signers = [get_account_view(
        [2; 32],
        [0; 32],
        true,
        false,
        false,
        vec![],
    )];
    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));
    let mut owner_hashes = OwnerHashCache::new();
    proof_inputs
        .fill_output_owner_pk_hashes(OutputOwnerMode::All, &outputs, &mut owner_hashes)
        .unwrap();

    assert_eq!(
        proof_inputs.fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes),
        Err(ProgramError::Custom(
            ShieldedPoolError::InvalidTransactShape as u32
        ))
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
    let mut proof_inputs = TransactProofInputs::new(CircuitId::RingEddsa(1, 3, 1));
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
        solana_owner_identity(&[1; 32]).unwrap()
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
