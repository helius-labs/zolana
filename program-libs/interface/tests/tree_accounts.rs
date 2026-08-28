#![cfg(feature = "solana")]

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::instruction::instruction_data::merge_transact::MergeProof;
use zolana_interface::instruction::{
    CircuitId, InputUtxo, MergeRing, MergeTransact, MergeTransactIxData, RingAuthorityTransact,
    RingTransact, Transact, TransactIxData, TransactProof,
};
use zolana_interface::pda;

fn transact_data(circuit: CircuitId) -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: Vec::new(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: Vec::new(),
    }
}

fn transact_data_with_inputs(circuit: CircuitId, nullifiers: &[[u8; 32]]) -> TransactIxData {
    let mut data = transact_data(circuit);
    data.inputs = nullifiers
        .iter()
        .map(|nullifier_hash| InputUtxo {
            nullifier_hash: *nullifier_hash,
            nullifier_tree_root_index: 0,
            utxo_tree_root_index: 0,
        })
        .collect();
    data
}

fn merge_nullifiers() -> Vec<[u8; 32]> {
    (1u8..=8).map(|i| [i; 32]).collect()
}

fn merge_data() -> MergeTransactIxData {
    MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [0u8; 32],
        eddsa_owner: true,
        private_tx_hash: [0u8; 32],
        nullifiers: merge_nullifiers(),
        utxo_tree_root_index: vec![0; 8],
        nullifier_tree_root_index: vec![0; 8],
    }
}

fn marker_metas(input_tree: &Pubkey, nullifiers: &[[u8; 32]]) -> Vec<AccountMeta> {
    nullifiers
        .iter()
        .map(|nullifier| AccountMeta::new(pda::nullifier_marker(input_tree, nullifier).0, false))
        .collect()
}

fn assert_marker_slots(
    instruction: &Instruction,
    first_marker_index: usize,
    input_tree: &Pubkey,
    nullifiers: &[[u8; 32]],
) {
    let markers = &instruction.accounts[first_marker_index..first_marker_index + nullifiers.len()];
    assert_eq!(markers, marker_metas(input_tree, nullifiers).as_slice());
}

fn assert_tree_slots(
    instruction: &Instruction,
    first_tree_index: usize,
    input_tree: Pubkey,
    output_tree: Pubkey,
) {
    let input = &instruction.accounts[first_tree_index];
    let output = &instruction.accounts[first_tree_index + 1];
    assert_eq!(input.pubkey, input_tree);
    assert_eq!(output.pubkey, output_tree);
    assert!(input.is_writable);
    assert!(output.is_writable);
}

#[test]
fn every_spend_builder_has_explicit_input_and_output_tree_slots() {
    let payer = Pubkey::new_unique();
    let input_tree = Pubkey::new_unique();
    let output_tree = Pubkey::new_unique();
    let ring_program_id = Pubkey::new_unique();

    let transact = Transact {
        payer,
        input_tree,
        output_tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::ConfidentialEddsa(0, 0, 3)),
    }
    .instruction();
    assert_tree_slots(&transact, 1, input_tree, output_tree);

    let ring = RingTransact {
        payer,
        input_tree,
        output_tree,
        ring_program_id,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::RingEddsa(0, 0, 3)),
    }
    .cpi_instruction();
    assert_tree_slots(&ring, 1, input_tree, output_tree);

    let ring_authority = RingAuthorityTransact {
        payer,
        input_tree,
        output_tree,
        ring_program_id,
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::RingAuthority(0, 0, 3)),
    }
    .cpi_instruction();
    assert_tree_slots(&ring_authority, 1, input_tree, output_tree);

    let merge = MergeTransact {
        input_tree,
        output_tree,
        payer,
        user_record: Pubkey::new_unique(),
        data: merge_data(),
    }
    .instruction();
    assert_tree_slots(&merge, 0, input_tree, output_tree);

    let merge_ring = MergeRing {
        input_tree,
        output_tree,
        ring_program_id,
        payer,
        data: merge_data(),
        output_ring_data_hash: [0u8; 32],
    }
    .cpi_instruction();
    assert_tree_slots(&merge_ring, 0, input_tree, output_tree);
}

#[test]
fn every_spend_builder_places_one_marker_per_input_after_its_fixed_accounts() {
    let payer = Pubkey::new_unique();
    let input_tree = Pubkey::new_unique();
    let output_tree = Pubkey::new_unique();
    let ring_program_id = Pubkey::new_unique();
    let owner_signer = Pubkey::new_unique();
    let nullifiers = [[11u8; 32], [22u8; 32]];

    let transact = Transact {
        payer,
        input_tree,
        output_tree,
        owner_signers: vec![owner_signer],
        interface_transfer_accounts: Vec::new(),
        data: transact_data_with_inputs(CircuitId::ConfidentialEddsa(2, 2, 3), &nullifiers),
    }
    .instruction();
    assert_marker_slots(&transact, 5, &input_tree, &nullifiers);
    assert_eq!(transact.accounts[7].pubkey, owner_signer);
    assert_eq!(transact.accounts.len(), 8);

    let ring = RingTransact {
        payer,
        input_tree,
        output_tree,
        ring_program_id,
        owner_signers: vec![owner_signer],
        interface_transfer_accounts: Vec::new(),
        data: transact_data_with_inputs(CircuitId::RingEddsa(2, 2, 3), &nullifiers),
    }
    .cpi_instruction();
    assert_eq!(ring.accounts[5].pubkey, pda::ring_auth(&ring_program_id).0);
    assert_marker_slots(&ring, 6, &input_tree, &nullifiers);
    assert_eq!(ring.accounts[8].pubkey, owner_signer);
    assert_eq!(ring.accounts.len(), 9);

    let ring_authority = RingAuthorityTransact {
        payer,
        input_tree,
        output_tree,
        ring_program_id,
        interface_transfer_accounts: Vec::new(),
        data: transact_data_with_inputs(CircuitId::RingAuthority(2, 2, 3), &nullifiers),
    }
    .cpi_instruction();
    assert_eq!(
        ring_authority.accounts[5].pubkey,
        pda::ring_auth(&ring_program_id).0
    );
    assert_marker_slots(&ring_authority, 6, &input_tree, &nullifiers);
    assert_eq!(ring_authority.accounts.len(), 8);

    let merge = MergeTransact {
        input_tree,
        output_tree,
        payer,
        user_record: Pubkey::new_unique(),
        data: merge_data(),
    }
    .instruction();
    assert_eq!(merge.accounts[4].pubkey, Pubkey::default());
    assert_marker_slots(&merge, 5, &input_tree, &merge_nullifiers());
    assert_eq!(
        merge.accounts[13].pubkey,
        zolana_interface::PROGRAM_ID_PUBKEY
    );
    assert_eq!(merge.accounts.len(), 14);

    let merge_ring = MergeRing {
        input_tree,
        output_tree,
        ring_program_id,
        payer,
        data: merge_data(),
        output_ring_data_hash: [0u8; 32],
    }
    .cpi_instruction();
    assert_eq!(merge_ring.accounts[4].pubkey, Pubkey::default());
    assert_marker_slots(&merge_ring, 5, &input_tree, &merge_nullifiers());
    assert_eq!(
        merge_ring.accounts[13].pubkey,
        zolana_interface::PROGRAM_ID_PUBKEY
    );
    assert_eq!(merge_ring.accounts.len(), 14);
}

#[test]
fn same_pubkey_is_valid_in_both_tree_slots() {
    let tree = Pubkey::new_unique();
    let instruction = Transact {
        payer: Pubkey::new_unique(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::ConfidentialEddsa(0, 0, 3)),
    }
    .instruction();

    assert_tree_slots(&instruction, 1, tree, tree);
}
