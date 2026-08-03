#![cfg(feature = "solana")]

use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_interface::instruction::instruction_data::merge_transact::MergeProof;
use zolana_interface::instruction::{
    CircuitId, MergeRing, MergeTransact, MergeTransactIxData, RingAuthorityTransact, RingTransact,
    Transact, TransactIxData, TransactProof,
};

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

fn merge_data() -> MergeTransactIxData {
    MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [0u8; 32],
        eddsa_owner: true,
        private_tx_hash: [0u8; 32],
        nullifiers: vec![[0u8; 32]; 8],
        utxo_tree_root_index: vec![0; 8],
        nullifier_tree_root_index: vec![0; 8],
    }
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
