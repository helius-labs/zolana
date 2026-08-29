#![cfg(feature = "solana")]

use borsh::BorshDeserialize;
use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
use zolana_interface::instruction::instruction_data::merge_transact::MergeProof;
use zolana_interface::instruction::{
    nullifier_pda_accounts, tag, CircuitId, CloseNullifierPdas, CloseNullifierPdasData, InputUtxo,
    MergeRing, MergeTransact, MergeTransactIxData, RingAuthorityTransact, RingTransact, Transact,
    TransactIxData, TransactProof,
};
use zolana_interface::{pda, PROGRAM_ID_PUBKEY};

fn transact_data(circuit: CircuitId, nullifiers: &[[u8; 32]]) -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: nullifiers
            .iter()
            .map(|nullifier_hash| InputUtxo {
                nullifier_hash: *nullifier_hash,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
            })
            .collect(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: Vec::new(),
    }
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

fn nullifier_pdas(tree: &Pubkey, nullifiers: &[[u8; 32]]) -> Vec<AccountMeta> {
    nullifier_pda_accounts(tree, nullifiers)
}

#[test]
fn every_spend_builder_has_the_exact_account_layout() {
    let payer = Pubkey::new_unique();
    let input_tree = Pubkey::new_unique();
    let output_tree = Pubkey::new_unique();
    let ring_program_id = Pubkey::new_unique();
    let ring_auth = pda::ring_auth(&ring_program_id).0;
    let owner_signer = Pubkey::new_unique();
    let user_record = Pubkey::new_unique();
    let nullifiers = [[11u8; 32], [22u8; 32]];
    let nullifier_pda_metas = nullifier_pdas(&input_tree, &nullifiers);

    let transact = Transact {
        payer,
        input_tree,
        output_tree,
        owner_signers: vec![owner_signer],
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::ConfidentialEddsa(2, 2, 3), &nullifiers),
    }
    .instruction();
    let mut expected_transact = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(input_tree, false),
        AccountMeta::new(output_tree, false),
        AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        AccountMeta::new_readonly(Pubkey::default(), false),
    ];
    expected_transact.extend(nullifier_pda_metas.clone());
    expected_transact.push(AccountMeta::new_readonly(owner_signer, true));
    assert_eq!(transact.accounts, expected_transact);

    let ring = RingTransact {
        payer,
        input_tree,
        output_tree,
        ring_program_id,
        owner_signers: vec![owner_signer],
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::RingEddsa(2, 2, 3), &nullifiers),
    }
    .cpi_instruction();
    let mut expected_ring = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(input_tree, false),
        AccountMeta::new(output_tree, false),
        AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new_readonly(ring_auth, true),
    ];
    expected_ring.extend(nullifier_pda_metas.clone());
    expected_ring.push(AccountMeta::new_readonly(owner_signer, true));
    assert_eq!(ring.accounts, expected_ring);

    let ring_authority = RingAuthorityTransact {
        payer,
        input_tree,
        output_tree,
        ring_program_id,
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::RingAuthority(2, 2, 3), &nullifiers),
    }
    .cpi_instruction();
    let mut expected_ring_authority = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(input_tree, false),
        AccountMeta::new(output_tree, false),
        AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new_readonly(ring_auth, true),
    ];
    expected_ring_authority.extend(nullifier_pda_metas);
    assert_eq!(ring_authority.accounts, expected_ring_authority);

    let merge_data = merge_data();
    let merge_nullifier_pdas = nullifier_pdas(&input_tree, &merge_data.nullifiers);
    let merge = MergeTransact {
        input_tree,
        output_tree,
        payer,
        user_record,
        data: merge_data.clone(),
    }
    .instruction();
    let mut expected_merge = vec![
        AccountMeta::new(input_tree, false),
        AccountMeta::new(output_tree, false),
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(user_record, false),
        AccountMeta::new_readonly(Pubkey::default(), false),
    ];
    expected_merge.extend(merge_nullifier_pdas.clone());
    expected_merge.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));
    assert_eq!(merge.accounts, expected_merge);

    let merge_ring = MergeRing {
        input_tree,
        output_tree,
        ring_program_id,
        payer,
        data: merge_data,
        output_ring_data_hash: [0u8; 32],
    }
    .cpi_instruction();
    let mut expected_merge_ring = vec![
        AccountMeta::new(input_tree, false),
        AccountMeta::new(output_tree, false),
        AccountMeta::new_readonly(ring_auth, true),
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(Pubkey::default(), false),
    ];
    expected_merge_ring.extend(merge_nullifier_pdas);
    expected_merge_ring.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));
    assert_eq!(merge_ring.accounts, expected_merge_ring);
}

#[test]
fn outer_ring_builders_target_the_ring_and_leave_auth_unsigned() {
    let payer = Pubkey::new_unique();
    let tree = Pubkey::new_unique();
    let ring_program_id = Pubkey::new_unique();
    let ring_auth = pda::ring_auth(&ring_program_id).0;

    let ring = RingTransact {
        payer,
        input_tree: tree,
        output_tree: tree,
        ring_program_id,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::RingEddsa(0, 0, 3), &[]),
    }
    .instruction();
    assert_eq!(ring.program_id, ring_program_id);
    assert_eq!(
        ring.accounts,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(ring_auth, false),
        ]
    );

    let authority = RingAuthorityTransact {
        payer,
        input_tree: tree,
        output_tree: tree,
        ring_program_id,
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::RingAuthority(0, 0, 3), &[]),
    }
    .instruction();
    assert_eq!(authority.program_id, ring_program_id);
    assert_eq!(authority.accounts, ring.accounts);
}

#[test]
fn close_nullifier_pdas_builder_encodes_data_and_exact_accounts() {
    let tree = Pubkey::new_unique();
    let nullifiers = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let instruction = CloseNullifierPdas {
        tree,
        nullifiers: nullifiers.clone(),
    }
    .instruction();

    let mut expected_accounts = vec![AccountMeta::new(tree, false)];
    expected_accounts.extend(nullifier_pdas(&tree, &nullifiers));
    assert_eq!(instruction.accounts, expected_accounts);
    assert_eq!(instruction.program_id, PROGRAM_ID_PUBKEY);
    assert_eq!(instruction.data.first(), Some(&tag::CLOSE_NULLIFIER_PDAS));
    assert_eq!(
        CloseNullifierPdasData::try_from_slice(&instruction.data[1..]).unwrap(),
        CloseNullifierPdasData { nullifiers }
    );
}

#[test]
fn same_pubkey_is_valid_in_both_tree_slots() {
    let payer = Pubkey::new_unique();
    let tree = Pubkey::new_unique();
    let instruction = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_data(CircuitId::ConfidentialEddsa(0, 0, 3), &[]),
    }
    .instruction();

    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ]
    );
}
