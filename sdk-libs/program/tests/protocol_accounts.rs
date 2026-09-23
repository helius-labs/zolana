#![cfg(feature = "protocol")]

use borsh::BorshDeserialize;
use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
use zolana_interface::instruction::{tag, SetTreeFeesData};
use zolana_interface::{pda, PROGRAM_ID_PUBKEY};
use zolana_program::instruction::{
    nullifier_pda_accounts, ClaimTreeLamports, CloseNullifierPdas, SetTreeFees,
};

#[test]
fn close_nullifier_pdas_builder_encodes_data_and_exact_accounts() {
    let authority = Pubkey::new_unique();
    let tree = Pubkey::new_unique();
    let reimbursement_recipient = Pubkey::new_unique();
    let nullifiers = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let instruction = CloseNullifierPdas {
        authority,
        tree,
        reimbursement_recipient,
        nullifiers: nullifiers.clone(),
    }
    .instruction();

    let mut expected_accounts = vec![
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new_readonly(pda::protocol_config(), false),
        AccountMeta::new(tree, false),
        AccountMeta::new(reimbursement_recipient, false),
    ];
    expected_accounts.extend(nullifier_pda_accounts(&tree, &nullifiers));
    assert_eq!(instruction.accounts, expected_accounts);
    assert_eq!(instruction.program_id, PROGRAM_ID_PUBKEY);
    assert_eq!(instruction.data, vec![tag::CLOSE_NULLIFIER_PDAS]);
}

#[test]
fn set_tree_fees_builder_has_exact_accounts_and_data() {
    let authority = Pubkey::new_unique();
    let tree = Pubkey::new_unique();
    let fees = SetTreeFeesData {
        fee_per_nullifier: 190,
        append_reimbursement: 5_000,
        close_reimbursement: 170,
    };
    let instruction = SetTreeFees {
        authority,
        tree,
        fees,
    }
    .instruction();

    assert_eq!(instruction.program_id, PROGRAM_ID_PUBKEY);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(tree, false),
        ]
    );
    assert_eq!(instruction.data.len(), 25);
    assert_eq!(instruction.data.first(), Some(&tag::SET_TREE_FEES));
    assert_eq!(
        SetTreeFeesData::try_from_slice(instruction.data.get(1..).unwrap()).unwrap(),
        fees
    );
}

#[test]
fn claim_tree_lamports_builder_has_exact_accounts_and_data() {
    let authority = Pubkey::new_unique();
    let tree = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let instruction = ClaimTreeLamports {
        authority,
        tree,
        recipient,
    }
    .instruction();

    assert_eq!(instruction.program_id, PROGRAM_ID_PUBKEY);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(tree, false),
            AccountMeta::new(recipient, false),
        ]
    );
    assert_eq!(instruction.data, vec![tag::CLAIM_TREE_LAMPORTS]);
}
