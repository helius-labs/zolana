//! `approve_transact` negatives and its positive, which mollusk runs in full
//! (system program create is native).

use custom_ring_program::{
    error::CustomRingError,
    state::{WithdrawalRule, TRANSACT_APPROVAL},
    tag,
};
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{
    account, approval_account, approval_pda, approve_transact_fixture, approver, auditor_pubkey,
    authority, config_account_with_policy, initialized_config_account, setup_mollusk,
    PolicyFixture,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn config_with_approver() -> solana_account::Account {
    config_account_with_policy(
        authority(),
        auditor_pubkey(2),
        PolicyFixture {
            withdrawals: WithdrawalRule::Approval,
            approver: Some(approver()),
            ..PolicyFixture::default()
        },
    )
}

#[test]
fn approver_creates_the_approval_of_one_transact() {
    let (mollusk, _) = setup_mollusk();
    let private_tx_hash = [4u8; 32];
    let (instruction, accounts) = approve_transact_fixture(config_with_approver(), private_tx_hash);
    let result = mollusk.process_and_validate_instruction(&instruction, &accounts, &[]);
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let (address, bump) = approval_pda(&private_tx_hash);
    let approval = result.get_account(&address).expect("approval account");
    assert_eq!(approval.owner, crate::common::program_id());
    assert_eq!(approval.data, vec![TRANSACT_APPROVAL, bump]);
}

/// `revoke_approval` over the account `approve_transact` wrote. The account
/// closes and its lamports land with the rent recipient.
#[test]
fn approver_revokes_an_unspent_approval() {
    let (mollusk, _) = setup_mollusk();
    let private_tx_hash = [4u8; 32];
    let (address, approval) = approval_account(&private_tx_hash);
    let rent_recipient = Pubkey::new_from_array([80; 32]);
    let (config_key, _) = crate::common::config_pda();
    let mut data = vec![tag::REVOKE_APPROVAL];
    data.extend_from_slice(&private_tx_hash);
    let instruction = solana_instruction::Instruction {
        program_id: crate::common::program_id(),
        accounts: vec![
            AccountMeta::new_readonly(approver(), true),
            AccountMeta::new(rent_recipient, false),
            AccountMeta::new_readonly(config_key, false),
            AccountMeta::new(address, false),
        ],
        data,
    };
    let accounts = vec![
        (approver(), account(1_000_000_000)),
        (rent_recipient, account(1_000_000_000)),
        (config_key, config_with_approver()),
        (address, approval),
    ];
    let result = mollusk.process_and_validate_instruction(&instruction, &accounts, &[]);
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    assert_eq!(
        result.get_account(&rent_recipient).map(|a| a.lamports),
        Some(1_001_000_000)
    );
    assert_eq!(result.get_account(&address).map(|a| a.lamports), Some(0));

    // Not the approver.
    let mut wrong = instruction.clone();
    let impostor = Pubkey::new_from_array([81; 32]);
    wrong.accounts[0].pubkey = impostor;
    let mut wrong_accounts = accounts.clone();
    wrong_accounts.push((impostor, account(1_000_000_000)));
    expect_err_exact(
        &mollusk,
        &wrong,
        &wrong_accounts,
        custom(CustomRingError::UnauthorizedApprover),
    );
}

#[test]
fn a_config_without_approver_rejects_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = approve_transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        [4u8; 32],
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedApprover),
    );
}

#[test]
fn a_signer_other_than_the_approver_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) =
        approve_transact_fixture(config_with_approver(), [4u8; 32]);
    let impostor = Pubkey::new_from_array([78; 32]);
    instruction.accounts[0].pubkey = impostor;
    accounts.push((impostor, account(1_000_000_000)));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedApprover),
    );
}

#[test]
fn an_approval_at_the_wrong_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) =
        approve_transact_fixture(config_with_approver(), [4u8; 32]);
    let elsewhere = Pubkey::new_from_array([79; 32]);
    instruction.accounts[3].pubkey = elsewhere;
    accounts.push((elsewhere, account(0)));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidApproval),
    );
}
