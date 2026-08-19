//! `set_policy` negatives and the one positive that mollusk can run in full.

use custom_ring_program::{
    error::CustomRingError,
    instructions::set_policy::{AssetRule, SetPolicyIxData},
    state::{
        RingProgramConfig, ASSETS_ALLOWLIST, ASSETS_ANY, MAX_ASSETS, WITHDRAWALS_APPROVAL,
        WITHDRAWALS_BLOCKED, WITHDRAWALS_OPEN,
    },
};
use pinocchio::Address;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{
    account, approver, auditor_pubkey, authority, config_pda, initialized_config_account,
    set_policy_fixture, setup_mollusk,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn allowlist(assets: Vec<AssetRule>) -> SetPolicyIxData {
    SetPolicyIxData {
        withdrawals: WITHDRAWALS_BLOCKED,
        asset_policy: ASSETS_ALLOWLIST,
        approver: [0u8; 32],
        assets,
    }
}

#[test]
fn policy_is_written_as_sent() {
    let (mollusk, _) = setup_mollusk();
    let usdc = AssetRule {
        mint: [9u8; 32],
        withdrawals: WITHDRAWALS_APPROVAL,
    };
    let sol = AssetRule {
        mint: [0u8; 32],
        withdrawals: WITHDRAWALS_OPEN,
    };
    let mut policy = allowlist(vec![usdc, sol]);
    policy.approver = approver().to_bytes();
    let (instruction, accounts) = set_policy_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        &policy,
    );
    let result = mollusk.process_and_validate_instruction(&instruction, &accounts, &[]);
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let (config_key, _) = config_pda();
    let config = result.get_account(&config_key).expect("config account");
    let state: &RingProgramConfig = bytemuck::from_bytes(&config.data);
    assert_eq!(state.withdrawals, WITHDRAWALS_BLOCKED);
    assert_eq!(state.asset_policy, ASSETS_ALLOWLIST);
    assert_eq!(
        state.approver,
        Address::new_from_array(approver().to_bytes())
    );
    assert_eq!(
        state.assets().collect::<Vec<_>>(),
        vec![(&usdc.mint, usdc.withdrawals), (&sol.mint, sol.withdrawals)]
    );
    assert_eq!(state.withdrawal_rule(&usdc.mint), WITHDRAWALS_APPROVAL);
    assert_eq!(state.withdrawal_rule(&sol.mint), WITHDRAWALS_OPEN);
    assert_eq!(
        state.withdrawal_rule(&[5u8; 32]),
        WITHDRAWALS_BLOCKED,
        "unlisted assets take the default rule"
    );
    assert_eq!(
        state.auditor_pubkey,
        auditor_pubkey(2),
        "the rest is untouched"
    );
}

#[test]
fn a_signer_other_than_the_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = set_policy_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        &allowlist(vec![]),
    );
    let impostor = Pubkey::new_from_array([77; 32]);
    instruction.accounts[0].pubkey = impostor;
    accounts.push((impostor, account(1_000_000_000)));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedAuthority),
    );
}

#[test]
fn an_uninitialized_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = set_policy_fixture(account(1_000_000_000), &allowlist(vec![]));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::ConfigNotInitialized),
    );
}

#[test]
fn out_of_range_policy_values_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let config = || initialized_config_account(authority(), auditor_pubkey(2));
    let rule = |withdrawals| AssetRule {
        mint: [1u8; 32],
        withdrawals,
    };
    for policy in [
        SetPolicyIxData {
            withdrawals: 3,
            asset_policy: ASSETS_ANY,
            approver: [0u8; 32],
            assets: vec![],
        },
        SetPolicyIxData {
            withdrawals: WITHDRAWALS_OPEN,
            asset_policy: 2,
            approver: [0u8; 32],
            assets: vec![],
        },
        allowlist(vec![rule(WITHDRAWALS_OPEN); MAX_ASSETS + 1]),
        allowlist(vec![rule(3)]),
        // Approval anywhere needs an approver.
        allowlist(vec![rule(WITHDRAWALS_APPROVAL)]),
        SetPolicyIxData {
            withdrawals: WITHDRAWALS_APPROVAL,
            asset_policy: ASSETS_ANY,
            approver: [0u8; 32],
            assets: vec![],
        },
    ] {
        let (instruction, accounts) = set_policy_fixture(config(), &policy);
        expect_err_exact(
            &mollusk,
            &instruction,
            &accounts,
            custom(CustomRingError::InvalidPolicy),
        );
    }
}
