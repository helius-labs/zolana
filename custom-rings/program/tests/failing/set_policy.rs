//! `set_policy` negatives and the one positive that mollusk can run in full.

use custom_ring_program::{
    error::CustomRingError,
    instructions::set_policy::{AssetRuleData, SetPolicyIxData},
    state::{AssetPolicy, AssetRule, RingProgramConfig, WithdrawalRule, MAX_ASSETS},
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

fn allowlist(assets: Vec<AssetRuleData>) -> SetPolicyIxData {
    SetPolicyIxData {
        withdrawals: WithdrawalRule::Blocked as u8,
        asset_policy: AssetPolicy::Allowlist as u8,
        approver: [0u8; 32],
        assets,
    }
}

#[test]
fn policy_is_written_as_sent() {
    let (mollusk, _) = setup_mollusk();
    let usdc = AssetRuleData {
        mint: [9u8; 32],
        withdrawals: WithdrawalRule::Approval as u8,
    };
    let sol = AssetRuleData {
        mint: [0u8; 32],
        withdrawals: WithdrawalRule::Open as u8,
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
    assert_eq!(state.asset_policy(), AssetPolicy::Allowlist);
    assert_eq!(
        state.approver(),
        Some(&Address::new_from_array(approver().to_bytes()))
    );
    assert_eq!(
        state.assets().collect::<Vec<_>>(),
        vec![
            AssetRule {
                mint: usdc.mint,
                withdrawals: WithdrawalRule::Approval
            },
            AssetRule {
                mint: sol.mint,
                withdrawals: WithdrawalRule::Open
            },
        ]
    );
    assert_eq!(state.withdrawal_rule(&usdc.mint), WithdrawalRule::Approval);
    assert_eq!(state.withdrawal_rule(&sol.mint), WithdrawalRule::Open);
    assert_eq!(
        state.withdrawal_rule(&[5u8; 32]),
        WithdrawalRule::Blocked,
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
    let rule = |withdrawals| AssetRuleData {
        mint: [1u8; 32],
        withdrawals,
    };
    let distinct: Vec<AssetRuleData> = (0..=MAX_ASSETS as u8)
        .map(|index| AssetRuleData {
            mint: [index; 32],
            withdrawals: WithdrawalRule::Open as u8,
        })
        .collect();
    for policy in [
        SetPolicyIxData {
            withdrawals: 3,
            asset_policy: AssetPolicy::Any as u8,
            approver: [0u8; 32],
            assets: vec![],
        },
        SetPolicyIxData {
            withdrawals: WithdrawalRule::Open as u8,
            asset_policy: 2,
            approver: [0u8; 32],
            assets: vec![],
        },
        allowlist(distinct),
        allowlist(vec![rule(3)]),
        // The same mint twice would let one rule shadow the other.
        allowlist(vec![
            rule(WithdrawalRule::Open as u8),
            rule(WithdrawalRule::Blocked as u8),
        ]),
        // Approval anywhere needs an approver.
        allowlist(vec![rule(WithdrawalRule::Approval as u8)]),
        SetPolicyIxData {
            withdrawals: WithdrawalRule::Approval as u8,
            asset_policy: AssetPolicy::Any as u8,
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
