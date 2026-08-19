//! `set_policy` negatives and the one positive that mollusk can run in full.

use custom_ring_program::{
    error::CustomRingError,
    instructions::set_policy::SetPolicyIxData,
    state::{
        RingProgramConfig, ASSETS_ALLOWLIST, ASSETS_ANY, MAX_ALLOWED_ASSETS, WITHDRAWALS_BLOCKED,
        WITHDRAWALS_OPEN,
    },
};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{
    account, auditor_pubkey, authority, config_pda, initialized_config_account, set_policy_fixture,
    setup_mollusk,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn allowlist(mints: Vec<[u8; 32]>) -> SetPolicyIxData {
    SetPolicyIxData {
        withdrawals: WITHDRAWALS_BLOCKED,
        asset_policy: ASSETS_ALLOWLIST,
        allowed_assets: mints,
    }
}

#[test]
fn policy_is_written_as_sent() {
    let (mollusk, _) = setup_mollusk();
    let usdc = [9u8; 32];
    let (instruction, accounts) = set_policy_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        &allowlist(vec![usdc, [0u8; 32]]),
    );
    let result = mollusk.process_and_validate_instruction(&instruction, &accounts, &[]);
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let (config_key, _) = config_pda();
    let config = result.get_account(&config_key).expect("config account");
    let state: &RingProgramConfig = bytemuck::from_bytes(&config.data);
    assert_eq!(state.withdrawals, WITHDRAWALS_BLOCKED);
    assert_eq!(state.asset_policy, ASSETS_ALLOWLIST);
    assert_eq!(state.allowed_assets(), &[usdc, [0u8; 32]]);
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
    for policy in [
        SetPolicyIxData {
            withdrawals: 2,
            asset_policy: ASSETS_ANY,
            allowed_assets: vec![],
        },
        SetPolicyIxData {
            withdrawals: WITHDRAWALS_OPEN,
            asset_policy: 2,
            allowed_assets: vec![],
        },
        allowlist(vec![[1u8; 32]; MAX_ALLOWED_ASSETS + 1]),
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
