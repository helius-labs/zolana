//! Ring-deposit forwarder negatives.
//!
//! The forwarder's only work is validation plus the CPI into SPP, which mollusk
//! cannot execute (SPP is not loaded here), so every assertable failure is
//! pre-CPI. The successful forward is covered by the localnet end-to-end test.

use custom_ring_program::{
    error::CustomRingError,
    state::{AssetRule, WithdrawalRule, SOL_MINT},
};
use pinocchio::cpi::MAX_CPI_ACCOUNTS;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::instruction::{
    DepositAssetKind, EncryptedRingDepositData, RingDepositEntry, RingDepositIxData,
};
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{
    account, auditor_pubkey, authority, config_account_with_policy, deposit_fixture,
    deposit_fixture_with, setup_mollusk, substitute_account, PolicyFixture,
};

fn allowlist(mint: [u8; 32]) -> solana_account::Account {
    config_account_with_policy(
        authority(),
        auditor_pubkey(2),
        PolicyFixture {
            allowlist: true,
            assets: &[AssetRule {
                mint,
                withdrawals: WithdrawalRule::Open,
            }],
            ..PolicyFixture::default()
        },
    )
}

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

#[test]
fn impostor_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = deposit_fixture();
    substitute_account(
        &mut instruction,
        &mut accounts,
        4,
        Pubkey::new_from_array([71; 32]),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn missing_ring_auth_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = deposit_fixture();
    substitute_account(
        &mut instruction,
        &mut accounts,
        3,
        Pubkey::new_from_array([72; 32]),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::MissingRingAuth),
    );
}

/// The forwarder names the runtime's CPI account limit instead of surfacing the
/// loader's opaque `InvalidArgument`.
#[test]
fn oversized_account_list_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = deposit_fixture();
    // Filler addresses start above every address the fixture already uses. The
    // ring config in front is not forwarded, so the forwarded list is one
    // shorter than the instruction's.
    let mut filler = 100u8;
    while instruction.accounts.len() <= MAX_CPI_ACCOUNTS + 1 {
        filler += 1;
        let key = Pubkey::new_from_array([filler; 32]);
        instruction
            .accounts
            .push(AccountMeta::new_readonly(key, false));
        accounts.push((key, account(1_000_000_000)));
    }
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::TooManyAccounts),
    );
}

/// A SOL deposit body as SPP's `RING_DEPOSIT` carries it, with one full entry
/// after the asset kinds: the policy reads only the prefix and must leave the
/// entry alone.
fn sol_deposit_body() -> Vec<u8> {
    RingDepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits: vec![RingDepositEntry {
            asset_index: 0,
            view_tag: [1u8; 32],
            owner_utxo_hash: [2u8; 32],
            amount: 7,
            data_hash: Some([3u8; 32]),
            ring_data_hash: [4u8; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [2u8; 33],
                salt: [5u8; 16],
                ciphertext: vec![6u8; 300],
            },
        }],
    }
    .serialize()
    .expect("serialize ring deposit")
}

/// The policy check runs before the CPI, so a disallowed asset is named even
/// though SPP is not loaded.
#[test]
fn deposit_of_an_asset_outside_the_allowlist_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = deposit_fixture_with(allowlist([9u8; 32]), sol_deposit_body());
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::AssetNotAllowed),
    );
}

/// An allowlisted deposit passes the policy and reaches the CPI, which fails
/// here only because SPP is not loaded.
#[test]
fn deposit_of_an_allowlisted_asset_reaches_the_forward() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = deposit_fixture_with(allowlist(SOL_MINT), sol_deposit_body());
    let result = mollusk.process_instruction(&instruction, &accounts);
    assert_ne!(
        result.program_result,
        mollusk_svm::result::ProgramResult::Failure(custom(CustomRingError::AssetNotAllowed)),
        "SOL is on the allowlist"
    );
    assert_ne!(
        result.program_result,
        mollusk_svm::result::ProgramResult::Failure(custom(
            CustomRingError::InvalidInstructionData
        )),
        "the deposit body parses"
    );
}
