//! Ring-deposit forwarder negatives.
//!
//! The forwarder's only work is validation plus the CPI into SPP, which mollusk
//! cannot execute (SPP is not loaded here), so both assertable failures are
//! pre-CPI. The successful forward is covered by the localnet end-to-end test.

use custom_ring_program::CustomRingError;
use pinocchio::cpi::MAX_CPI_ACCOUNTS;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use mollusk_svm::result::ProgramResult;
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

use crate::common::{
    account, deposit_fixture, entries_tree, initialized_policy_config_account,
    policy_deposit_fixture, ring_auth_pda, setup_mollusk, transfer_cap_policy_config_account,
    velocity_policy_config_account, Slot,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

#[test]
fn impostor_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = deposit_fixture();
    fixture.substitute("spp_program", Pubkey::new_from_array([71; 32]));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn missing_ring_auth_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = deposit_fixture();
    fixture.substitute("ring_config", Pubkey::new_from_array([72; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::MissingRingAuth));
}

#[test]
fn oversized_account_list_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = deposit_fixture();
    let mut filler = 100u8;
    // The config, co-signer and window slots stay behind, only the rest forwards.
    while fixture.instruction().accounts.len() - 4 <= MAX_CPI_ACCOUNTS {
        filler += 1;
        fixture.push(Slot {
            label: "filler",
            meta: AccountMeta::new_readonly(Pubkey::new_from_array([filler; 32]), false),
            account: account(1_000_000_000),
        });
    }
    fixture.expect_err(&mollusk, custom(CustomRingError::TooManyAccounts));
}

#[test]
fn the_forward_raises_only_ring_auth_to_a_signer() {
    let (mut mollusk, _) = setup_mollusk();
    let spp_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    mollusk.add_program(&spp_id, "spp_recorder_program");
    let mut fixture = deposit_fixture();
    let metas = fixture.instruction().accounts.clone();
    // The co-signer prefix and the window slots stay behind, SPP receives the
    // list from the tree onward.
    let tree_key = fixture.account_key("tree");
    let forwarded = metas
        .iter()
        .position(|meta| meta.pubkey == tree_key)
        .expect("tree in metas");
    let spp = &metas[forwarded..];
    let mut recorder = account(1_000_000_000);
    recorder.owner = spp_id;
    recorder.data = vec![0u8; spp.len()];
    fixture.set_account("tree", recorder);

    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let recorded = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &tree_key)
        .map(|(_, account)| account.data.clone())
        .expect("tree in result");
    let expected: Vec<u8> = spp
        .iter()
        .map(|meta| {
            let signer = meta.is_signer || meta.pubkey == ring_auth_pda().0;
            u8::from(signer) | u8::from(meta.is_writable) << 1
        })
        .collect();
    assert_eq!(recorded, expected);
}

#[test]
fn a_windowed_deposit_off_the_entries_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    // The default tree is foreign to the policy's entries tree.
    policy_deposit_fixture(velocity_policy_config_account())
        .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTree));
}

#[test]
fn a_windowed_deposit_into_the_entries_tree_reaches_the_spp_cpi() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_deposit_fixture(velocity_policy_config_account());
    fixture.substitute("tree", entries_tree());
    fixture.expect_spp_cpi(&mollusk);
}

#[test]
fn a_per_transfer_deposit_keeps_its_tree_choice() {
    let (mollusk, _) = setup_mollusk();
    policy_deposit_fixture(transfer_cap_policy_config_account()).expect_spp_cpi(&mollusk);
}

#[test]
fn an_ordinary_policy_deposit_keeps_its_tree_choice() {
    let (mollusk, _) = setup_mollusk();
    policy_deposit_fixture(initialized_policy_config_account()).expect_spp_cpi(&mollusk);
}

#[test]
fn an_audit_only_deposit_keeps_its_tree_choice() {
    let (mollusk, _) = setup_mollusk();
    deposit_fixture().expect_spp_cpi(&mollusk);
}
