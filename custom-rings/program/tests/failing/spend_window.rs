//! Pins independent public deposit and withdrawal counters for each mint.

use custom_ring_interface::{SpendWindow, AUDITOR_MESSAGE_LEN, SPEND_WINDOW};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::{InstructionResult, ProgramResult};
use pinocchio::Address;
use solana_account::Account;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::instruction::{
    instruction_data::deposit::DepositAssetKind, InterfaceTransfer,
};

use crate::common::{
    account, audit_only_config_account, audit_transact_fixture, auditor_pubkey, authority,
    clear_spend_window_fixture, custom, deposit_fixture, rent_recipient, ring_deposit_data,
    set_spend_window_data, set_spend_window_fixture, setup_mollusk, sol_settlement,
    spend_window_pda, spl_settlement, stored, window_slot, Fixture, Slot, WindowState, SOL,
    SOL_DEPOSIT_AMOUNT, USDC,
};
use crate::transact::{auditor_message, bogus_proof, instruction_data, transact};

const WINDOW_SLOTS: u64 = 100;

fn window(mint: Pubkey, deposit_cap: u64, withdrawal_cap: u64) -> WindowState {
    WindowState {
        mint,
        window_slots: WINDOW_SLOTS,
        deposit_cap,
        withdrawal_cap,
        window_start_slot: 0,
        deposited: 0,
        withdrawn: 0,
    }
}

fn stored_window(result: &InstructionResult, mint: Pubkey) -> SpendWindow {
    stored(result, spend_window_pda(mint).0)
}

#[test]
fn set_spend_window_creates_the_account_at_the_canonical_bump() {
    let (mut mollusk, _) = setup_mollusk();
    mollusk.warp_to_slot(1234);
    let fixture =
        set_spend_window_fixture(USDC, set_spend_window_data(USDC, WINDOW_SLOTS, 7, 9), None);
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = stored_window(&result, USDC);
    assert_eq!(written.discriminator, SPEND_WINDOW);
    assert_eq!(written.mint, Address::new_from_array(USDC.to_bytes()));
    assert_eq!(written.window_slots(), WINDOW_SLOTS);
    assert_eq!(written.deposit_cap(), 7);
    assert_eq!(written.withdrawal_cap(), 9);
    assert_eq!(written.window_start_slot(), 1200);
    assert_eq!(written.deposited(), 0);
    assert_eq!(written.withdrawn(), 0);
    assert_eq!(written.bump, spend_window_pda(USDC).1);
}

#[test]
fn set_spend_window_replaces_an_existing_account_and_restarts_the_counters() {
    let (mut mollusk, _) = setup_mollusk();
    mollusk.warp_to_slot(50);
    let mut existing = window(SOL, 10, 10);
    existing.deposited = 4;
    existing.withdrawn = 6;
    let fixture = set_spend_window_fixture(
        SOL,
        set_spend_window_data(SOL, 20, 0, 3),
        Some(existing.account()),
    );
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = stored_window(&result, SOL);
    assert_eq!(written.window_slots(), 20);
    assert_eq!(written.deposit_cap(), 0);
    assert_eq!(written.withdrawal_cap(), 3);
    assert_eq!(written.window_start_slot(), 40);
    assert_eq!(written.deposited(), 0);
    assert_eq!(written.withdrawn(), 0);
}

#[test]
fn a_zero_length_window_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    set_spend_window_fixture(SOL, set_spend_window_data(SOL, 0, 1, 1), None)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn set_spend_window_by_a_non_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        set_spend_window_fixture(SOL, set_spend_window_data(SOL, WINDOW_SLOTS, 1, 1), None);
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn set_spend_window_at_a_non_canonical_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        set_spend_window_fixture(SOL, set_spend_window_data(SOL, WINDOW_SLOTS, 1, 1), None);
    fixture.substitute("window", spend_window_pda(USDC).0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn set_spend_window_with_a_wrong_system_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        set_spend_window_fixture(SOL, set_spend_window_data(SOL, WINDOW_SLOTS, 1, 1), None);
    fixture.substitute("system_program", Pubkey::new_from_array([68; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSystemProgram));
}

#[test]
fn set_spend_window_with_trailing_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        set_spend_window_fixture(SOL, set_spend_window_data(SOL, WINDOW_SLOTS, 1, 1), None);
    fixture.push_data(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn clear_spend_window_closes_the_account_to_the_rent_recipient() {
    let (mollusk, _) = setup_mollusk();
    let fixture = clear_spend_window_fixture(USDC, window(USDC, 1, 1).account());
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let closed = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &spend_window_pda(USDC).0)
        .map(|(_, account)| account.clone())
        .expect("window in result");
    assert_eq!(closed.lamports, 0);
    assert!(closed.data.is_empty());
    let refunded = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &rent_recipient())
        .map(|(_, account)| account.lamports)
        .expect("rent recipient in result");
    assert_eq!(refunded, 1_000_000_000 + 1_500_000);
}

#[test]
fn clear_spend_window_before_set_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    clear_spend_window_fixture(USDC, account(0))
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn clear_spend_window_by_a_non_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = clear_spend_window_fixture(USDC, window(USDC, 1, 1).account());
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn clear_spend_window_into_itself_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = clear_spend_window_fixture(USDC, window(USDC, 1, 1).account());
    fixture.substitute("rent_recipient", spend_window_pda(USDC).0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn clear_spend_window_of_another_mint_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = clear_spend_window_fixture(USDC, window(USDC, 1, 1).account());
    fixture.substitute("window", spend_window_pda(SOL).0);
    fixture.set_account("window", window(SOL, 1, 1).account());
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn clear_spend_window_with_a_short_mint_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = clear_spend_window_fixture(USDC, window(USDC, 1, 1).account());
    fixture.data_mut().pop();
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

/// Repeated mint legs retain repeated canonical window account slots.
fn windowed_transact(
    legs: Vec<InterfaceTransfer>,
    windows: Vec<Slot>,
    settlements: Vec<Slot>,
) -> Fixture {
    let mut content = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    content.interface_transfers = legs;
    let mut fixture = audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        instruction_data(bogus_proof(), content),
    );
    fixture.insert_windows(windows);
    for slot in settlements {
        fixture.push(slot);
    }
    fixture
}

fn sol_withdrawal(amount: u64, window: Option<Account>) -> Fixture {
    windowed_transact(
        vec![InterfaceTransfer::SolWithdrawal { amount }],
        vec![window_slot(SOL, window)],
        sol_settlement(),
    )
}

#[test]
fn an_uninitialized_canonical_window_leaves_the_mint_uncapped() {
    let (mollusk, _) = setup_mollusk();
    sol_withdrawal(u64::MAX, None)
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_window_slot_at_another_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = sol_withdrawal(1, None);
    fixture.substitute("window", Pubkey::new_from_array([69; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
    let mut other_mint = sol_withdrawal(1, None);
    other_mint.substitute("window", spend_window_pda(USDC).0);
    other_mint.expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn an_omitted_window_slot_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = sol_withdrawal(1, None);
    fixture.remove("window");
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn a_withdrawal_above_the_cap_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut state = window(SOL, 0, 10);
    state.withdrawn = 5;
    sol_withdrawal(6, Some(state.account()))
        .expect_err(&mollusk, custom(CustomRingError::SpendWindowExceeded));
    sol_withdrawal(5, Some(state.account()))
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_zero_cap_still_checks_counter_overflow() {
    let (mollusk, _) = setup_mollusk();
    let mut state = window(SOL, 0, 0);
    state.withdrawn = u64::MAX - 1;
    sol_withdrawal(1, Some(state.account()))
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    sol_withdrawal(2, Some(state.account())).expect_err(&mollusk, ProgramError::ArithmeticOverflow);
}

#[test]
fn a_new_window_restarts_the_counters() {
    let (mut mollusk, _) = setup_mollusk();
    let mut state = window(SOL, 0, 10);
    state.withdrawn = 10;
    mollusk.warp_to_slot(WINDOW_SLOTS - 1);
    sol_withdrawal(1, Some(state.account()))
        .expect_err(&mollusk, custom(CustomRingError::SpendWindowExceeded));
    mollusk.warp_to_slot(WINDOW_SLOTS);
    sol_withdrawal(10, Some(state.account()))
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn the_legs_of_one_mint_sum_against_its_cap() {
    let (mollusk, _) = setup_mollusk();
    let split = || {
        let mut settlements = sol_settlement();
        settlements.extend(sol_settlement());
        windowed_transact(
            vec![
                InterfaceTransfer::SolWithdrawal { amount: 6 },
                InterfaceTransfer::SolWithdrawal { amount: 6 },
            ],
            vec![
                window_slot(SOL, Some(window(SOL, 0, 10).account())),
                Slot {
                    label: "second_window",
                    ..window_slot(SOL, None)
                },
            ],
            settlements,
        )
    };
    split().expect_err(&mollusk, custom(CustomRingError::SpendWindowExceeded));
    let mut relabeled = split();
    relabeled.substitute("second_window", spend_window_pda(USDC).0);
    relabeled.expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn each_mint_and_direction_has_its_own_cap() {
    let (mollusk, _) = setup_mollusk();
    let mixed = |sol: WindowState, usdc: WindowState| {
        let mut settlements = sol_settlement();
        settlements.extend(spl_settlement(USDC));
        windowed_transact(
            vec![
                InterfaceTransfer::SolDeposit { amount: 6 },
                InterfaceTransfer::SplWithdrawal {
                    amount: 6,
                    spl_interface_bump: 250,
                },
            ],
            vec![
                window_slot(SOL, Some(sol.account())),
                window_slot(USDC, Some(usdc.account())),
            ],
            settlements,
        )
    };
    mixed(window(SOL, 10, 1), window(USDC, 1, 10))
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    mixed(window(SOL, 5, 1), window(USDC, 1, 10))
        .expect_err(&mollusk, custom(CustomRingError::SpendWindowExceeded));
    mixed(window(SOL, 10, 1), window(USDC, 1, 5))
        .expect_err(&mollusk, custom(CustomRingError::SpendWindowExceeded));
}

#[test]
fn a_foreign_or_truncated_or_readonly_window_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut foreign = window(SOL, 0, 10).account();
    foreign.owner = Pubkey::new_from_array([70; 32]);
    sol_withdrawal(1, Some(foreign))
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
    let mut truncated = window(SOL, 0, 10).account();
    truncated.data.pop();
    sol_withdrawal(1, Some(truncated))
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
    let mut readonly = sol_withdrawal(1, Some(window(SOL, 0, 10).account()));
    readonly.set_writable("window", false);
    readonly.expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn the_ring_deposit_counts_against_the_deposit_cap() {
    let (mollusk, _) = setup_mollusk();
    let mut capped = deposit_fixture();
    capped.set_account("window", window(SOL, SOL_DEPOSIT_AMOUNT - 1, 0).account());
    capped.expect_err(&mollusk, custom(CustomRingError::SpendWindowExceeded));
    let mut under = deposit_fixture();
    under.set_account("window", window(SOL, SOL_DEPOSIT_AMOUNT, 0).account());
    under.expect_spp_cpi(&mollusk);
}

#[test]
fn a_ring_deposit_without_a_window_slot_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = deposit_fixture();
    fixture.remove("window");
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSpendWindow));
}

#[test]
fn a_ring_deposit_with_unreadable_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = deposit_fixture();
    fixture.data_mut().truncate(1);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
    let mut dangling = deposit_fixture();
    *dangling.data_mut() = ring_deposit_data(vec![DepositAssetKind::Sol], 1);
    // The entry references an asset outside the declared table.
    dangling.data_mut()[4] = 3;
    dangling.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}
