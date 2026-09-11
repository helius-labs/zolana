//! The co-signer account and the operations it gates.

use custom_ring_interface::{
    tag, CoSigner, AUDITOR_MESSAGE_LEN, COSIGN_DEPOSITS, COSIGN_TRANSFERS, COSIGN_WITHDRAWALS,
    CO_SIGNER, MAX_CO_SIGNER_THRESHOLDS,
};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use pinocchio::Address;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::instruction::InterfaceTransfer;

use crate::common::{
    account, audit_only_config_account, audit_transact_fixture, auditor_pubkey, authority,
    clear_cosigner_fixture, cosigner, cosigner_account, cosigner_pda, deposit_fixture,
    rent_recipient, set_cosigner_data, set_cosigner_fixture, setup_mollusk, Fixture, Slot,
};
use crate::transact::{auditor_message, bogus_proof, instruction_data, transact};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

const SOL: Pubkey = Pubkey::new_from_array([0; 32]);
const USDC: Pubkey = Pubkey::new_from_array([60; 32]);

fn stored(result: &mollusk_svm::result::InstructionResult) -> CoSigner {
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &cosigner_pda().0)
        .map(|(_, account)| account.clone())
        .expect("cosigner in result");
    assert_eq!(written.owner, crate::common::program_id());
    *bytemuck::from_bytes::<CoSigner>(&written.data)
}

#[test]
fn set_cosigner_creates_the_account_at_the_canonical_bump() {
    let (mollusk, _) = setup_mollusk();
    let fixture = set_cosigner_fixture(
        set_cosigner_data(cosigner(), COSIGN_WITHDRAWALS, &[(SOL, 10), (USDC, 20)]),
        None,
    );
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = stored(&result);
    assert_eq!(written.discriminator, CO_SIGNER);
    assert_eq!(
        written.signer,
        Address::new_from_array(cosigner().to_bytes())
    );
    assert_eq!(written.scope, COSIGN_WITHDRAWALS);
    assert_eq!(written.bump, cosigner_pda().1);
    assert_eq!(
        written.threshold(&Address::new_from_array(USDC.to_bytes())),
        Some(20)
    );
    assert_eq!(written.threshold(&Address::new_from_array([61; 32])), None);
}

#[test]
fn set_cosigner_replaces_an_existing_account_in_place() {
    let (mollusk, _) = setup_mollusk();
    let other = Pubkey::new_from_array([38; 32]);
    let fixture = set_cosigner_fixture(
        set_cosigner_data(other, COSIGN_TRANSFERS, &[]),
        Some(cosigner_account(COSIGN_WITHDRAWALS, &[(SOL, 10)])),
    );
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = stored(&result);
    assert_eq!(written.signer, Address::new_from_array(other.to_bytes()));
    assert_eq!(written.scope, COSIGN_TRANSFERS);
    assert_eq!(written.threshold_count, 0);
}

#[test]
fn a_zero_scope_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    set_cosigner_fixture(set_cosigner_data(cosigner(), 0, &[]), None)
        .expect_err(&mollusk, custom(CustomRingError::InvalidCoSignerScope));
}

#[test]
fn a_scope_bit_outside_the_mask_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    set_cosigner_fixture(set_cosigner_data(cosigner(), 8, &[]), None)
        .expect_err(&mollusk, custom(CustomRingError::InvalidCoSignerScope));
}

#[test]
fn a_ninth_threshold_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let rows: Vec<(Pubkey, u64)> = (0..=MAX_CO_SIGNER_THRESHOLDS as u8)
        .map(|byte| (Pubkey::new_from_array([byte; 32]), 1))
        .collect();
    set_cosigner_fixture(
        set_cosigner_data(cosigner(), COSIGN_WITHDRAWALS, &rows),
        None,
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidCoSignerThresholds));
}

#[test]
fn a_repeated_threshold_mint_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    set_cosigner_fixture(
        set_cosigner_data(cosigner(), COSIGN_WITHDRAWALS, &[(USDC, 1), (USDC, 2)]),
        None,
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidCoSignerThresholds));
}

#[test]
fn set_cosigner_by_a_non_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        set_cosigner_fixture(set_cosigner_data(cosigner(), COSIGN_TRANSFERS, &[]), None);
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn set_cosigner_at_a_non_canonical_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        set_cosigner_fixture(set_cosigner_data(cosigner(), COSIGN_TRANSFERS, &[]), None);
    fixture.substitute("cosigner_pda", Pubkey::new_from_array([67; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidCoSigner));
}

#[test]
fn set_cosigner_with_a_wrong_system_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        set_cosigner_fixture(set_cosigner_data(cosigner(), COSIGN_TRANSFERS, &[]), None);
    fixture.substitute("system_program", Pubkey::new_from_array([68; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSystemProgram));
}

#[test]
fn set_cosigner_with_trailing_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        set_cosigner_fixture(set_cosigner_data(cosigner(), COSIGN_TRANSFERS, &[]), None);
    fixture.push_data(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn clear_cosigner_closes_the_account_to_the_rent_recipient() {
    let (mollusk, _) = setup_mollusk();
    let fixture = clear_cosigner_fixture(cosigner_account(COSIGN_TRANSFERS, &[]));
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let closed = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &cosigner_pda().0)
        .map(|(_, account)| account.clone())
        .expect("cosigner in result");
    assert_eq!(closed.lamports, 0);
    assert!(closed.data.is_empty());
    let refunded = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &rent_recipient())
        .map(|(_, account)| account.lamports)
        .expect("rent recipient in result");
    assert_eq!(refunded, 1_000_000_000 + 3_000_000);
}

#[test]
fn clear_cosigner_before_set_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    clear_cosigner_fixture(account(0))
        .expect_err(&mollusk, custom(CustomRingError::InvalidCoSigner));
}

#[test]
fn clear_cosigner_by_a_non_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = clear_cosigner_fixture(cosigner_account(COSIGN_TRANSFERS, &[]));
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn clear_cosigner_into_itself_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = clear_cosigner_fixture(cosigner_account(COSIGN_TRANSFERS, &[]));
    fixture.substitute("rent_recipient", cosigner_pda().0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidCoSigner));
}

#[test]
fn clear_cosigner_with_trailing_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = clear_cosigner_fixture(cosigner_account(COSIGN_TRANSFERS, &[]));
    fixture.push_data(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

/// An audit-only transact whose gate decides before the proof, `legs` trail
/// as SPP settlement groups.
fn gated_transact(legs: Vec<InterfaceTransfer>, settlements: Vec<Slot>) -> Fixture {
    let mut content = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    content.interface_transfers = legs;
    let mut fixture = audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        instruction_data(bogus_proof(), content),
    );
    for slot in settlements {
        fixture.push(slot);
    }
    fixture
}

fn sol_withdrawal_slots() -> Vec<Slot> {
    vec![
        Slot {
            label: "sol_interface",
            meta: AccountMeta::new(Pubkey::new_from_array([53; 32]), false),
            account: account(1_000_000_000),
        },
        Slot {
            label: "recipient",
            meta: AccountMeta::new(Pubkey::new_from_array([54; 32]), false),
            account: account(1_000_000_000),
        },
    ]
}

/// `[cpi_authority, mint, spl_interface, user_token_account, token_program]`.
fn spl_withdrawal_slots(mint: Pubkey) -> Vec<Slot> {
    [55u8, 0, 56, 57, 58]
        .into_iter()
        .enumerate()
        .map(|(index, byte)| Slot {
            label: "spl_settlement",
            meta: AccountMeta::new_readonly(
                if index == 1 {
                    mint
                } else {
                    Pubkey::new_from_array([byte; 32])
                },
                false,
            ),
            account: account(1_000_000_000),
        })
        .collect()
}

fn with_cosigner(mut fixture: Fixture, account: Account, signed: bool) -> Fixture {
    fixture.set_account("cosigner_pda", account);
    if signed {
        fixture.sign("cosigner");
    }
    fixture
}

#[test]
fn a_ring_without_a_cosigner_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    gated_transact(Vec::new(), Vec::new())
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_cosigner_pda_at_another_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = gated_transact(Vec::new(), Vec::new());
    fixture.substitute("cosigner_pda", Pubkey::new_from_array([67; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidCoSigner));
}

#[test]
fn a_transfer_in_scope_needs_the_cosigner_signature() {
    let (mollusk, _) = setup_mollusk();
    let scoped = cosigner_account(COSIGN_TRANSFERS, &[]);
    with_cosigner(
        gated_transact(Vec::new(), Vec::new()),
        scoped.clone(),
        false,
    )
    .expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));
    let mut impostor = with_cosigner(gated_transact(Vec::new(), Vec::new()), scoped.clone(), true);
    impostor.substitute("cosigner", Pubkey::new_from_array([39; 32]));
    impostor.sign("cosigner");
    impostor.expect_err(&mollusk, custom(CustomRingError::UnauthorizedCoSigner));
    with_cosigner(gated_transact(Vec::new(), Vec::new()), scoped, true)
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// A transact is always a transfer, a deposit leg adds the deposit class.
#[test]
fn a_deposit_scope_gates_only_a_transact_with_a_deposit_leg() {
    let (mollusk, _) = setup_mollusk();
    let scoped = cosigner_account(COSIGN_DEPOSITS, &[]);
    with_cosigner(
        gated_transact(Vec::new(), Vec::new()),
        scoped.clone(),
        false,
    )
    .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    with_cosigner(
        gated_transact(
            vec![InterfaceTransfer::SolDeposit { amount: 5 }],
            sol_withdrawal_slots(),
        ),
        scoped,
        false,
    )
    .expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));
}

#[test]
fn withdrawal_thresholds_sum_the_legs_of_one_mint() {
    let (mollusk, _) = setup_mollusk();
    let scoped = cosigner_account(COSIGN_WITHDRAWALS, &[(SOL, 10)]);
    let one_leg = gated_transact(
        vec![InterfaceTransfer::SolWithdrawal { amount: 6 }],
        sol_withdrawal_slots(),
    );
    with_cosigner(one_leg, scoped.clone(), false)
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    let mut two_legs = sol_withdrawal_slots();
    two_legs.extend(sol_withdrawal_slots());
    let split = gated_transact(
        vec![
            InterfaceTransfer::SolWithdrawal { amount: 6 },
            InterfaceTransfer::SolWithdrawal { amount: 6 },
        ],
        two_legs,
    );
    with_cosigner(split, scoped, false)
        .expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));
}

/// SOL and a mint never share a threshold, a mint without a row always needs
/// the co-signer.
#[test]
fn a_withdrawn_mint_without_a_threshold_row_needs_the_cosigner() {
    let (mollusk, _) = setup_mollusk();
    let scoped = cosigner_account(COSIGN_WITHDRAWALS, &[(SOL, 10)]);
    let spl = gated_transact(
        vec![InterfaceTransfer::SplWithdrawal {
            amount: 1,
            spl_interface_bump: 250,
        }],
        spl_withdrawal_slots(USDC),
    );
    with_cosigner(spl, scoped, false)
        .expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));
    let rowed = cosigner_account(COSIGN_WITHDRAWALS, &[(USDC, 10)]);
    let under = gated_transact(
        vec![InterfaceTransfer::SplWithdrawal {
            amount: 10,
            spl_interface_bump: 250,
        }],
        spl_withdrawal_slots(USDC),
    );
    with_cosigner(under, rowed, false)
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_deposit_scope_gates_the_ring_deposit() {
    let (mollusk, _) = setup_mollusk();
    with_cosigner(
        deposit_fixture(),
        cosigner_account(COSIGN_TRANSFERS, &[]),
        false,
    )
    .expect_spp_cpi(&mollusk);
    with_cosigner(
        deposit_fixture(),
        cosigner_account(COSIGN_DEPOSITS, &[]),
        false,
    )
    .expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));
    with_cosigner(
        deposit_fixture(),
        cosigner_account(COSIGN_DEPOSITS, &[]),
        true,
    )
    .expect_spp_cpi(&mollusk);
}

#[test]
fn a_transfer_scope_gates_the_merge() {
    let (mollusk, _) = setup_mollusk();
    let mut merge = deposit_fixture();
    merge.data_mut()[0] = tag::MERGE;
    with_cosigner(merge, cosigner_account(COSIGN_TRANSFERS, &[]), false)
        .expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));
}
