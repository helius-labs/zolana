//! The permanent delegate and the authority rail it unlocks.

use custom_ring_interface::{tag, Delegate, AUDITOR_MESSAGE_LEN, COSIGN_TRANSFERS, DELEGATE};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use pinocchio::Address;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{CircuitId, InterfaceTransfer},
    N_PUBLIC_SLOTS,
};

use crate::common::{
    account, audit_only_config_account, auditor_pubkey, authority, cosigner_account, delegate,
    delegate_account, delegate_pda, delegate_transact_fixture, initialized_config_account,
    policy_delegate_transact_fixture, program_id, set_delegate_data, set_delegate_fixture,
    setup_mollusk, Fixture,
};
use crate::transact::{auditor_message, bogus_proof, instruction_data, transact};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

#[test]
fn set_delegate_creates_the_account_at_the_canonical_bump() {
    let (mollusk, _) = setup_mollusk();
    let fixture = set_delegate_fixture(set_delegate_data(delegate()), None);
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &delegate_pda().0)
        .map(|(_, account)| account.clone())
        .expect("delegate in result");
    assert_eq!(written.owner, program_id());
    let state = *bytemuck::from_bytes::<Delegate>(&written.data);
    assert_eq!(state.discriminator, DELEGATE);
    assert_eq!(
        state.delegate,
        Address::new_from_array(delegate().to_bytes())
    );
    assert_eq!(state.bump, delegate_pda().1);
}

#[test]
fn a_second_set_delegate_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let other = Pubkey::new_from_array([48; 32]);
    set_delegate_fixture(set_delegate_data(other), Some(delegate_account(delegate())))
        .expect_err(&mollusk, custom(CustomRingError::DelegateAlreadySet));
}

#[test]
fn set_delegate_by_the_config_authority_alone_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_delegate_fixture(set_delegate_data(delegate()), None);
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.sign("authority");
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn set_delegate_at_a_non_canonical_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_delegate_fixture(set_delegate_data(delegate()), None);
    fixture.substitute("delegate_pda", Pubkey::new_from_array([67; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidDelegate));
}

#[test]
fn set_delegate_with_a_wrong_system_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_delegate_fixture(set_delegate_data(delegate()), None);
    fixture.substitute("system_program", Pubkey::new_from_array([68; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSystemProgram));
}

#[test]
fn set_delegate_with_malformed_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut trailing = set_delegate_fixture(set_delegate_data(delegate()), None);
    trailing.push_data(0);
    trailing.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
    set_delegate_fixture(set_delegate_data(Pubkey::default()), None)
        .expect_err(&mollusk, custom(CustomRingError::InvalidDelegate));
}

/// Wire-valid authority rail content under the delegate tag.
fn delegate_move(legs: Vec<InterfaceTransfer>) -> Fixture {
    let mut content = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    content.circuit = CircuitId::RingAuthority(2, 2, N_PUBLIC_SLOTS as u8);
    content.interface_transfers = legs;
    let mut data = instruction_data(bogus_proof(), content);
    data[0] = tag::DELEGATE_TRANSACT;
    delegate_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        data,
    )
}

#[test]
fn a_delegate_move_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    delegate_move(Vec::new())
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// The policy accounts follow the delegate slots.
#[test]
fn a_policy_ring_delegate_move_reaches_the_policy_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    content.circuit = CircuitId::RingAuthority(2, 2, N_PUBLIC_SLOTS as u8);
    let mut data = instruction_data(bogus_proof(), content);
    data[0] = tag::DELEGATE_TRANSACT;
    policy_delegate_transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        data,
    )
    .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_ring_without_a_delegate_refuses_the_rail_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = delegate_move(Vec::new());
    fixture.set_account("delegate_pda", account(0));
    fixture.expect_err(&mollusk, custom(CustomRingError::DelegateDisabled));
}

#[test]
fn a_delegate_pda_at_another_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = delegate_move(Vec::new());
    fixture.substitute("delegate_pda", Pubkey::new_from_array([69; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidDelegate));
}

#[test]
fn a_move_needs_the_delegate_signature() {
    let (mollusk, _) = setup_mollusk();
    let mut unsigned = delegate_move(Vec::new());
    unsigned.unsign("delegate");
    unsigned.expect_err(&mollusk, custom(CustomRingError::UnauthorizedDelegate));
    let mut impostor = delegate_move(Vec::new());
    impostor.substitute("delegate", Pubkey::new_from_array([49; 32]));
    impostor.sign("delegate");
    impostor.expect_err(&mollusk, custom(CustomRingError::UnauthorizedDelegate));
}

/// Refused before the co-signer and the proof.
#[test]
fn a_public_leg_on_the_delegate_rail_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    delegate_move(vec![InterfaceTransfer::SolWithdrawal { amount: 1 }])
        .expect_err(&mollusk, custom(CustomRingError::DelegatePublicLeg));
}

#[test]
fn the_member_circuit_on_the_delegate_rail_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    content.circuit = CircuitId::RingEddsa(2, 3, N_PUBLIC_SLOTS as u8);
    let mut data = instruction_data(bogus_proof(), content);
    data[0] = tag::DELEGATE_TRANSACT;
    delegate_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        data,
    )
    .expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
}

#[test]
fn the_authority_circuit_on_the_member_rail_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    content.circuit = CircuitId::RingAuthority(2, 2, N_PUBLIC_SLOTS as u8);
    crate::common::audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        instruction_data(bogus_proof(), content),
    )
    .expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
}

#[test]
fn a_delegate_move_still_needs_the_auditor_message() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact(Vec::new());
    content.circuit = CircuitId::RingAuthority(2, 2, N_PUBLIC_SLOTS as u8);
    let mut data = instruction_data(bogus_proof(), content);
    data[0] = tag::DELEGATE_TRANSACT;
    delegate_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        data,
    )
    .expect_err(&mollusk, custom(CustomRingError::MissingAuditorMessage));
}

#[test]
fn a_transfer_scoped_cosigner_gates_the_delegate_move() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = delegate_move(Vec::new());
    fixture.set_account("cosigner_pda", cosigner_account(COSIGN_TRANSFERS, &[]));
    fixture.expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));
}
