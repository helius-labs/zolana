//! The velocity transact contract and the record registration, refused before the proof or the CPI.

use custom_ring_interface::{tag, COSIGN_DEPOSITS};
use custom_ring_program::CustomRingError;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, InputUtxo, OwnerTag, TransactIxData},
        InterfaceTransfer,
    },
    N_PUBLIC_SLOTS,
};

use crate::common::{
    account, auditor_pubkey, authority, cosigner_account, entries_tree, initialized_config_account,
    initialized_policy_config_account, payer, policy_delegate_transact_fixture,
    register_spend_fixture, setup_mollusk, spend_record_head_account, spend_record_head_pda,
    spend_record_head_slot, spend_record_output, transact_fixture, uninitialized_head_account,
    velocity_policy_config_account, window_slot, Fixture, Slot,
};
use crate::transact::{body, confidential_output, transact_data};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// The record output's member, keys the head and its spend address.
const RECORD_MEMBER_TAG: [u8; 32] = [61u8; 32];
/// The nullifier the registered head pins, the record input carries it.
const SPENT_RECORD_NULLIFIER: [u8; 32] = [0x5eu8; 32];

/// The record input the transfer spends, then the sender's money output, then
/// the successor record.
fn velocity_transact() -> TransactIxData {
    let mut content = transact_data();
    content.circuit = CircuitId::RingEddsa(2, 2, N_PUBLIC_SLOTS as u8);
    content.inputs = vec![InputUtxo {
        nullifier_hash: SPENT_RECORD_NULLIFIER,
        nullifier_tree_root_index: 0,
        utxo_tree_root_index: 0,
    }];
    content.outputs = vec![confidential_output(), spend_record_output(RECORD_MEMBER_TAG)];
    content
}

/// Both SPP trees are the entries tree, the record lives there, the sender's
/// head pins the spent record.
fn velocity_fixture(approval_required: u8, transact: TransactIxData) -> Fixture {
    registered_velocity_fixture(approval_required, transact, |bump| {
        spend_record_head_account(SPENT_RECORD_NULLIFIER, bump)
    })
}

fn registered_velocity_fixture(
    approval_required: u8,
    transact: TransactIxData,
    head: impl FnOnce(u8) -> solana_account::Account,
) -> Fixture {
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        body(0, 0, approval_required, transact),
    );
    fixture.set_account("policy_config", velocity_policy_config_account());
    fixture.substitute("input_tree", entries_tree());
    fixture.substitute("output_tree", entries_tree());
    let (_, bump) = spend_record_head_pda(RECORD_MEMBER_TAG);
    fixture.insert(6, spend_record_head_slot(RECORD_MEMBER_TAG, head(bump)));
    fixture
}

/// The spent record on the sender's head chain clears the boundary and reaches
/// the proof.
#[test]
fn a_velocity_transfer_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    velocity_fixture(0, velocity_transact())
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// No head means no registered record, the transfer cannot spend one.
#[test]
fn an_unregistered_sender_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    registered_velocity_fixture(0, velocity_transact(), |_| uninitialized_head_account())
        .expect_err(&mollusk, custom(CustomRingError::SpendRecordUnregistered));
}

/// A forged record whose nullifier is not the head's cannot reset the meter.
#[test]
fn a_record_off_the_head_chain_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    registered_velocity_fixture(0, velocity_transact(), |bump| {
        spend_record_head_account([0x11u8; 32], bump)
    })
    .expect_err(&mollusk, custom(CustomRingError::SpendRecordHeadMismatch));
}

#[test]
fn a_money_tree_apart_from_the_entries_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = velocity_fixture(0, velocity_transact());
    fixture.substitute("output_tree", Pubkey::new_from_array([42; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTree));
}

/// The published record must be the preimage of the last output's leaf.
#[test]
fn a_record_that_does_not_open_its_leaf_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut forged = velocity_transact();
    forged.outputs[1].utxo_hash[0] ^= 1;
    velocity_fixture(0, forged).expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));

    let mut foreign_owner = velocity_transact();
    foreign_owner.outputs[1].owner_tag = OwnerTag::Inline([9u8; 32]);
    velocity_fixture(0, foreign_owner)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));

    let mut truncated = velocity_transact();
    truncated.outputs[1]
        .data
        .as_mut()
        .expect("record data")
        .pop();
    velocity_fixture(0, truncated)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));

    // A plaintext slot anywhere but last is a money output without a scheme.
    let mut record_first = velocity_transact();
    record_first.outputs.swap(0, 1);
    velocity_fixture(0, record_first)
        .expect_err(&mollusk, custom(CustomRingError::UnsupportedOutputScheme));
}

/// Without the record slot there is nothing to charge.
#[test]
fn a_transfer_without_a_record_output_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut content = velocity_transact();
    content.outputs.truncate(1);
    velocity_fixture(0, content).expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

/// A deposit leg would let inflow exceed the record's inputs.
#[test]
fn a_deposit_leg_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut content = velocity_transact();
    content.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 5 }];
    let mut fixture = velocity_fixture(0, content);
    fixture.insert(7, window_slot(Pubkey::new_from_array([0; 32]), None));
    for byte in [53u8, 54] {
        fixture.push(Slot {
            label: "settlement",
            meta: AccountMeta::new(Pubkey::new_from_array([byte; 32]), false),
            account: account(1_000_000_000),
        });
    }
    fixture.expect_err(&mollusk, custom(CustomRingError::VelocityDepositLeg));
}

#[test]
fn the_delegate_rail_is_closed_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut content = velocity_transact();
    content.circuit = CircuitId::RingAuthority(2, 2, N_PUBLIC_SLOTS as u8);
    let mut data = body(0, 0, 0, content);
    data[0] = tag::DELEGATE_TRANSACT;
    let mut fixture = policy_delegate_transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        data,
    );
    fixture.set_account("policy_config", velocity_policy_config_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::DelegateOnVelocityRing));
}

/// The approval bit demands a configured co-signer whatever its scope.
#[test]
fn an_approval_needs_the_configured_cosigner() {
    let (mollusk, _) = setup_mollusk();
    velocity_fixture(1, velocity_transact())
        .expect_err(&mollusk, custom(CustomRingError::ApprovalWithoutCoSigner));

    let mut unsigned = velocity_fixture(1, velocity_transact());
    unsigned.set_account("cosigner_pda", cosigner_account(COSIGN_DEPOSITS, &[]));
    unsigned.expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));

    let mut signed = velocity_fixture(1, velocity_transact());
    signed.set_account("cosigner_pda", cosigner_account(COSIGN_DEPOSITS, &[]));
    signed.sign("cosigner");
    signed.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));

    let mut impostor = velocity_fixture(1, velocity_transact());
    impostor.set_account("cosigner_pda", cosigner_account(COSIGN_DEPOSITS, &[]));
    impostor.substitute("cosigner", Pubkey::new_from_array([39; 32]));
    impostor.sign("cosigner");
    impostor.expect_err(&mollusk, custom(CustomRingError::UnauthorizedCoSigner));
}

/// The bit is a velocity statement, a plain policy ring cannot carry it.
#[test]
fn an_approval_outside_velocity_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        body(0, 0, 1, transact_data()),
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
    velocity_fixture(2, velocity_transact())
        .expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn register_spend_needs_a_velocity_window() {
    let (mollusk, _) = setup_mollusk();
    register_spend_fixture(initialized_policy_config_account(), payer())
        .expect_err(&mollusk, custom(CustomRingError::VelocityDisabled));
}

#[test]
fn register_spend_reaches_the_cpi() {
    let (mollusk, _) = setup_mollusk();
    register_spend_fixture(velocity_policy_config_account(), payer()).expect_spp_cpi(&mollusk);
}

/// A member registers once, a second registration cannot reset the head.
#[test]
fn register_spend_refuses_a_second_registration() {
    let (mollusk, _) = setup_mollusk();
    let (_, bump) = spend_record_head_pda(payer().to_bytes());
    let mut fixture = register_spend_fixture(velocity_policy_config_account(), payer());
    fixture.set_account("record_head", spend_record_head_account([0x11u8; 32], bump));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::SpendRecordAlreadyRegistered),
    );
}
