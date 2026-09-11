//! The velocity transact contract and the record registration, refused before the proof or the CPI.

use custom_ring_interface::{tag, COSIGN_DEPOSITS};
use custom_ring_program::CustomRingError;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, OwnerTag, TransactIxData},
        InterfaceTransfer,
    },
    N_PUBLIC_SLOTS,
};

use crate::common::{
    account, auditor_pubkey, authority, cosigner_account, entries_tree, initialized_config_account,
    initialized_policy_config_account, payer, policy_delegate_transact_fixture,
    register_spend_fixture, setup_mollusk, spend_record_output, transact_fixture,
    velocity_policy_config_account, window_slot, Fixture, Slot,
};
use crate::transact::{body, confidential_output, transact_data};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// The sender's money output, then its record.
fn velocity_transact() -> TransactIxData {
    let mut content = transact_data();
    content.circuit = CircuitId::RingEddsa(2, 2, N_PUBLIC_SLOTS as u8);
    content.outputs = vec![confidential_output(), spend_record_output([61u8; 32])];
    content
}

/// Both SPP trees are the entries tree, the record lives there.
fn velocity_fixture(approval_required: u8, transact: TransactIxData) -> Fixture {
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        body(0, 0, approval_required, transact),
    );
    fixture.set_account("policy_config", velocity_policy_config_account());
    fixture.substitute("input_tree", entries_tree());
    fixture.substitute("output_tree", entries_tree());
    fixture
}

#[test]
fn a_velocity_transfer_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    velocity_fixture(0, velocity_transact())
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
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
    fixture.insert(6, window_slot(Pubkey::new_from_array([0; 32]), None));
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
