//! Pins stateless transfer limits and their approval requirements.

use custom_ring_interface::{tag, CoSignScope};
use custom_ring_program::CustomRingError;
use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, TransactIxData},
        InterfaceTransfer,
    },
    N_PUBLIC_SLOTS,
};

use crate::common::{
    account, auditor_pubkey, authority, cosigner_account, custom, initialized_config_account,
    payer, policy_delegate_transact_fixture, register_spend_fixture, setup_mollusk,
    spend_record_output, transact_fixture, transfer_cap_policy_config_account, window_slot,
    Fixture, Slot,
};
use crate::transact::{body, transact_data};

/// Stateless caps do not confine transaction trees.
fn transfer_cap_fixture(approval_required: u8, transact: TransactIxData) -> Fixture {
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        body(0, 0, approval_required, transact),
    );
    fixture.set_account("policy_config", transfer_cap_policy_config_account());
    fixture
}

#[test]
fn a_cap_ring_reaches_the_proof_without_a_record() {
    let (mollusk, _) = setup_mollusk();
    transfer_cap_fixture(0, transact_data())
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_plaintext_record_output_is_a_money_output_without_a_window() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact_data();
    content.outputs.push(spend_record_output([61u8; 32]));
    transfer_cap_fixture(0, content)
        .expect_err(&mollusk, custom(CustomRingError::UnsupportedOutputScheme));
}

#[test]
fn a_deposit_leg_is_rejected_exactly_without_a_window() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact_data();
    content.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 5 }];
    let mut fixture = transfer_cap_fixture(0, content);
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
fn the_delegate_rail_is_exempt_from_per_transfer_caps() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact_data();
    content.circuit = CircuitId::RingAuthority(2, 2, N_PUBLIC_SLOTS as u8);
    let mut data = body(0, 0, 0, content);
    data[0] = tag::DELEGATE_TRANSACT;
    let mut fixture = policy_delegate_transact_fixture(data);
    fixture.set_account("policy_config", transfer_cap_policy_config_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn an_approval_needs_the_configured_cosigner_without_a_window() {
    let (mollusk, _) = setup_mollusk();
    transfer_cap_fixture(1, transact_data())
        .expect_err(&mollusk, custom(CustomRingError::ApprovalWithoutCoSigner));

    let mut signed = transfer_cap_fixture(1, transact_data());
    signed.set_account("cosigner_pda", cosigner_account(CoSignScope::DEPOSITS, &[]));
    signed.sign("cosigner");
    signed.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn per_transfer_caps_cannot_register_spend_records() {
    let (mollusk, _) = setup_mollusk();
    register_spend_fixture(transfer_cap_policy_config_account(), payer())
        .expect_err(&mollusk, custom(CustomRingError::VelocityDisabled));
}
