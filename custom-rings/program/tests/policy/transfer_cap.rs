//! Pins the outflow limit statement and its approval requirement.

use custom_ring_interface::CustomRingError;
use custom_ring_interface::{tag, CoSignScope};
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
    limit_policy_config_account, policy_delegate_transact_fixture, setup_mollusk, transact_fixture,
    Fixture, Slot,
};
use crate::transact::{body, transact_data};

/// Outflow limits do not confine transaction trees.
fn limit_fixture(approval_required: bool, transact: TransactIxData) -> Fixture {
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(4)),
        body(0, 0, approval_required, transact),
    );
    fixture.set_account("policy_config", limit_policy_config_account());
    fixture
}

#[test]
fn a_limited_ring_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    limit_fixture(false, transact_data())
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// The circuit bounds the outflow, the program takes no view of the public legs.
#[test]
fn a_deposit_leg_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact_data();
    content.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 5 }];
    let mut fixture = limit_fixture(false, content);
    for byte in [53u8, 54] {
        fixture.push(Slot {
            label: "settlement",
            meta: AccountMeta::new(Pubkey::new_from_array([byte; 32]), byte == 54),
            account: account(1_000_000_000),
        });
    }
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn the_delegate_rail_is_exempt_from_outflow_limits() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact_data();
    content.circuit = CircuitId::RingAuthority(2, 2, N_PUBLIC_SLOTS as u8);
    let mut data = body(0, 0, false, content);
    data[0] = tag::DELEGATE_TRANSACT;
    let mut fixture = policy_delegate_transact_fixture(data);
    fixture.set_account("policy_config", limit_policy_config_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn an_approval_needs_the_configured_cosigner() {
    let (mollusk, _) = setup_mollusk();
    limit_fixture(true, transact_data())
        .expect_err(&mollusk, custom(CustomRingError::ApprovalWithoutCoSigner));

    let mut signed = limit_fixture(true, transact_data());
    signed.set_account("cosigner_pda", cosigner_account(CoSignScope::DEPOSITS, &[]));
    signed.sign("cosigner");
    signed.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}
