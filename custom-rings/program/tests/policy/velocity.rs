//! Pins compressed velocity validation before proof verification or SPP execution.

use custom_ring_interface::CustomRingError;
use custom_ring_interface::{tag, CoSignScope};
use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, InputUtxo, OwnerTag, TransactIxData},
        InterfaceTransfer,
    },
    N_PUBLIC_SLOTS,
};

use crate::common::{
    account, address_tree, auditor_pubkey, authority, cosigner_account, custom, encode_transact,
    initialized_config_account, initialized_other_tree_account, initialized_policy_config_account,
    namespace_pda, other_tree, payer, policy_delegate_transact_fixture, register_spend_data,
    register_spend_fixture, setup_mollusk, spend_record_output, spend_record_output_in,
    transact_fixture, velocity_policy_config_account, window_slot, Fixture, Slot, ADDRESS_TREE_ID,
    OTHER_TREE_ID, VELOCITY_WINDOW_SLOTS,
};
use crate::transact::{body, confidential_output, ix_data, transact_data};

const RECORD_MEMBER_TAG: [u8; 32] = [61u8; 32];
const SPENT_RECORD_NULLIFIER: [u8; 32] = [0x5eu8; 32];

/// Synthetic openings exercise program validation without a valid policy proof.
fn velocity_transact() -> TransactIxData {
    let mut content = transact_data();
    content.circuit = CircuitId::RingEddsa(2, 2, N_PUBLIC_SLOTS as u8);
    content.inputs = vec![InputUtxo {
        nullifier_hash: SPENT_RECORD_NULLIFIER,
        tree_index: 0,
    }];
    let mut counters = vec![0u8; zolana_ring_policy::SPEND_COUNTERS_BODY_LEN];
    counters[..content.tx_viewing_pk.len()].copy_from_slice(&content.tx_viewing_pk);
    content.messages.insert(
        0,
        zolana_interface::instruction::MessageData {
            view_tag: namespace_pda().0.to_bytes(),
            data: counters,
        },
    );
    let mut record = spend_record_output(RECORD_MEMBER_TAG);
    content.messages.insert(
        0,
        zolana_interface::instruction::MessageData {
            view_tag: zolana_ring_policy::spend_record_message_tag(namespace_pda().0.as_array())
                .unwrap(),
            data: record.data.take().unwrap(),
        },
    );
    record.data = confidential_output().data;
    record.data.as_mut().unwrap()[5] = zolana_interface::event::CONFIDENTIAL_ENCRYPTED_SCHEME_TAG;
    content.outputs = vec![confidential_output(), record];
    content
}

fn velocity_fixture(approval_required: bool, transact: TransactIxData) -> Fixture {
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        body(0, 0, approval_required, transact),
    );
    fixture.set_account("policy_config", velocity_policy_config_account());
    fixture.substitute("input_tree", address_tree());
    fixture.substitute("output_tree", address_tree());
    fixture
}

#[test]
fn a_velocity_transfer_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    velocity_fixture(false, velocity_transact())
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// The successor record lands in the money tree and hashes under its id.
#[test]
fn a_money_tree_apart_from_the_address_tree_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let in_other_tree = |output_tree_id| {
        let mut content = velocity_transact();
        let record = spend_record_output_in(RECORD_MEMBER_TAG, output_tree_id);
        content.outputs[1].utxo_hash = record.utxo_hash;
        let mut fixture = velocity_fixture(false, content);
        fixture.substitute("output_tree", other_tree());
        fixture.substitute("input_tree", other_tree());
        fixture.set_account("output_tree", initialized_other_tree_account());
        fixture
    };
    in_other_tree(OTHER_TREE_ID)
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    in_other_tree(ADDRESS_TREE_ID)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

#[test]
fn a_record_output_tree_that_is_not_a_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = velocity_fixture(false, velocity_transact());
    fixture.substitute("output_tree", Pubkey::new_from_array([42; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

/// The published record must be the preimage of the last output's leaf.
#[test]
fn a_record_that_does_not_open_its_leaf_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut forged = velocity_transact();
    forged.outputs[1].utxo_hash[0] ^= 1;
    velocity_fixture(false, forged)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));

    let mut foreign_owner = velocity_transact();
    foreign_owner.outputs[1].owner_tag = OwnerTag::Inline([9u8; 32]);
    velocity_fixture(false, foreign_owner)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));

    let mut truncated = velocity_transact();
    truncated.messages[0].data.pop();
    velocity_fixture(false, truncated)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));

    let mut record_first = velocity_transact();
    record_first.outputs.swap(0, 1);
    velocity_fixture(false, record_first)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

#[test]
fn missing_duplicate_or_wrongly_tagged_record_messages_are_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut missing = velocity_transact();
    missing.messages.remove(0);
    velocity_fixture(false, missing)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
    let mut duplicate = velocity_transact();
    duplicate.messages.insert(0, duplicate.messages[0].clone());
    velocity_fixture(false, duplicate)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
    let mut wrong_tag = velocity_transact();
    wrong_tag.messages[0].view_tag = [0x99; 32];
    velocity_fixture(false, wrong_tag)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

#[test]
fn a_record_carrier_cannot_hide_its_default_ring_owner() {
    let (mollusk, _) = setup_mollusk();
    let mut masked = velocity_transact();
    masked.outputs[1].data = confidential_output().data;
    velocity_fixture(false, masked)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

#[test]
fn a_transfer_without_a_record_output_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut content = velocity_transact();
    content.outputs.truncate(1);
    velocity_fixture(false, content)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

#[test]
fn a_deposit_leg_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut content = velocity_transact();
    content.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 5 }];
    let mut fixture = velocity_fixture(false, content);
    fixture.insert_windows(vec![window_slot(Pubkey::new_from_array([0; 32]), None)]);
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
fn the_delegate_rail_is_velocity_exempt_and_reaches_its_own_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact_data();
    content.circuit = CircuitId::RingAuthority(2, 2, N_PUBLIC_SLOTS as u8);
    let mut data = body(0, 0, false, content);
    data[0] = tag::DELEGATE_TRANSACT;
    let mut fixture = policy_delegate_transact_fixture(data);
    fixture.set_account("policy_config", velocity_policy_config_account());
    fixture.substitute("output_tree", address_tree());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn the_delegate_rail_takes_no_window_index() {
    let (mollusk, _) = setup_mollusk();
    let mut content = transact_data();
    content.circuit = CircuitId::RingAuthority(2, 2, N_PUBLIC_SLOTS as u8);
    let mut ix = ix_data(0, 0, false, content);
    ix.window_index = 1;
    let mut fixture =
        policy_delegate_transact_fixture(encode_transact(tag::DELEGATE_TRANSACT, &ix));
    fixture.set_account("policy_config", velocity_policy_config_account());
    fixture.substitute("output_tree", address_tree());
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidWindowIndex));
}

/// Approval overrides the configured operation scope.
#[test]
fn an_approval_needs_the_configured_cosigner() {
    let (mollusk, _) = setup_mollusk();
    velocity_fixture(true, velocity_transact())
        .expect_err(&mollusk, custom(CustomRingError::ApprovalWithoutCoSigner));

    let mut unsigned = velocity_fixture(true, velocity_transact());
    unsigned.set_account("cosigner_pda", cosigner_account(CoSignScope::DEPOSITS, &[]));
    unsigned.expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));

    let mut signed = velocity_fixture(true, velocity_transact());
    signed.set_account("cosigner_pda", cosigner_account(CoSignScope::DEPOSITS, &[]));
    signed.sign("cosigner");
    signed.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));

    let mut impostor = velocity_fixture(true, velocity_transact());
    impostor.set_account("cosigner_pda", cosigner_account(CoSignScope::DEPOSITS, &[]));
    impostor.substitute("cosigner", Pubkey::new_from_array([39; 32]));
    impostor.sign("cosigner");
    impostor.expect_err(&mollusk, custom(CustomRingError::UnauthorizedCoSigner));
}

#[test]
fn an_approval_outside_velocity_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        body(0, 0, true, transact_data()),
    )
    .expect_err(&mollusk, custom(CustomRingError::UnexpectedApproval));
}

#[test]
fn an_approval_byte_above_one_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let off = body(0, 0, false, velocity_transact());
    let on = body(0, 0, true, velocity_transact());
    let at = off.iter().zip(&on).position(|(a, b)| a != b).unwrap();
    let mut fixture = velocity_fixture(false, velocity_transact());
    fixture.data_mut()[at] = 2;
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

/// The window index is checked against the clock before any proof work.
#[test]
fn a_velocity_transfer_proves_the_current_window() {
    let (mut mollusk, _) = setup_mollusk();
    mollusk.warp_to_slot(VELOCITY_WINDOW_SLOTS);
    let at_window = |window_index| {
        let mut ix = ix_data(0, 0, false, velocity_transact());
        ix.window_index = window_index;
        let mut fixture = velocity_fixture(false, velocity_transact());
        *fixture.data_mut() = encode_transact(tag::TRANSACT, &ix);
        fixture
    };
    at_window(0).expect_err(&mollusk, custom(CustomRingError::WindowElapsed));
    at_window(2).expect_err(&mollusk, custom(CustomRingError::InvalidWindowIndex));
    at_window(1).expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn register_spend_proves_the_current_window() {
    let (mut mollusk, _) = setup_mollusk();
    mollusk.warp_to_slot(VELOCITY_WINDOW_SLOTS);
    let at_window = |window_index| {
        let mut fixture = register_spend_fixture(velocity_policy_config_account(), payer());
        *fixture.data_mut() = register_spend_data(window_index);
        fixture
    };
    at_window(0).expect_err(&mollusk, custom(CustomRingError::WindowElapsed));
    at_window(2).expect_err(&mollusk, custom(CustomRingError::InvalidWindowIndex));
    at_window(1).expect_spp_cpi(&mollusk);
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
