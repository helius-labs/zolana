//! Pins compressed velocity validation before proof verification or SPP execution.

use custom_ring_interface::{
    tag, CoSignScope, CustomRingTransactIxData, HeadMapTransition, HEAD_MAP_CAPACITY,
    HEAD_MAP_EMPTY_ROOT,
};
use custom_ring_program::CustomRingError;
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
    account, address_tree, auditor_pubkey, authority, cosigner_account, custom,
    head_map_root_account, head_map_root_slot, initialized_config_account,
    initialized_other_tree_account, initialized_policy_config_account, namespace_pda, other_tree,
    payer, policy_delegate_transact_fixture, register_spend_fixture, setup_mollusk,
    spend_record_output, spend_record_output_in, transact_fixture,
    uninitialized_head_map_root_account, velocity_policy_config_account, window_slot, Fixture,
    Slot, ADDRESS_TREE_ID, OTHER_TREE_ID,
};
use crate::transact::{body, confidential_output, transact_data};

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

fn velocity_fixture(approval_required: u8, transact: TransactIxData) -> Fixture {
    velocity_fixture_with_root(approval_required, transact, || {
        head_map_root_account(HEAD_MAP_EMPTY_ROOT, 1)
    })
}

fn velocity_fixture_with_root(
    approval_required: u8,
    transact: TransactIxData,
    root_account: impl FnOnce() -> solana_account::Account,
) -> Fixture {
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        body(0, 0, approval_required, transact),
    );
    fixture.set_account("policy_config", velocity_policy_config_account());
    fixture.substitute("input_tree", address_tree());
    fixture.substitute("output_tree", address_tree());
    let mut decoded: CustomRingTransactIxData =
        wincode::deserialize_exact(&fixture.data_mut()[1..]).expect("body");
    decoded.head_transition = Some(HeadMapTransition {
        old_root: HEAD_MAP_EMPTY_ROOT,
        new_root: [1; 32],
    });
    *fixture.data_mut() = [
        &[tag::TRANSACT][..],
        &wincode::serialize(&decoded).expect("body"),
    ]
    .concat();
    fixture.insert(6, head_map_root_slot(root_account()));
    fixture
}

#[test]
fn a_velocity_transfer_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    velocity_fixture(0, velocity_transact())
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn an_uninitialized_map_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    velocity_fixture_with_root(0, velocity_transact(), uninitialized_head_map_root_account)
        .expect_err(&mollusk, custom(CustomRingError::InvalidHeadMapRoot));
}

#[test]
fn a_stale_head_map_is_rejected_before_the_proof() {
    let (mollusk, _) = setup_mollusk();
    velocity_fixture_with_root(0, velocity_transact(), || {
        head_map_root_account([0x11u8; 32], 1)
    })
    .expect_err(&mollusk, custom(CustomRingError::StaleHeadMapRoot));
}

/// The successor record lands in the money tree and hashes under its id.
#[test]
fn a_money_tree_apart_from_the_address_tree_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let in_other_tree = |output_tree_id| {
        let mut content = velocity_transact();
        let record = spend_record_output_in(RECORD_MEMBER_TAG, output_tree_id);
        content.outputs[1].utxo_hash = record.utxo_hash;
        let mut fixture = velocity_fixture(0, content);
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
    let mut fixture = velocity_fixture(0, velocity_transact());
    fixture.substitute("output_tree", Pubkey::new_from_array([42; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
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
    truncated.messages[0].data.pop();
    velocity_fixture(0, truncated)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));

    let mut record_first = velocity_transact();
    record_first.outputs.swap(0, 1);
    velocity_fixture(0, record_first)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

#[test]
fn missing_duplicate_or_wrongly_tagged_record_messages_are_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut missing = velocity_transact();
    missing.messages.remove(0);
    velocity_fixture(0, missing).expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
    let mut duplicate = velocity_transact();
    duplicate.messages.insert(0, duplicate.messages[0].clone());
    velocity_fixture(0, duplicate)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
    let mut wrong_tag = velocity_transact();
    wrong_tag.messages[0].view_tag = [0x99; 32];
    velocity_fixture(0, wrong_tag)
        .expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

#[test]
fn a_record_carrier_cannot_hide_its_default_ring_owner() {
    let (mollusk, _) = setup_mollusk();
    let mut masked = velocity_transact();
    masked.outputs[1].data = confidential_output().data;
    velocity_fixture(0, masked).expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

#[test]
fn a_transfer_without_a_record_output_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut content = velocity_transact();
    content.outputs.truncate(1);
    velocity_fixture(0, content).expect_err(&mollusk, custom(CustomRingError::InvalidSpendRecord));
}

#[test]
fn a_deposit_leg_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut content = velocity_transact();
    content.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 5 }];
    let mut fixture = velocity_fixture(0, content);
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
    content.circuit = CircuitId::RingAuthority(1, 1, N_PUBLIC_SLOTS as u8);
    let mut data = body(0, 0, 0, content);
    data[0] = tag::DELEGATE_TRANSACT;
    let mut fixture = policy_delegate_transact_fixture(data);
    fixture.set_account("policy_config", velocity_policy_config_account());
    fixture.substitute("output_tree", address_tree());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// Approval overrides the configured operation scope.
#[test]
fn an_approval_needs_the_configured_cosigner() {
    let (mollusk, _) = setup_mollusk();
    velocity_fixture(1, velocity_transact())
        .expect_err(&mollusk, custom(CustomRingError::ApprovalWithoutCoSigner));

    let mut unsigned = velocity_fixture(1, velocity_transact());
    unsigned.set_account("cosigner_pda", cosigner_account(CoSignScope::DEPOSITS, &[]));
    unsigned.expect_err(&mollusk, custom(CustomRingError::MissingCoSigner));

    let mut signed = velocity_fixture(1, velocity_transact());
    signed.set_account("cosigner_pda", cosigner_account(CoSignScope::DEPOSITS, &[]));
    signed.sign("cosigner");
    signed.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));

    let mut impostor = velocity_fixture(1, velocity_transact());
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
fn register_spend_requires_the_head_insertion_proof() {
    let (mollusk, _) = setup_mollusk();
    register_spend_fixture(velocity_policy_config_account(), payer())
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn register_spend_refuses_a_stale_registration_root() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = register_spend_fixture(velocity_policy_config_account(), payer());
    fixture.set_account("head_map_root", head_map_root_account([0x11u8; 32], 2));
    fixture.expect_err(&mollusk, custom(CustomRingError::StaleHeadMapRoot));
}

#[test]
fn register_spend_requires_the_live_append_cursor() {
    let (mollusk, _) = setup_mollusk();
    for cursor in [0, 2, HEAD_MAP_CAPACITY] {
        let mut fixture = register_spend_fixture(velocity_policy_config_account(), payer());
        fixture.set_account(
            "head_map_root",
            head_map_root_account(HEAD_MAP_EMPTY_ROOT, cursor),
        );
        fixture.expect_err(&mollusk, custom(CustomRingError::InvalidHeadMapCursor));
    }
}

#[test]
fn a_windowed_transfer_cannot_drop_the_compressed_statement() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = velocity_fixture(0, velocity_transact());
    let mut decoded: CustomRingTransactIxData =
        wincode::deserialize_exact(&fixture.data_mut()[1..]).expect("body");
    decoded.head_transition = None;
    *fixture.data_mut() = [
        &[tag::TRANSACT][..],
        &wincode::serialize(&decoded).expect("body"),
    ]
    .concat();
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn a_member_cannot_attach_a_head_transition_to_an_ordinary_policy() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = velocity_fixture(0, velocity_transact());
    fixture.set_account("policy_config", initialized_policy_config_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn transfer_head_accounts_are_canonical_and_initialized() {
    let (mollusk, _) = setup_mollusk();
    let mut substituted = velocity_fixture(0, velocity_transact());
    substituted.substitute("head_map_root", Pubkey::new_from_array([29; 32]));
    substituted.set_account(
        "head_map_root",
        head_map_root_account(HEAD_MAP_EMPTY_ROOT, 1),
    );
    substituted.expect_err(&mollusk, custom(CustomRingError::InvalidHeadMapRoot));
    for truncated in [false, true] {
        let mut fixture = velocity_fixture(0, velocity_transact());
        let mut root = head_map_root_account(HEAD_MAP_EMPTY_ROOT, 1);
        if truncated {
            root.data.pop();
        } else {
            root.owner = Pubkey::new_from_array([29; 32]);
        }
        fixture.set_account("head_map_root", root);
        fixture.expect_err(&mollusk, custom(CustomRingError::InvalidHeadMapRoot));
    }
}
