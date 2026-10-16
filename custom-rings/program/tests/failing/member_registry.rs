//! Pins member registry root init and the record write checks before the proof.

use custom_ring_interface::CustomRingError;
use custom_ring_interface::{
    MemberRegistryRoot, MemberUpdate, MEMBER_REGISTRY_EMPTY_ROOT, MEMBER_REGISTRY_ROOT,
    MEMBER_REGISTRY_ROOT_HISTORY,
};
use mollusk_svm::result::{InstructionResult, ProgramResult};
use solana_pubkey::Pubkey;
use zolana_ring_policy::ListId;

use crate::common::{
    authority, create_member_registry_root_fixture, custom, member_registry_root_account,
    member_registry_root_pda, owner_tag, payer, register_key_fixture, register_key_item,
    setup_mollusk, stored, update_members_fixture,
};

fn stored_root(result: &InstructionResult) -> MemberRegistryRoot {
    stored(result, member_registry_root_pda().0)
}

fn fresh_root() -> solana_account::Account {
    member_registry_root_account(MEMBER_REGISTRY_EMPTY_ROOT, 1)
}

#[test]
fn create_member_registry_root_writes_the_empty_root_at_the_canonical_bump() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_member_registry_root_fixture(None);
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = stored_root(&result);
    assert_eq!(written.discriminator, MEMBER_REGISTRY_ROOT);
    assert_eq!(written.root(), Some(MEMBER_REGISTRY_EMPTY_ROOT));
    assert_eq!(written.next_index(), 1);
    assert_eq!(written.bump, member_registry_root_pda().1);
    assert_eq!(written.history_cursor, 0);
    assert!((1..=MEMBER_REGISTRY_ROOT_HISTORY as u8).all(|index| written.root_at(index).is_none()));
}

#[test]
fn create_member_registry_root_by_a_non_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_member_registry_root_fixture(None);
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn create_member_registry_root_at_a_non_canonical_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_member_registry_root_fixture(None);
    fixture.substitute("member_registry_root", Pubkey::new_from_array([9; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidMemberRegistryRoot));
}

#[test]
fn authority_cannot_reinitialize_an_advanced_registry() {
    let (mollusk, _) = setup_mollusk();
    let advanced = member_registry_root_account([0x11; 32], 19);
    let fixture = create_member_registry_root_fixture(Some(advanced));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::MemberRegistryRootAlreadyExists),
    );
}

#[test]
fn create_member_registry_root_with_trailing_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_member_registry_root_fixture(None);
    fixture.push_data(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn a_register_key_on_a_fresh_root_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let fixture = register_key_fixture(fresh_root(), payer(), register_key_item(&payer(), 1));
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_register_key_for_another_member_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = register_key_fixture(fresh_root(), payer(), register_key_item(&authority(), 1));
    fixture.expect_err(&mollusk, custom(CustomRingError::MemberRecordMismatch));
}

#[test]
fn a_register_key_that_changes_lists_or_overwrites_a_key_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let root = member_registry_root_account(MEMBER_REGISTRY_EMPTY_ROOT, 3);
    let rewrite = MemberUpdate {
        old_lists: 1,
        lists: 1,
        index: 1,
        ..register_key_item(&payer(), 1)
    };
    register_key_fixture(root.clone(), payer(), rewrite)
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    let changed_lists = MemberUpdate {
        lists: 3,
        ..rewrite
    };
    register_key_fixture(root.clone(), payer(), changed_lists)
        .expect_err(&mollusk, custom(CustomRingError::MemberRecordMismatch));
    let registered = MemberUpdate {
        old_escrow_key: [9; 32],
        ..rewrite
    };
    register_key_fixture(root, payer(), registered)
        .expect_err(&mollusk, custom(CustomRingError::MemberRecordMismatch));
}

#[test]
fn a_register_key_insert_past_the_append_slot_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = register_key_fixture(fresh_root(), payer(), register_key_item(&payer(), 2));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidMemberRegistryCursor),
    );
}

#[test]
fn a_register_key_against_an_older_history_slot_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut advanced = member_registry_root_account(MEMBER_REGISTRY_EMPTY_ROOT, 1);
    let mut state: MemberRegistryRoot = *bytemuck::from_bytes(&advanced.data);
    state.history[1] = [0x55; 32];
    state.history_cursor = 1;
    advanced.data = bytemuck::bytes_of(&state).to_vec();
    let fixture = register_key_fixture(advanced, payer(), register_key_item(&payer(), 1));
    fixture.expect_err(&mollusk, custom(CustomRingError::StaleMemberRegistryRoot));
}

fn allow(member: &Pubkey, index: u64) -> MemberUpdate {
    MemberUpdate {
        member: owner_tag(member),
        lists: ListId::Allow.record_bit(),
        index,
        ..MemberUpdate::default()
    }
}

fn ascending(mut items: Vec<MemberUpdate>) -> Vec<MemberUpdate> {
    items.sort_by_key(|item| item.member);
    for (offset, item) in items.iter_mut().enumerate() {
        item.index = 1 + offset as u64;
    }
    items
}

#[test]
fn an_authority_batch_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let items = ascending(vec![allow(&payer(), 0), allow(&authority(), 0)]);
    let fixture = update_members_fixture(fresh_root(), items, &[authority()]);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_batch_without_the_authority_signature_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = update_members_fixture(fresh_root(), vec![allow(&payer(), 1)], &[payer()]);
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedListWrite));
}

#[test]
fn a_member_list_needs_the_member_and_a_key_change_too() {
    let (mollusk, _) = setup_mollusk();
    let recovery = MemberUpdate {
        lists: ListId::Recovery.record_bit(),
        ..allow(&payer(), 1)
    };
    update_members_fixture(fresh_root(), vec![recovery], &[authority()])
        .expect_err(&mollusk, custom(CustomRingError::UnauthorizedListWrite));
    update_members_fixture(fresh_root(), vec![recovery], &[payer()])
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    let key = MemberUpdate {
        lists: 0,
        escrow_key: [7; 32],
        ..allow(&payer(), 1)
    };
    update_members_fixture(fresh_root(), vec![key], &[authority()])
        .expect_err(&mollusk, custom(CustomRingError::UnauthorizedListWrite));
}

#[test]
fn a_batch_out_of_member_order_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut items = ascending(vec![allow(&payer(), 0), allow(&authority(), 0)]);
    items.swap(0, 1);
    let fixture = update_members_fixture(fresh_root(), items, &[authority()]);
    fixture.expect_err(&mollusk, custom(CustomRingError::MemberBatchOrder));
}

#[test]
fn an_empty_or_oversized_batch_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    update_members_fixture(fresh_root(), Vec::new(), &[authority()])
        .expect_err(&mollusk, custom(CustomRingError::MemberBatchTooLarge));
    let items: Vec<MemberUpdate> = (0..17u8)
        .map(|byte| allow(&Pubkey::new_from_array([byte + 1; 32]), 0))
        .collect();
    update_members_fixture(fresh_root(), ascending(items), &[authority()])
        .expect_err(&mollusk, custom(CustomRingError::MemberBatchTooLarge));
}

#[test]
fn an_unknown_list_bit_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let item = MemberUpdate {
        lists: 1 << 8,
        ..allow(&payer(), 1)
    };
    update_members_fixture(fresh_root(), vec![item], &[authority()])
        .expect_err(&mollusk, custom(CustomRingError::InvalidListId));
}

#[test]
fn inserts_take_the_next_free_slots_in_order() {
    let (mollusk, _) = setup_mollusk();
    let mut items = ascending(vec![allow(&payer(), 0), allow(&authority(), 0)]);
    items[1].index = 3;
    update_members_fixture(fresh_root(), items, &[authority()]).expect_err(
        &mollusk,
        custom(CustomRingError::InvalidMemberRegistryCursor),
    );
    let occupied = MemberUpdate {
        old_lists: 2,
        ..allow(&payer(), 1)
    };
    update_members_fixture(fresh_root(), vec![occupied], &[authority()])
        .expect_err(&mollusk, custom(CustomRingError::MemberRecordMismatch));
}
