use custom_ring_interface::{
    register_key_verifying_key, CustomRingError, EscrowKey, MemberRegistryRoot, RegisterKeyIxData,
    RegisterKeyPublicInput, RingProgramConfig,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::Member;

use crate::{
    instructions::{
        loader::{load, load_mut},
        shared::parse,
        verifier::verify_groth16,
    },
    state::RootTransition,
};

/// `[member, config, member_registry_root]`, the member signs for its own record.
#[inline(never)]
pub fn process_register_key_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: RegisterKeyIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let member_signer = iter.next_signer("member")?;
    let config = iter.next_account("config")?;
    let root_account = iter.next_mut("member_registry_root")?;

    let member = Member::owner_tag(member_signer.address().as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    let item = &ix.item;
    let escrow_key = EscrowKey {
        nullifier_pk: &ix.nullifier_pk,
        ciphertext: &ix.ciphertext,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    // A registered key is never overwritten and the lists stay as they are.
    if item.member != *member.as_bytes()
        || item.old_escrow_key != [0; 32]
        || item.lists != item.old_lists
        || item.escrow_key != escrow_key
    {
        return Err(CustomRingError::MemberRecordMismatch.into());
    }
    let mut root = load_mut::<MemberRegistryRoot>(program_id, root_account)?;
    let next_index = root.next_index();
    let inserts = if item.inserts(next_index) {
        if item.index != next_index {
            return Err(CustomRingError::InvalidMemberRegistryCursor.into());
        }
        if item.old_lists != 0 {
            return Err(CustomRingError::MemberRecordMismatch.into());
        }
        1
    } else {
        0
    };
    let transition = RootTransition {
        old_root_index: ix.old_root_index,
        new_root: ix.new_root,
        inserts,
    }
    .check(&root)?;
    let auditor_pubkey = load::<RingProgramConfig>(program_id, config)?.auditor_pubkey;
    let public_input = RegisterKeyPublicInput {
        registry_old_root: transition.old_root(),
        registry_new_root: &ix.new_root,
        member: member.as_bytes(),
        nullifier_pk: &ix.nullifier_pk,
        auditor_pk: &auditor_pubkey,
        eph_pk: &ix.eph_pk,
        ciphertext: &ix.ciphertext,
        index: item.index,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    verify_groth16(
        &ix.proof,
        public_input,
        &register_key_verifying_key::VERIFYINGKEY,
    )?;
    // The registry moves only after the proof verifies.
    transition.apply(&mut root);
    Ok(())
}
