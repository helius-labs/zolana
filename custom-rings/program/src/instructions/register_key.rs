use custom_ring_interface::{
    KeyRegistryRoot, RegisterKeyIxData, RegisterKeyPublicInput, HEAD_MAP_CAPACITY,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::Member;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_append_root_mut, load_config},
        verifier::verify_groth16,
    },
    state::{Advance, RootTransition},
};

#[inline(never)]
pub fn process_register_key_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: RegisterKeyIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let member_signer = iter.next_signer("member")?;
    let config_account = iter.next_account("config")?;
    let root_account = iter.next_mut("key_registry_root")?;

    let mut root = load_append_root_mut::<KeyRegistryRoot>(program_id, root_account)?;
    if root.root != ix.registry_old_root {
        return Err(CustomRingError::StaleKeyRegistryRoot.into());
    }
    if root.next_index() != ix.registry_next_index || ix.registry_next_index >= HEAD_MAP_CAPACITY {
        return Err(CustomRingError::InvalidKeyRegistryCursor.into());
    }
    let member = Member::owner_tag(member_signer.address().as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    let auditor_pubkey = load_config(program_id, config_account)?.auditor_pubkey;
    let public_input = RegisterKeyPublicInput {
        registry_old_root: &ix.registry_old_root,
        registry_new_root: &ix.registry_new_root,
        member: member.as_bytes(),
        nullifier_pk: &ix.nullifier_pk,
        auditor_pk: &auditor_pubkey,
        eph_pk: &ix.eph_pk,
        ciphertext: &ix.ciphertext,
        new_index: ix.registry_next_index,
    }
    .hash()
    .map_err(|_| CustomRingError::HashingFailed)?;
    verify_groth16(
        &ix.proof,
        public_input,
        &custom_ring_interface::register_key_verifying_key::VERIFYINGKEY,
    )?;
    RootTransition {
        expected_root: &ix.registry_old_root,
        new_root: ix.registry_new_root,
        advance: Advance::Register,
    }
    .apply(&mut *root)
}
