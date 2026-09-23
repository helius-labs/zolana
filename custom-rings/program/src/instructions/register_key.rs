use custom_ring_interface::{RegisterKeyIxData, RegisterKeyPublicInput};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::Member;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_config, load_key_registry_root_mut},
        verifier::verify_groth16,
    },
    state::RootTransition,
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

    // 1. Bind enrollment to the member signer, the current root and the append position.
    let mut root = load_key_registry_root_mut(program_id, root_account)?;
    let transition = RootTransition {
        expected_root: &ix.registry_old_root,
        expected_next_index: ix.registry_next_index,
        new_root: ix.registry_new_root,
    }
    .check(&root)?;
    let member = Member::owner_tag(member_signer.address().as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    let auditor_pubkey = load_config(program_id, config_account)?.auditor_pubkey;
    // 2. Prove key encryption to the pinned auditor and insertion under the
    // signed member identity.
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
    // 3. Commit the registry transition only after proof verification.
    transition.apply(&mut root);
    Ok(())
}
