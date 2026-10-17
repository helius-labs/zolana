use custom_ring_interface::{
    register_key_verifying_key, CustomRingError, KeyRegistryRoot, RegisterKeyIxData,
    RegisterKeyPublicInput, RingMode, VIEWING_PUBKEY_TAG,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::Member;

use crate::{
    instructions::{
        loader::{load_audited_config, load_mut},
        shared::parse,
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
    let ix: RegisterKeyIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let member_signer = iter.next_signer("member")?;
    let config = iter.next_account("config")?;
    let root_account = iter.next_mut("key_registry_root")?;

    let mut root = load_mut::<KeyRegistryRoot>(program_id, root_account)?;
    let transition = RootTransition {
        expected_root: &ix.registry_old_root,
        expected_next_index: ix.registry_next_index,
        new_root: ix.registry_new_root,
    }
    .check(&root)?;
    let member = Member::owner_tag(member_signer.address().as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    let config = load_audited_config(program_id, config)?;
    // An anonymous ring escrows no key, its auditor already sees every opening.
    if config.mode == RingMode::Anonymous {
        return Err(CustomRingError::AnonymousRingRefused.into());
    }
    if ix.eph_pk[0] != VIEWING_PUBKEY_TAG {
        return Err(CustomRingError::InvalidAuditorMessage.into());
    }
    let public_input = RegisterKeyPublicInput {
        registry_old_root: &ix.registry_old_root,
        registry_new_root: &ix.registry_new_root,
        member: member.as_bytes(),
        nullifier_pk: &ix.nullifier_pk,
        auditor_pk: &config.auditor_pubkey,
        eph_pk: &ix.eph_pk,
        ciphertext: &ix.ciphertext,
        new_index: ix.registry_next_index,
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
