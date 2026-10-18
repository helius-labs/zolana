use custom_ring_interface::{
    update_members_verifying_key, CustomRingError, MemberRegistryRoot, MemberUpdate,
    RingProgramConfig, UpdateMembersIxData, UpdateMembersPublicInput, MAX_MEMBER_BATCH,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::is_canonical_bn254_scalar_be;
use zolana_ring_policy::{ListId, Member, Writer};

use crate::{
    instructions::{
        loader::{load, load_mut},
        shared::parse,
        verifier::verify_groth16,
    },
    state::RootTransition,
};

/// `[config, member_registry_root, signers..]`, every item authorized by the authority or its member.
#[inline(never)]
pub fn process_update_members_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: UpdateMembersIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let config = iter.next_account("config")?;
    let root_account = iter.next_mut("member_registry_root")?;
    let signers = iter.remaining_unchecked()?;

    if !(1..=MAX_MEMBER_BATCH).contains(&ix.items.len()) {
        return Err(CustomRingError::MemberBatchTooLarge.into());
    }
    let authority = load::<RingProgramConfig>(program_id, config)?.authority;
    let signers = Signers::collect(
        signers
            .iter()
            .filter(|account| account.is_signer())
            .map(|account| account.address()),
        &authority,
    )?;
    let mut root = load_mut::<MemberRegistryRoot>(program_id, root_account)?;
    let next_index = root.next_index();
    let mut inserts = 0u64;
    let mut previous: Option<[u8; 32]> = None;
    for item in &ix.items {
        if previous.is_some_and(|previous| previous >= item.member) {
            return Err(CustomRingError::MemberBatchOrder.into());
        }
        previous = Some(item.member);
        if item.member == [0; 32] || !is_canonical_bn254_scalar_be(&item.member) {
            return Err(CustomRingError::InvalidPolicyMember.into());
        }
        // Only RegisterKey proves that the auditor can recover this commitment's
        // nullifier secret. List updates must preserve that verified binding.
        if item.escrow_key != item.old_escrow_key {
            return Err(CustomRingError::MemberRecordMismatch.into());
        }
        signers.authorize(item)?;
        if item.inserts(next_index) {
            if item.index != next_index + inserts {
                return Err(CustomRingError::InvalidMemberRegistryCursor.into());
            }
            if item.old_lists != 0 || item.old_escrow_key != [0; 32] {
                return Err(CustomRingError::MemberRecordMismatch.into());
            }
            inserts += 1;
        }
    }
    let transition = RootTransition {
        old_root_index: ix.old_root_index,
        new_root: ix.new_root,
        inserts,
    }
    .check(&root)?;
    let public_input = UpdateMembersPublicInput {
        old_root: transition.old_root(),
        new_root: &ix.new_root,
        items: &ix.items,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    verify_groth16(
        &ix.proof,
        public_input,
        &update_members_verifying_key::VERIFYINGKEY,
    )?;
    // The registry moves only after the proof verifies.
    transition.apply(&mut root);
    Ok(())
}

/// The signing accounts of the batch, as the authority and as members.
struct Signers {
    authority: bool,
    members: Vec<Member>,
}

impl Signers {
    fn collect<'a>(
        accounts: impl Iterator<Item = &'a Address>,
        authority: &Address,
    ) -> Result<Self, CustomRingError> {
        let mut signers = Self {
            authority: false,
            members: Vec::new(),
        };
        for address in accounts {
            signers.authority |= address == authority;
            signers.members.push(
                Member::owner_tag(address.as_array())
                    .map_err(|_| CustomRingError::HashingFailed)?,
            );
        }
        Ok(signers)
    }

    /// A changed authority list needs the authority, a changed member list the member.
    fn authorize(&self, item: &MemberUpdate) -> Result<(), CustomRingError> {
        let mut needs_authority = false;
        let mut needs_member = false;
        let mut changed = item.old_lists ^ item.lists;
        let member_signed = self
            .members
            .iter()
            .any(|member| member.as_bytes() == &item.member);
        // Even an unchanged record consumes a root-history slot. An empty
        // insertion also consumes registry capacity, so neither is permissionless.
        if changed == 0 && !self.authority && !member_signed {
            return Err(CustomRingError::UnauthorizedListWrite);
        }
        while changed != 0 {
            let bit = changed.trailing_zeros();
            changed &= changed - 1;
            let list_id = ListId::of_record_bit(bit).ok_or(CustomRingError::InvalidListId)?;
            match list_id.writer() {
                Writer::Authority => needs_authority = true,
                Writer::Member => needs_member = true,
            }
        }
        if needs_authority && !self.authority {
            return Err(CustomRingError::UnauthorizedListWrite);
        }
        if needs_member && !member_signed {
            return Err(CustomRingError::UnauthorizedListWrite);
        }
        Ok(())
    }
}
