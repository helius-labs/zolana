use custom_ring_interface::{CustomRingError, UpdateEntryIxData};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_ring_policy::{EntryState, ListEntry, ListId, Member};

use crate::instructions::{
    policy_shared::{MutationAccounts, MutationKind, NamespaceWrite, Spend},
    shared::parse,
};

/// Spends the live version and recreates the entry at its address one version up.
#[inline(never)]
pub fn process_update_entry_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: UpdateEntryIxData = parse(data)?;
    let list_id = ListId::try_from(ix.list_id).map_err(|_| CustomRingError::InvalidListId)?;
    let spent_state =
        EntryState::try_from(ix.spent_state).map_err(|_| CustomRingError::InvalidEntryState)?;
    let state = EntryState::try_from(ix.state).map_err(|_| CustomRingError::InvalidEntryState)?;
    let member = Member::from_bytes(ix.member).map_err(|_| CustomRingError::InvalidPolicyMember)?;
    // The spent content only rebuilds the spent leaf, a wrong one fails the proof.
    if !list_id.admits_content(ix.content_hash) {
        return Err(CustomRingError::InvalidEntryContent.into());
    }

    let parsed = MutationAccounts::validate_and_parse(program_id, accounts, MutationKind::Replace)?;
    parsed.check_writer(list_id, &member)?;
    let spent = ListEntry {
        list_id,
        member,
        state: spent_state,
        version: ix.spent_version,
        content_hash: ix.spent_content_hash,
        blinding: ix.spent_blinding,
    };
    let (leaf, nullifier) = parsed.trees.spent_entry(&parsed.owner, &spent)?;
    let entry = ListEntry {
        state,
        version: ix
            .spent_version
            .checked_add(1)
            .ok_or(CustomRingError::EntryVersionOverflow)?,
        content_hash: ix.content_hash,
        blinding: ix.blinding,
        ..spent
    };
    NamespaceWrite {
        output_hash: parsed.trees.written_entry(&parsed.owner, &entry)?,
        content: &entry.to_output_data(),
        spend: Spend::Replace { leaf, nullifier },
        private_tx_blinding: ix.private_tx_blinding,
        nullifier_tree_root_index: ix.nullifier_tree_root_index,
        utxo_tree_root_index: ix.utxo_tree_root_index,
        proof: ix.proof,
    }
    .send(program_id, &parsed, accounts)
}
