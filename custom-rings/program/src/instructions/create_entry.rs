use custom_ring_interface::{CreateEntryIxData, CustomRingError};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_ring_policy::{EntryState, ListEntry, ListId, Member};

use crate::instructions::{
    policy_shared::{MutationAccounts, MutationKind, NamespaceWrite, Spend},
    shared::parse,
};

/// The input slot nullifies the derived address, a second create of the same
/// `(list_id, member)` fails in SPP.
#[inline(never)]
pub fn process_create_entry_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: CreateEntryIxData = parse(data)?;
    let list_id = ListId::try_from(ix.list_id).map_err(|_| CustomRingError::InvalidListId)?;
    let state = EntryState::try_from(ix.state).map_err(|_| CustomRingError::InvalidEntryState)?;
    let member = Member::from_bytes(ix.member).map_err(|_| CustomRingError::InvalidPolicyMember)?;
    if !list_id.admits_content(ix.content_hash) {
        return Err(CustomRingError::InvalidEntryContent.into());
    }

    let parsed = MutationAccounts::validate_and_parse(program_id, accounts, MutationKind::Claim)?;
    parsed.check_writer(list_id, &member)?;
    let entry = ListEntry {
        list_id,
        member,
        state,
        version: 0,
        content_hash: ix.content_hash,
        blinding: ix.blinding,
    };
    NamespaceWrite {
        output_hash: parsed.trees.written_entry(&parsed.owner, &entry)?,
        content: &entry.to_output_data(),
        spend: Spend::Claim(parsed.trees.entry_address(&parsed.owner, &entry)?),
        private_tx_blinding: ix.private_tx_blinding,
        nullifier_tree_root_index: ix.nullifier_tree_root_index,
        utxo_tree_root_index: ix.utxo_tree_root_index,
        proof: ix.proof,
    }
    .send(program_id, &parsed, accounts)
}
