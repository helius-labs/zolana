use custom_ring_interface::UpdateEntryIxData;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::instruction_data::transact::InputUtxo;
use zolana_ring_policy::{EntryState, ListEntry, ListId, Member};

use crate::{
    error::CustomRingError,
    instructions::policy_shared::{
        cpi_spp_namespace_signed, entry_spend_input, EntryTransition, MutationAccounts,
    },
};

/// Spends the live version and recreates the entry at the same address with
/// the version raised by one, in one SPP transact.
#[inline(never)]
pub fn process_update_entry_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: UpdateEntryIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let list_id = ListId::try_from(ix.list_id).map_err(|_| CustomRingError::InvalidListId)?;
    let spent_state =
        EntryState::try_from(ix.spent_state).map_err(|_| CustomRingError::InvalidEntryState)?;
    let state = EntryState::try_from(ix.state).map_err(|_| CustomRingError::InvalidEntryState)?;
    let member = Member::from_bytes(ix.member).map_err(|_| CustomRingError::InvalidPolicyMember)?;

    let parsed = MutationAccounts::validate_and_parse(program_id, accounts, list_id)?;
    parsed.check_mutator(list_id, &member)?;

    let spent = ListEntry {
        list_id,
        member,
        state: spent_state,
        version: ix.spent_version,
        content_hash: ix.spent_content_hash,
    };
    let (spent_hash, nullifier) = entry_spend_input(&parsed.owner, &spent)?;
    let version = ix
        .spent_version
        .checked_add(1)
        .ok_or(CustomRingError::EntryVersionOverflow)?;
    let transact = EntryTransition {
        entry: ListEntry {
            list_id,
            member,
            state,
            version,
            content_hash: ix.content_hash,
        },
        input: InputUtxo {
            nullifier_hash: nullifier,
            nullifier_tree_root_index: ix.nullifier_tree_root_index,
            utxo_tree_root_index: ix.utxo_tree_root_index,
        },
        input_hash: spent_hash,
        address_utxo_hash: [0u8; 32],
        proof: ix.proof,
    }
    .into_transact(&parsed.owner, &parsed.namespace_address)?;

    cpi_spp_namespace_signed(
        &parsed.namespace_address,
        parsed.namespace_bump,
        accounts,
        &transact,
    )
}
