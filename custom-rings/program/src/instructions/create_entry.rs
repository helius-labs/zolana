use custom_ring_interface::CreateEntryIxData;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::instruction_data::transact::{InputUtxo, TreeContext};
use zolana_program::TransactInputs;
use zolana_ring_policy::{EntryState, ListEntry, ListId, Member};

use crate::{
    error::CustomRingError,
    instructions::policy_shared::{
        cpi_spp_namespace_signed, EntryTransition, MutationAccounts, MutationKind,
    },
};

/// The address slot inserts the derived address, a second create for the same
/// `(list_id, member)` fails in SPP.
#[inline(never)]
pub fn process_create_entry_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: CreateEntryIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let list_id = ListId::try_from(ix.list_id).map_err(|_| CustomRingError::InvalidListId)?;
    let state = EntryState::try_from(ix.state).map_err(|_| CustomRingError::InvalidEntryState)?;
    let member = Member::from_bytes(ix.member).map_err(|_| CustomRingError::InvalidPolicyMember)?;
    if !list_id.admits_content(ix.content_hash) {
        return Err(CustomRingError::InvalidEntryContent.into());
    }

    let parsed = MutationAccounts::validate_and_parse(program_id, accounts, MutationKind::Claim)?;
    parsed.check_source(list_id)?;
    parsed.check_mutator(list_id, &member)?;

    let entry = ListEntry {
        list_id,
        member,
        state,
        version: 0,
        content_hash: ix.content_hash,
        blinding: ix.blinding,
    };
    let address = parsed.trees.entry_address(&parsed.owner, &entry)?;
    let transact = EntryTransition {
        entry,
        inputs: TransactInputs {
            inputs: vec![InputUtxo {
                nullifier_hash: address,
                tree_index: 0,
            }],
            tree_contexts: vec![TreeContext {
                utxo_tree_root_index: ix.utxo_tree_root_index,
                nullifier_tree_root_index: ix.nullifier_tree_root_index,
            }],
        },
        input_hash: [0u8; 32],
        address_nullifier: address,
        private_tx_blinding: ix.private_tx_blinding,
        proof: ix.proof,
    }
    .into_transact(&parsed)?;

    cpi_spp_namespace_signed(
        &parsed.namespace_address,
        parsed.namespace_bump,
        accounts,
        &transact,
    )
}
