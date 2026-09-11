use custom_ring_interface::RegisterSpendIxData;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::instruction::instruction_data::transact::InputUtxo;
use zolana_ring_policy::{Member, SpendCounters, SpendRecord};

use crate::{
    error::CustomRingError,
    instructions::policy_shared::{cpi_spp_namespace_signed, MutationAccounts, NamespaceWrite},
};

/// The record content is derived from the payer and the clock.
#[inline(never)]
pub fn process_register_spend_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: RegisterSpendIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    let parsed = MutationAccounts::validate_and_parse(program_id, accounts)?;
    if parsed.window_slots == 0 {
        return Err(CustomRingError::VelocityDisabled.into());
    }
    let member = Member::owner_tag(parsed.payer.address().as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    let address = parsed
        .owner
        .spend_address(&member, parsed.entries_tree_id)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let record = SpendRecord {
        member,
        version: 0,
        window: Clock::get()?.slot / parsed.window_slots,
        counters_commitment: SpendCounters::zero(&[])
            .commitment()
            .map_err(|_| CustomRingError::HashingFailed)?,
        blinding: ix.blinding,
    };
    let output_hash = record
        .utxo_hash(&parsed.owner, &address, parsed.entries_tree_id)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let content = record.to_output_data();
    let transact = NamespaceWrite {
        output_hash,
        content: &content,
        input: InputUtxo {
            nullifier_hash: address,
            nullifier_tree_root_index: ix.nullifier_tree_root_index,
            utxo_tree_root_index: ix.utxo_tree_root_index,
        },
        input_hash: [0u8; 32],
        address_nullifier: address,
        private_tx_blinding: ix.private_tx_blinding,
        proof: ix.proof,
    }
    .into_transact(&parsed.namespace_address)?;

    cpi_spp_namespace_signed(
        &parsed.namespace_address,
        parsed.namespace_bump,
        accounts,
        &transact,
    )
}
