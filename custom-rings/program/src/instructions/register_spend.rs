use core::num::NonZeroU64;

use custom_ring_interface::{FixedWindow, RegisterSpendIxData};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::instruction::instruction_data::transact::{InputUtxo, TreeContext};
use zolana_program::TransactInputs;
use zolana_ring_policy::{Member, SpendCounters, SpendRecord};

use crate::{
    error::CustomRingError,
    instructions::policy_shared::{cpi_spp_namespace_signed, MutationAccounts, NamespaceWrite},
};

#[inline(never)]
pub fn process_register_spend_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: RegisterSpendIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    // 1. Require windowed velocity before claiming a member record.
    let parsed = MutationAccounts::validate_and_parse(program_id, accounts)?;
    let window = FixedWindow {
        slots: NonZeroU64::new(parsed.window_slots).ok_or(CustomRingError::VelocityDisabled)?,
    };
    // 2. Derive the signer's genesis record with zero counters in the current
    // window.
    let member = Member::owner_tag(parsed.payer.address().as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    let address = parsed
        .owner
        .spend_address(&member, parsed.entries_tree_id)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let record = SpendRecord {
        member,
        version: 0,
        window: window.index(Clock::get()?.slot),
        counters_commitment: SpendCounters::EMPTY
            .commitment()
            .map_err(|_| CustomRingError::HashingFailed)?,
        blinding: ix.blinding,
    };
    let output_hash = record
        .utxo_hash(&parsed.owner, &address, parsed.entries_tree_id)
        .map_err(|_| CustomRingError::HashingFailed)?;

    // 3. Create the record through SPP, the address nullifier admits one
    // record chain per member.
    let content = record.to_output_data();
    let transact = NamespaceWrite {
        output_hash,
        content: &content,
        inputs: TransactInputs {
            inputs: vec![InputUtxo {
                nullifier_hash: address,
                tree_index: 0,
            }],
            tree_contexts: vec![TreeContext {
                nullifier_tree_root_index: ix.nullifier_tree_root_index,
                utxo_tree_root_index: ix.utxo_tree_root_index,
            }],
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
