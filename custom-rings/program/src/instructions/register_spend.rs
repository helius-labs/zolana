use core::num::NonZeroU64;

use custom_ring_interface::{CustomRingError, FixedWindow, RegisterSpendIxData};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_ring_policy::{Member, SpendCounters, SpendRecord};

use crate::instructions::{
    policy_shared::{MutationAccounts, MutationKind, NamespaceWrite, Spend},
    shared::parse,
};

#[inline(never)]
pub fn process_register_spend_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: RegisterSpendIxData = parse(data)?;
    let parsed = MutationAccounts::validate_and_parse(program_id, accounts, MutationKind::Claim)?;
    let window = FixedWindow {
        slots: NonZeroU64::new(parsed.window_slots).ok_or(CustomRingError::VelocityDisabled)?,
    };
    let member =
        Member::owner_tag(parsed.payer.as_array()).map_err(|_| CustomRingError::HashingFailed)?;
    let address = parsed
        .owner
        .spend_address(&member, parsed.trees.address)
        .map_err(CustomRingError::from)?;
    let record = SpendRecord {
        member,
        version: 0,
        window: window.index(Clock::get()?.slot),
        counters_commitment: SpendCounters::EMPTY
            .commitment()
            .map_err(CustomRingError::from)?,
        blinding: ix.blinding,
    };
    // The address nullifier admits one record lineage per member.
    NamespaceWrite {
        output_hash: record
            .utxo_hash(&parsed.owner, &address, parsed.trees.output)
            .map_err(CustomRingError::from)?,
        content: &record.to_output_data(),
        spend: Spend::Claim(address),
        private_tx_blinding: ix.private_tx_blinding,
        nullifier_tree_root_index: ix.nullifier_tree_root_index,
        utxo_tree_root_index: ix.utxo_tree_root_index,
        proof: ix.proof,
    }
    .send(program_id, &parsed, accounts)
}
