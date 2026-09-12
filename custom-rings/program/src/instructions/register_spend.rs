use custom_ring_interface::{RegisterSpendIxData, SpendRecordHead};
use pinocchio::{
    cpi::{Seed, Signer},
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::instruction::instruction_data::transact::InputUtxo;
use zolana_ring_policy::{entry_nullifier, Member, SpendCounters, SpendRecord};

use crate::{
    error::CustomRingError,
    instructions::{
        loader::load_spend_record_head,
        policy_shared::{cpi_spp_namespace_signed, MutationAccounts, NamespaceWrite},
        shared::PdaCheck,
    },
    state::SpendRecordHeadInitParams,
};

/// The record content is derived from the payer and the clock, its nullifier
/// pins a fresh head.
#[inline(never)]
pub fn process_register_spend_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: RegisterSpendIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    // The head trails the SPP list, it is never forwarded.
    let (head_account, mutation) = accounts
        .split_last_mut()
        .ok_or(pinocchio::error::ProgramError::NotEnoughAccountKeys)?;
    let parsed = MutationAccounts::validate_and_parse(program_id, mutation)?;
    if parsed.window_slots == 0 {
        return Err(CustomRingError::VelocityDisabled.into());
    }
    let member = Member::owner_tag(parsed.payer.address().as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    if load_spend_record_head(program_id, head_account, member.as_bytes())?.is_some() {
        return Err(CustomRingError::SpendRecordAlreadyRegistered.into());
    }
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
    let head_nullifier =
        entry_nullifier(&output_hash, &ix.blinding).map_err(|_| CustomRingError::HashingFailed)?;
    let bump = PdaCheck {
        program_id,
        address: head_account.address(),
        seeds: &[SpendRecordHead::SEED, member.as_bytes()],
        mismatch: CustomRingError::InvalidSpendRecordHead,
    }
    .verify()?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(SpendRecordHead::SEED),
        Seed::from(member.as_bytes().as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        head_account,
        SpendRecordHead::SIZE,
        program_id,
        parsed.payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;
    SpendRecordHeadInitParams {
        nullifier: head_nullifier,
        bump,
    }
    .init(head_account)?;

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
        mutation,
        &transact,
    )
}
