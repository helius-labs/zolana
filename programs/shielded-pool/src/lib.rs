pub mod instructions;

/// Test-only re-exports for the program-tests crate (`test-sbf` is never
/// enabled for the shipped .so): the smallest surface the moved unit tests
/// need, nothing more.
#[cfg(feature = "test-sbf")]
pub mod testing {
    pub use crate::instructions::hash::solana_pk_hash;
    pub use crate::instructions::merge::account::MergeTransactAccounts;
    pub use crate::instructions::ring_config::{
        loader::load_ring_config, update_owner::process_update_ring_config_owner,
    };
    pub use crate::instructions::settlement::{Settlement, SettlementAccountsSol};
    pub use crate::instructions::shared::{
        forester_fee_amount, reimburse_forester_with_rent_minimum, tree_error,
    };
    pub use crate::instructions::transact::verify::{
        amount_field, fixed_signer_hash_chain, OwnerHashCache, TransactProof, TransactProofInputs,
        MAX_SIGNERS, SIGNER_ZERO_SUFFIX_CHAINS,
    };
}

use light_program_profiler::profile;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::tag::InstructionTag;

use crate::instructions::{
    batch_update_nullifier_tree::process_batch_update_nullifier_tree,
    close_nullifier_pdas::process_close_nullifier_pdas,
    create_asset_counter::process_create_asset_counter,
    create_spl_interface::processor::process_create_spl_interface,
    create_tree::process_create_tree,
    deposit::{process_deposit, process_ring_deposit},
    merge::process_merge_transact_ix,
    merge_ring::process_merge_ring_ix,
    protocol_config::{
        create::process_create_protocol_config, pause_tree::process_pause_tree,
        update::process_update_protocol_config,
    },
    ring_config::{
        create::process_create_ring_config, update::process_update_ring_config,
        update_owner::process_update_ring_config_owner,
    },
    transact::process_transact_ix,
};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}
pinocchio::address::declare_id!("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG");

#[profile]
pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (ix_tag, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    let ix_tag =
        InstructionTag::try_from(*ix_tag).map_err(|_| ProgramError::InvalidInstructionData)?;

    match ix_tag {
        // Deliberate no-op: the event self-CPI exists only to record inner-
        // instruction data. Anyone can invoke this tag (directly or via CPI)
        // with forged bytes; indexers MUST filter events by parent instruction
        // (see `zolana_event::tag::EMIT_EVENT`).
        InstructionTag::EmitEvent => Ok(()),
        InstructionTag::Transact
        | InstructionTag::RingTransact
        | InstructionTag::RingAuthorityTransact => process_transact_ix(accounts, payload, ix_tag),
        InstructionTag::CreateTree => process_create_tree(accounts, payload),
        InstructionTag::BatchUpdateNullifierTree => {
            process_batch_update_nullifier_tree(accounts, payload)
        }
        InstructionTag::Deposit => process_deposit(accounts, payload),
        InstructionTag::RingDeposit => process_ring_deposit(accounts, payload),
        InstructionTag::CreateAssetCounter => process_create_asset_counter(accounts, payload),
        InstructionTag::CreateSplInterface => process_create_spl_interface(accounts, payload),
        InstructionTag::CreateProtocolConfig => process_create_protocol_config(accounts, payload),
        InstructionTag::UpdateProtocolConfig => process_update_protocol_config(accounts, payload),
        InstructionTag::PauseTree => process_pause_tree(accounts, payload),
        InstructionTag::CreateRingConfig => process_create_ring_config(accounts, payload),
        InstructionTag::UpdateRingConfigOwner => {
            process_update_ring_config_owner(accounts, payload)
        }
        InstructionTag::UpdateRingConfig => process_update_ring_config(accounts, payload),
        InstructionTag::MergeTransact => process_merge_transact_ix(accounts, payload),
        InstructionTag::RingMergeTransact => process_merge_ring_ix(accounts, payload),
        InstructionTag::CloseNullifierPdas => process_close_nullifier_pdas(accounts, payload),
    }
}
