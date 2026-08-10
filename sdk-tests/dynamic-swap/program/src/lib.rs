pub mod error;
pub mod instructions;
pub mod state;
pub mod verifying_keys;
#[cfg(feature = "vk-registry")]
pub mod vk_registry;
pub mod vk_registry_specs;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{
    process_create_escrow_ix, process_create_pair_ix, process_settle_ix, process_update_price_ix,
};

pub mod tag {
    pub const CREATE_PAIR: u8 = 1;
    pub const UPDATE_PRICE: u8 = 2;
    // Tags 3 and 4 are retired and stay reserved.
    pub const CREATE_ESCROW: u8 = 5;
    // Tags 6 and 7 are retired and stay reserved.
    // Settles an escrow (settle or price-refund) in one indistinguishable instruction.
    pub const SETTLE: u8 = 8;
    /// Only handled by a `vk-registry` build.
    pub const INIT_VK_REGISTRY: u8 = 9;
}

/// Seeds `[ESCROW_AUTHORITY_PDA_SEED, pair]`: owns every order and
/// reservation UTXO for that pair.
pub const ESCROW_AUTHORITY_PDA_SEED: &[u8] = b"escrow_authority";

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pinocchio::address::declare_id!("EMwmRvBALYSDxkmCJNpgyyJu383mG88GLLwC5PxREox4");

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (ix_tag, ix_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *ix_tag {
        tag::CREATE_PAIR => process_create_pair_ix(accounts, ix_data),
        tag::UPDATE_PRICE => process_update_price_ix(accounts, ix_data),
        tag::CREATE_ESCROW => process_create_escrow_ix(accounts, ix_data),
        tag::SETTLE => process_settle_ix(accounts, ix_data),
        #[cfg(feature = "vk-registry")]
        tag::INIT_VK_REGISTRY => vk_registry::process_init_vk_registry_ix(accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
