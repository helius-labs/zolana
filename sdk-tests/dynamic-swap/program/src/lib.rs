pub mod error;
pub mod instructions;
pub mod state;
pub mod verifying_keys;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{
    process_create_escrow_ix, process_create_pair_ix, process_settle_ix, process_update_price_ix,
};

pub mod tag {
    pub const CREATE_PAIR: u8 = 1;
    pub const UPDATE_PRICE: u8 = 2;
    // 3 retired (was DEPOSIT_LIQUIDITY) and 4 retired (was WITHDRAW_LIQUIDITY):
    // there is no shared pool -- the maker funds each escrow directly.
    pub const CREATE_ESCROW: u8 = 5;
    // 6 retired (was EXPIRE_ESCROW): expire is now one outcome of SETTLE.
    // 7 retired (was COMMIT_TO_SWAP): pricing is folded into CREATE_ESCROW, so
    // every escrow is committed at creation and there is no separate commit step.
    // Settles an escrow (settle / price-refund) in one indistinguishable
    // instruction. Reuses the former PAYOUT tag.
    pub const SETTLE: u8 = 8;
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
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
