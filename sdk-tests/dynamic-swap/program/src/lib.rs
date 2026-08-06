pub mod error;
pub mod instructions;
pub mod state;
pub mod verifying_keys;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{
    process_create_escrow_ix, process_create_pair_ix, process_deposit_liquidity_ix,
    process_refund_expired_ix, process_settle_ix, process_update_price_ix,
    process_withdraw_liquidity_ix,
};

pub mod tag {
    pub const CREATE_PAIR: u8 = 1;
    pub const UPDATE_PRICE: u8 = 2;
    pub const DEPOSIT_LIQUIDITY: u8 = 3;
    pub const WITHDRAW_LIQUIDITY: u8 = 4;
    pub const CREATE_ESCROW: u8 = 5;
    pub const REFUND_EXPIRED: u8 = 6;
    // 7 is retired; price commitment is part of CREATE_ESCROW.
    pub const SETTLE: u8 = 8;
}

/// Seeds `[POOL_AUTHORITY_PDA_SEED, pair]`: owns the pool's live UTXO.
pub const POOL_AUTHORITY_PDA_SEED: &[u8] = b"pool_authority";
/// Seeds `[ESCROW_AUTHORITY_PDA_SEED, pair]`: owns every order UTXO for that
/// pair.
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
        tag::DEPOSIT_LIQUIDITY => process_deposit_liquidity_ix(accounts, ix_data),
        tag::WITHDRAW_LIQUIDITY => process_withdraw_liquidity_ix(accounts, ix_data),
        tag::CREATE_ESCROW => process_create_escrow_ix(accounts, ix_data),
        tag::REFUND_EXPIRED => process_refund_expired_ix(accounts, ix_data),
        tag::SETTLE => process_settle_ix(accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
