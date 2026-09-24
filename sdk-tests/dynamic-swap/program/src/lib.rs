pub mod error;
pub mod instructions;
pub mod state;
pub mod verifying_keys;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{
    process_cancel_ix, process_create_escrow_ix, process_create_pair_ix,
    process_deposit_liquidity_ix, process_rebalance_liquidity_ix, process_settle_ix,
    process_update_price_ix, process_withdraw_liquidity_ix,
};

pub mod tag {
    pub const CREATE_PAIR: u8 = 1;
    pub const UPDATE_PRICE: u8 = 2;
    // Shields public SPL into a new pool note (booked = amount).
    pub const DEPOSIT_LIQUIDITY: u8 = 3;
    // Unshields a public amount from one pool note to the authority's SPL.
    pub const WITHDRAW_LIQUIDITY: u8 = 4;
    // Restructures pool notes (many to many) with an optional public credit.
    pub const REBALANCE_LIQUIDITY: u8 = 5;
    pub const CREATE_ESCROW: u8 = 6;
    // Fills an escrow before expiry from the pool.
    pub const SETTLE: u8 = 7;
    // Refunds an expired escrow to the taker.
    pub const CANCEL: u8 = 8;
}

/// Seeds `[ESCROW_AUTHORITY_PDA_SEED, pair]`: owns every order UTXO for that
/// pair.
pub const ESCROW_AUTHORITY_PDA_SEED: &[u8] = b"escrow_authority";

/// Seeds `[POOL_AUTHORITY_PDA_SEED, pair]`: owns every pool (liquidity) UTXO
/// for that pair.
pub const POOL_AUTHORITY_PDA_SEED: &[u8] = b"pool_authority";

/// The escrow_authority and pool_authority identities' nullifier pubkey: the
/// pubkey of the all-zero nullifier secret
/// (`Poseidon(right_align([0u8; 31]))`). The secret is deliberately public:
/// escrow- and pool-note spend linkage is already public
/// (`Escrow.order_utxo_hash` lives in the escrow account, deposit notes are
/// public), so a secret key would hide nothing, and a public key lets both the
/// maker (settle) and the taker (cancel) build the order spend. Spends are
/// gated by the proofs, the signer checks, and the liquidity accounting.
/// Pinned against `NullifierKey::from_secret([0u8; 31]).pubkey()` by an SDK
/// test.
pub const ESCROW_NULLIFIER_PUBKEY: [u8; 32] = [
    0x2a, 0x09, 0xa9, 0xfd, 0x93, 0xc5, 0x90, 0xc2, 0x6b, 0x91, 0xef, 0xfb, 0xb2, 0x49, 0x9f, 0x07,
    0xe8, 0xf7, 0xaa, 0x12, 0xe2, 0xb4, 0x94, 0x0a, 0x3a, 0xed, 0x24, 0x11, 0xcb, 0x65, 0xe1, 0x1c,
];

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
        tag::REBALANCE_LIQUIDITY => process_rebalance_liquidity_ix(accounts, ix_data),
        tag::CREATE_ESCROW => process_create_escrow_ix(accounts, ix_data),
        tag::SETTLE => process_settle_ix(accounts, ix_data),
        tag::CANCEL => process_cancel_ix(accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
