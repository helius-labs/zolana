mod escrow;
mod state;
mod withdraw;

use solana_address::Address;
use zolana_program::ProgramOwner;

pub use escrow::{
    Escrow, EscrowCircuit, EscrowPrivateInputs, EscrowPublicInputs, ESCROW_OUTPUT_SLOT,
    ESCROW_TOKEN_INPUTS,
};
pub use state::{EscrowTerms, EscrowTermsCircuit};
pub use withdraw::{Withdraw, WithdrawCircuit, WithdrawPrivateInputs, WithdrawPublicInputs};

pub const ID: Address = Address::from_str_const("CVtSrm1XGnozF4XKGDCWLDoxypr1KL8PxnJtK3KzrBDY");

pub const ESCROW_AUTHORITY_PDA_SEED: &[u8] = b"escrow_authority";

pub fn escrow_authority() -> ProgramOwner {
    ProgramOwner::find(&[ESCROW_AUTHORITY_PDA_SEED], &ID)
}
