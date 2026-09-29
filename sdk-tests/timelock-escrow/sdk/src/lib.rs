pub mod instructions;
pub mod prover;
pub mod state;
pub mod zk_program;

use solana_address::Address;
pub use timelock_escrow_program::{
    instructions::{
        escrow::{EscrowIxData, EscrowProof},
        withdraw::{WithdrawIxData, WithdrawProof},
    },
    tag, ESCROW_AUTHORITY_PDA_SEED,
};

use crate::zk_program::ProgramOwner;

pub fn escrow_authority() -> ProgramOwner {
    ProgramOwner::find(&[ESCROW_AUTHORITY_PDA_SEED], &timelock_escrow_program::ID)
}

pub fn escrow_authority_pda() -> Address {
    *escrow_authority().pda()
}

pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}
