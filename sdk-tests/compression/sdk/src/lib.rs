pub mod discovery;
pub mod instructions;
pub mod shared;
pub mod state;

use anyhow::Result;
use solana_address::Address;

pub use compression_example_program::{
    instructions::{create::CreateIxData, update::UpdateIxData},
    state::PdaOwner,
    tag, ACCOUNT_PDA_SEED,
};

pub fn account_pda(authority: &Address) -> Address {
    Address::find_program_address(
        &[ACCOUNT_PDA_SEED, authority.as_array()],
        &compression_example_program::ID,
    )
    .0
}

pub fn account_address(pda: &Address) -> Result<[u8; 32]> {
    PdaOwner::new(pda.as_array())
        .map_err(err)?
        .address()
        .map_err(err)
}

pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}
