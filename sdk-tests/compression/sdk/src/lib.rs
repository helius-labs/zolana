pub mod discovery;
pub mod instructions;
pub mod shared;
pub mod state;

use solana_address::Address;

pub use compression_example_program::{
    instructions::{create::CreateIxData, update::UpdateIxData},
    tag, ACCOUNT_PDA_SEED,
};

pub fn account_pda(authority: &Address) -> Address {
    Address::find_program_address(
        &[ACCOUNT_PDA_SEED, authority.as_array()],
        &compression_example_program::ID,
    )
    .0
}

pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}
