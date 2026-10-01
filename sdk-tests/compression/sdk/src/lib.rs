pub mod discovery;
pub mod instructions;
pub mod shared;
pub mod state;

use anyhow::Result;
use solana_address::Address;
use zolana_program::compression::{AddressSeed, NewAddress, PdaOwner};

pub use compression_example_program::{
    instructions::{create::CreateIxData, read::ReadIxData, update::UpdateIxData},
    tag, ACCOUNT_PDA_SEED,
};

pub fn account_pda(authority: &Address) -> Address {
    Address::find_program_address(
        &[ACCOUNT_PDA_SEED, authority.as_array()],
        &compression_example_program::ID,
    )
    .0
}

/// The compressed address this PDA reserves in the tree with the raw id
/// `tree_id`. The tree id is folded into the address UTXO's commitment, so an
/// address is scoped to one tree.
pub fn account_address(pda: &Address, tree_id: u16) -> Result<[u8; 32]> {
    let owner = PdaOwner::new(pda).map_err(err)?;
    let address = NewAddress::derive(&owner, AddressSeed::owner(&owner), tree_id).map_err(err)?;
    Ok(*address.address())
}

pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}
