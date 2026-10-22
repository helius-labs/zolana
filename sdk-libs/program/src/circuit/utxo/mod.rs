mod address;
mod balance;
mod data;
mod output;
mod token;
mod unique;

pub use address::NewAddress;
pub use balance::UtxoTrait;
use balance::{Amount, Balance, HasBalance};
pub use data::{DataHash, DataUtxo, UtxoData};
pub(crate) use output::Output;
pub use token::TokenUtxos;
pub use unique::UniqueDataUtxo;
pub(crate) use unique::{derive_address, CreatedAddress};
use zolana_interface::UTXO_DOMAIN;
pub(crate) use zolana_transaction::circuit::{SpentInput, Utxo};

use crate::circuit::{constant, CircuitVar};

fn utxo_domain() -> CircuitVar {
    constant(u64::from(UTXO_DOMAIN))
}
