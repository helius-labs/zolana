mod balance;
mod data;
mod input;
mod output;
mod token;
mod unique;

pub use balance::UtxoTrait;
use balance::{Amount, Balance, HasBalance};
pub use data::{checked_utxo_data, DataHash, DataUtxo, UtxoData};
pub(crate) use input::SpentInput;
pub use input::{Utxo, UtxoMeta};
pub(crate) use output::Output;
pub use token::TokenUtxo;
pub use unique::UniqueDataUtxo;
use zolana_interface::UTXO_DOMAIN;

use crate::circuit::{constant, CircuitVar};

fn utxo_domain() -> CircuitVar {
    constant(u64::from(UTXO_DOMAIN))
}
