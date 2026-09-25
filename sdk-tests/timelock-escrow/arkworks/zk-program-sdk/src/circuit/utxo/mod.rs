mod data;
mod input;
mod output;
mod token;

pub use data::{DataHash, DataUtxo, UtxoData};
pub use input::Utxo;
pub(crate) use output::Output;
pub use output::OutputTokenUtxo;
pub use token::TokenUtxo;
use zolana_interface::UTXO_DOMAIN;

use super::{constant, CircuitVar};

fn utxo_domain() -> CircuitVar {
    constant(u64::from(UTXO_DOMAIN))
}
