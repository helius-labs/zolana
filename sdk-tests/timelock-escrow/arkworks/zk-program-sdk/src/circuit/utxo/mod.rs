mod data;
mod input;
mod ledger;
mod output;
mod token;

pub use data::{DataHash, DataUtxo, UtxoData};
pub(crate) use input::SpentInput;
pub use input::Utxo;
pub use ledger::Balance;
use ledger::{HasLedger, Ledger};
pub(crate) use output::Output;
pub use token::TokenUtxo;
use zolana_interface::UTXO_DOMAIN;

use super::{constant, CircuitVar};

fn utxo_domain() -> CircuitVar {
    constant(u64::from(UTXO_DOMAIN))
}
