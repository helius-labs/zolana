mod data;
mod input;
mod output;
mod token;

pub use data::{DataHash, DataUtxo, UtxoData};
pub use input::Utxo;
pub(crate) use output::Output;
pub use output::OutputTokenUtxo;
pub use token::TokenUtxo;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::UTXO_DOMAIN;

use super::{constant, CircuitVar};
use crate::{conversion::var, RelationError};

fn sol_asset() -> Result<CircuitVar, RelationError> {
    var(
        &hash_bytes(zolana_transaction::Mint::SOL.asset.as_array())?,
        "the SOL asset",
    )
}

fn utxo_domain() -> CircuitVar {
    constant(u64::from(UTXO_DOMAIN))
}
