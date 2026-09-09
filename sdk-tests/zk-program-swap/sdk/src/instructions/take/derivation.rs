use anyhow::Result;
use zolana_keypair::hash::poseidon;
use zolana_transaction::Blinding;

use crate::err;

/// Settlement blinding seed shared by the maker and taker through the order opening.
/// Matches the take circuit's `SWTX` domain. Use before assigning SPP outputs.
pub fn take_blinding_seed(order_blinding: &Blinding) -> Result<[u8; 32]> {
    let mut domain = [0u8; 32];
    domain[28..].copy_from_slice(b"SWTX");
    poseidon(&[&domain, order_blinding]).map_err(err)
}
