use anyhow::Result;
use zolana_keypair::hash::poseidon;
use zolana_transaction::utxo::Blinding;

use crate::err;

/// Blinding seed of a settle transaction. It derives from the order opening,
/// which the taker and the maker both hold, so the taker recomputes its payout
/// note without a ciphertext. Matches the pool_settle circuit's `DSTX` domain.
pub fn settle_blinding_seed(order_blinding: &Blinding) -> Result<[u8; 32]> {
    order_blinding_seed(*b"DSTX", order_blinding)
}

/// Blinding seed of a cancel transaction, see [`settle_blinding_seed`].
/// Matches the escrow_cancel circuit's `DCNL` domain.
pub fn cancel_blinding_seed(order_blinding: &Blinding) -> Result<[u8; 32]> {
    order_blinding_seed(*b"DCNL", order_blinding)
}

fn order_blinding_seed(tag: [u8; 4], order_blinding: &Blinding) -> Result<[u8; 32]> {
    let mut domain = [0u8; 32];
    domain[28..].copy_from_slice(&tag);
    poseidon(&[&domain, order_blinding]).map_err(err)
}
