use anyhow::Result;
use dynamic_swap_program::circuits::{CANCEL_BLINDING_DOMAIN, SETTLE_BLINDING_DOMAIN};
use spr_keypair::hash::poseidon;
use spr_transaction::utxo::Blinding;

use crate::err;

/// Blinding seed of a settle transaction. It derives from the order opening,
/// which the taker and the maker both hold, so the taker recomputes its payout
/// note without a ciphertext.
pub fn settle_blinding_seed(order_blinding: &Blinding) -> Result<[u8; 32]> {
    order_blinding_seed(SETTLE_BLINDING_DOMAIN, order_blinding)
}

/// Blinding seed of a cancel transaction, see [`settle_blinding_seed`].
pub fn cancel_blinding_seed(order_blinding: &Blinding) -> Result<[u8; 32]> {
    order_blinding_seed(CANCEL_BLINDING_DOMAIN, order_blinding)
}

fn order_blinding_seed(domain_tag: [u8; 4], order_blinding: &Blinding) -> Result<[u8; 32]> {
    let mut domain = [0u8; 32];
    domain[28..].copy_from_slice(&domain_tag);
    poseidon(&[&domain, order_blinding]).map_err(err)
}
