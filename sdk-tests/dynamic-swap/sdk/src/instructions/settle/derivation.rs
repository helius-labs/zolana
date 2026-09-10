use anyhow::Result;
use zolana_keypair::hash::poseidon;
use zolana_transaction::Blinding;

use crate::err;

/// Settlement blinding seed shared through the escrow and reservation openings.
/// Matches the settle circuit's `DSTX` domain. Both settlement outcomes use it.
pub fn settle_blinding_seed(
    order_blinding: &Blinding,
    reservation_blinding: &Blinding,
) -> Result<[u8; 32]> {
    let mut domain = [0u8; 32];
    domain[28..].copy_from_slice(b"DSTX");
    poseidon(&[&domain, order_blinding, reservation_blinding]).map_err(err)
}
