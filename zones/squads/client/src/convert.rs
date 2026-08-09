//! Conversions shared by the request and crank paths.

use solana_pubkey::Pubkey;
use zolana_transaction::Address;

use crate::error::{Result, SquadsBackendError};

pub(crate) fn to_pubkey(address: Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

/// Split a P-256 owner signature into its `(r, s)` halves.
pub(crate) fn split_signature(signature: &[u8; 64]) -> Result<([u8; 32], [u8; 32])> {
    let r: [u8; 32] = signature
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| SquadsBackendError::Unsupported("owner signature r".into()))?;
    let s: [u8; 32] = signature
        .get(32..)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| SquadsBackendError::Unsupported("owner signature s".into()))?;
    Ok((r, s))
}
