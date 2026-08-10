//! Read authorization for the endpoints that return decrypted account data.
//!
//! `get_balances` and `get_proposals` resolve the auditor-recovered shared
//! viewing key and decrypt everything one account owns, so both are gated on a
//! policy chosen at construction time. The gate is a type parameter of
//! [`SquadsBackend`](crate::SquadsBackend), so a backend that authorizes every
//! caller cannot exist unless the operator names such a policy.

use zolana_transaction::Address;

use crate::error::{Result, SquadsBackendError};

/// Decides whether a request may read one account's decrypted balances and
/// proposals. `signature` is the caller-supplied authorization over the request.
pub trait ReadAuthorization {
    fn authorize(&self, viewing_key_account: Address, signature: &[u8; 64]) -> Result<()>;
}

/// The default policy, which authorizes nothing.
///
/// A viewing key account stores `owner` as a proof identity (a P-256 key hash on
/// the keypair rail, a vault hash on the smart-account rail), never a signing
/// public key, so no signature over the request can be verified against it from
/// this crate. Until the ring publishes an owner authentication key, denying is
/// the only answer that does not hand every caller another user's UTXO set.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyUnverifiedRead;

impl ReadAuthorization for DenyUnverifiedRead {
    fn authorize(&self, viewing_key_account: Address, _signature: &[u8; 64]) -> Result<()> {
        Err(SquadsBackendError::UnauthorizedRead(
            viewing_key_account.to_string(),
        ))
    }
}

/// A policy that authorizes every caller. It exposes every account's decrypted
/// UTXO set to anyone who can name the account address, so it is limited to
/// single-process test harnesses.
#[cfg(feature = "insecure-permissive-read")]
#[derive(Clone, Copy, Debug, Default)]
pub struct InsecurePermissiveRead;

#[cfg(feature = "insecure-permissive-read")]
impl ReadAuthorization for InsecurePermissiveRead {
    fn authorize(&self, _viewing_key_account: Address, _signature: &[u8; 64]) -> Result<()> {
        Ok(())
    }
}
