use pinocchio::Address;
use spr_hasher::{primitives::solana_owner_identity, Hasher, Poseidon};
pub use spr_interface::ZERO_NULLIFIER_PUBKEY;

use super::CompressedAccountError;

/// A program PDA as the owner of compressed accounts.
///
/// Its nullifier secret is 0, so anyone can recompute the nullifier of a UTXO
/// it owns from the UTXO's hash and blinding. That lets the program check a
/// spend or a read against plaintext state, and it is why only plaintext state
/// belongs under such an owner. The PDA's authority over its UTXOs is its
/// signature: the transact circuit requires the owner to sign every output
/// with a non-zero data hash, and only the program signs for its PDA.
///
/// This differs from a shielded PDA keypair, whose nullifier secret is derived
/// and kept private.
#[derive(Clone, Copy)]
pub struct PdaOwner {
    pda: Address,
    identity: [u8; 32],
    owner_hash: [u8; 32],
}

impl PdaOwner {
    /// `owner_hash = Poseidon(identity, Poseidon(0))`. A PDA is a Solana key,
    /// so its identity hashes under the Solana owner tag like every ed25519
    /// owner.
    pub fn new(pda: &Address) -> Result<Self, CompressedAccountError> {
        let identity = solana_owner_identity(pda.as_array())?;
        let owner_hash = Poseidon::hashv(&[&identity, &ZERO_NULLIFIER_PUBKEY])?;
        Ok(Self {
            pda: *pda,
            identity,
            owner_hash,
        })
    }

    pub fn pda(&self) -> &Address {
        &self.pda
    }

    pub fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    pub fn owner_hash(&self) -> &[u8; 32] {
        &self.owner_hash
    }
}
