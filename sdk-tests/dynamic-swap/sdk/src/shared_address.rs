use anyhow::Result;
use solana_address::Address;
use zolana_keypair::{
    constants::BLINDING_LEN, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress, ViewingKey,
};

use crate::err;

/// A shielded address whose owner is a program PDA and whose viewing key is
/// shared between two parties.
///
/// A PDA holds no private key, so spends are authorized by the owning program
/// via `invoke_signed` (SPP resolves the owner by the forwarded signer account,
/// not a signature) and the nullifier key is a well-known zero-secret constant.
/// The viewing key is derived once from a key exchange between the two parties'
/// viewing keys, so either can encrypt notes to this address and decrypt them
/// back -- neither the signing authority (the program) nor an observer can.
///
/// On-chain the owner is a standard Ed25519-rail owner (the PDA address as an
/// ed25519 key); the PDA-ness is purely the client/program authorization model.
pub struct SharedShieldedAddress {
    pda: Address,
    viewing_key: ViewingKey,
}

impl SharedShieldedAddress {
    /// Derive the shared viewing key from a key exchange -- the local party's
    /// viewing key against the counterparty's viewing pubkey -- and pair it with
    /// the owning PDA. Both parties compute an identical instance (ECDH is
    /// symmetric); the raw ECDH secret is run through `ViewingKey::from_seed` so
    /// it becomes a uniform, valid scalar. This is the only constructor: the
    /// viewing key is always the shared secret, never an arbitrary key.
    pub fn from_key_exchange(
        own: &ViewingKey,
        counterparty: &P256Pubkey,
        pda: Address,
    ) -> Result<Self> {
        let seed = own.ecdh(counterparty).map_err(err)?;
        let viewing_key = ViewingKey::from_seed(&seed, 0).map_err(err)?;
        Ok(Self { pda, viewing_key })
    }

    /// The nullifier key for UTXOs owned by this address: the constant
    /// zero-secret key. It must stay zero because the program derives the escrow
    /// authority's expected owner hash from this exact key
    /// (`escrow_authority_owner_hash`); deriving it from the shared viewing key
    /// would need a matching program change. The program gates the spend via
    /// `invoke_signed`, so a public nullifier key is not a spend authority.
    pub fn nullifier_key(&self) -> NullifierKey {
        NullifierKey::from_secret([0u8; BLINDING_LEN])
    }

    /// The shared viewing key, for decrypting notes sent to this address.
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// The `ShieldedAddress` derived from the PDA and the shared viewing key.
    /// Everything else the callers need -- `owner_hash()`, the scan
    /// `confidential_view_tag()`, the signing pubkey -- hangs off this.
    pub fn shielded_address(&self) -> Result<ShieldedAddress> {
        Ok(ShieldedAddress {
            signing_pubkey: PublicKey::from_ed25519(self.pda.as_array()),
            nullifier_pubkey: self.nullifier_key().pubkey().map_err(err)?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_parties_derive_the_same_address() {
        let maker = ViewingKey::new();
        let taker = ViewingKey::new();
        let pda = Address::new_from_array([3u8; 32]);
        let from_maker =
            SharedShieldedAddress::from_key_exchange(&maker, &taker.pubkey(), pda).expect("maker");
        let from_taker =
            SharedShieldedAddress::from_key_exchange(&taker, &maker.pubkey(), pda).expect("taker");
        assert_eq!(
            from_maker.shielded_address().unwrap(),
            from_taker.shielded_address().unwrap()
        );
    }
}
