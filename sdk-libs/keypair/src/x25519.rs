//! X25519 auditor envelope keys. A public key travels as the 33-byte `0x04 || u`.

use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
use zolana_hasher::primitives::is_canonical_x25519_public_key;

use crate::KeypairError;

pub const X25519_KEY_TAG: u8 = 4;

/// `0x04 || u` with a canonical little-endian u.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct X25519Pubkey([u8; 33]);

impl X25519Pubkey {
    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, KeypairError> {
        if bytes[0] != X25519_KEY_TAG {
            return Err(KeypairError::InvalidPublicKey);
        }
        let mut u = [0u8; 32];
        u.copy_from_slice(&bytes[1..]);
        Self::from_u(u)
    }

    pub fn from_u(u: [u8; 32]) -> Result<Self, KeypairError> {
        if !is_canonical_x25519_public_key(&u) {
            return Err(KeypairError::InvalidPublicKey);
        }
        let mut bytes = [X25519_KEY_TAG; 33];
        bytes[1..].copy_from_slice(&u);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    pub fn u(&self) -> [u8; 32] {
        let mut u = [0u8; 32];
        u.copy_from_slice(&self.0[1..]);
        u
    }
}

/// An RFC 7748 secret. Multiplication clamps it.
#[derive(Clone)]
pub struct X25519Secret(StaticSecret);

impl X25519Secret {
    pub fn new() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(StaticSecret::from(*bytes))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        Ok(Self(StaticSecret::from(*bytes)))
    }

    /// Unclamped secret bytes, the circuit witness encoding.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn pubkey(&self) -> X25519Pubkey {
        let mut bytes = [X25519_KEY_TAG; 33];
        bytes[1..].copy_from_slice(PublicKey::from(&self.0).as_bytes());
        X25519Pubkey(bytes)
    }

    /// Rejects a low-order peer, whose result does not depend on this secret.
    pub fn ecdh(&self, peer: &X25519Pubkey) -> Result<Zeroizing<[u8; 32]>, KeypairError> {
        let shared = self.0.diffie_hellman(&PublicKey::from(peer.u()));
        if !shared.was_contributory() {
            return Err(KeypairError::NonContributoryKey);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

impl Default for X25519Secret {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_tagged_keys_reject_p256_and_coordinate_aliases() {
        let key = X25519Secret::from_bytes(&[7; 32]).unwrap().pubkey();
        assert_eq!(X25519Pubkey::from_bytes(*key.as_bytes()).unwrap(), key);
        for tag in [0, 2, 3, 5] {
            let mut bytes = *key.as_bytes();
            bytes[0] = tag;
            assert!(X25519Pubkey::from_bytes(bytes).is_err());
        }
        let mut alias = key.u();
        alias[31] |= 128;
        assert!(X25519Pubkey::from_u(alias).is_err());
        let mut p = [255; 32];
        p[0] = 237;
        p[31] = 127;
        assert!(X25519Pubkey::from_u(p).is_err());
        p[0] -= 1;
        assert!(X25519Pubkey::from_u(p).is_ok());
    }

    #[test]
    fn clamping_accepts_zero_secrets_but_rejects_noncontributory_peers() {
        let key = X25519Secret::from_bytes(&[0; 32]).unwrap();
        let peer = X25519Secret::from_bytes(&[9; 32]).unwrap();
        assert_eq!(
            *key.ecdh(&peer.pubkey()).unwrap(),
            *peer.ecdh(&key.pubkey()).unwrap()
        );
        for u in [0, 1] {
            let mut low_order = [0; 32];
            low_order[0] = u;
            assert_eq!(
                key.ecdh(&X25519Pubkey::from_u(low_order).unwrap())
                    .unwrap_err(),
                KeypairError::NonContributoryKey
            );
        }
    }
}
