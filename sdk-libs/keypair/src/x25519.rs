//! X25519 viewing and auditor envelope keys. Public keys use `0x04 || u`.

use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
use zolana_hasher::primitives::is_canonical_x25519_public_key;

use crate::KeypairError;

pub const X25519_KEY_TAG: u8 = 4;
pub const X25519_PUBKEY_LEN: usize = 33;

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
    use crate::derivation::{
        DST_X25519_PDA_ROOT, DST_X25519_VIEW_ROOT, X25519_PDA_ROOT_U, X25519_VIEW_ROOT_U,
    };
    use num_bigint::BigUint;
    use sha2::{Digest, Sha256};

    #[test]
    fn fixed_peers_are_hash_derived_main_curve_prime_order_points() {
        let p = (BigUint::from(1u8) << 255) - 19u8;
        let candidate = |domain: &[u8], counter: u32| {
            let mut preimage = Vec::from(domain);
            preimage.extend_from_slice(&counter.to_be_bytes());
            let mut digest = Sha256::digest(preimage);
            digest[31] &= 127;
            BigUint::from_bytes_le(&digest)
        };
        let rhs = |x: &BigUint| (x * x * x + BigUint::from(486662u32) * x * x + x) % &p;
        for (domain, counter, fixed_u, expected_root) in [
            (
                DST_X25519_VIEW_ROOT,
                1,
                X25519_VIEW_ROOT_U,
                "4bc4c7d8ad80138320dcfc5134053357f1e323d04ae8a3f33114cb37c672c847",
            ),
            (
                DST_X25519_PDA_ROOT,
                3,
                X25519_PDA_ROOT_U,
                "de2db4a0ec3196280ab850100eeb1a17b98ecbae467d9a92c693aaf1be971b69",
            ),
        ] {
            for skipped_counter in 0..counter {
                let skipped = candidate(domain, skipped_counter);
                assert!(skipped < p);
                assert_eq!(rhs(&skipped).modpow(&((&p - 1u8) >> 1), &p), &p - 1u8);
            }
            let mut x = candidate(domain, counter);
            assert!(x < p);
            assert_eq!(rhs(&x).modpow(&((&p - 1u8) >> 1), &p), BigUint::from(1u8));

            // The clamp supplies a multiple of eight. Pin the projected peer,
            // whose discrete log relative to the public basepoint is unknown.
            let mut z = BigUint::from(1u8);
            for _ in 0..3 {
                let a = (&x + &z).modpow(&BigUint::from(2u8), &p);
                let b = ((&x + &p - &z) % &p).modpow(&BigUint::from(2u8), &p);
                let e = (&a + &p - &b) % &p;
                x = &a * &b % &p;
                z = &e * (&a + BigUint::from(121665u32) * &e) % &p;
            }
            assert_ne!(z, BigUint::from(0u8));
            let mut expected = (&x * z.modpow(&(&p - 2u8), &p) % &p).to_bytes_le();
            expected.resize(32, 0);
            assert_eq!(expected.as_slice(), fixed_u);
            let peer = X25519Pubkey::from_u(fixed_u).unwrap();
            let root = X25519Secret::from_bytes(&[7; 32])
                .unwrap()
                .ecdh(&peer)
                .unwrap();
            assert_eq!(hex::encode(*root), expected_root);
        }
    }

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
