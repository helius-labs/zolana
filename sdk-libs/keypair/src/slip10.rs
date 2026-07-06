//! SLIP-0010 hierarchical key derivation on NIST P-256.
//!
//! Backs the spec's wallet key hierarchy (`docs/spec.md`, "Signing Key" /
//! "ViewingKey"): `m/44'/TSPP_COIN_TYPE'/account'/change'/0'` on a BIP-39
//! `wallet_seed`, so a mnemonic reproduces the wallet's shielded keys.

use hmac::{Hmac, Mac};
use p256::{
    elliptic_curve::{sec1::ToEncodedPoint, Field, PrimeField},
    NonZeroScalar, PublicKey, Scalar,
};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::KeypairError;

/// Registered coin type for TSPP derivation paths, as declared by the spec.
/// The spec marks the value a placeholder; re-pinning it would change every
/// derived key, so wallets derived under it would stop being recoverable.
pub(crate) const TSPP_COIN_TYPE: u32 = 1_445_561_917;

/// Change-level index for the spend-authorizing key path.
pub(crate) const CHANGE_SIGNING: u32 = 0;
/// Change-level index for the viewing key path.
pub(crate) const CHANGE_VIEWING: u32 = 1;

const MASTER_HMAC_KEY: &[u8] = b"Nist256p1 seed";
const HARDENED: u32 = 1 << 31;

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC-SHA512 accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Left half of `I` as a P-256 scalar; `None` when `IL ≥ n` — the SLIP-0010
/// retry condition.
fn parse_scalar(il: &[u8]) -> Option<Scalar> {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(il);
    Option::<Scalar>::from(Scalar::from_repr(repr.into()))
}

/// A derivation node: a non-zero private scalar plus its chain code.
pub(crate) struct ExtendedKey {
    key: Scalar,
    chain_code: [u8; 32],
}

impl ExtendedKey {
    /// Master node: `I = HMAC-SHA512("Nist256p1 seed", seed)`; while `IL` is
    /// not a valid non-zero scalar, `I = HMAC-SHA512("Nist256p1 seed", I)`.
    pub(crate) fn master(seed: &[u8]) -> Self {
        let mut i = hmac_sha512(MASTER_HMAC_KEY, &[seed]);
        loop {
            if let Some(key) = parse_scalar(&i[..32]) {
                if !bool::from(key.is_zero()) {
                    let mut chain_code = [0u8; 32];
                    chain_code.copy_from_slice(&i[32..]);
                    return Self { key, chain_code };
                }
            }
            i = hmac_sha512(MASTER_HMAC_KEY, &[i.as_slice()]);
        }
    }

    /// SLIP-0010 CKDpriv. Hardened data is `0x00 ‖ ser256(k_par) ‖ ser32(i)`,
    /// normal data is `serP(k_par·G) ‖ ser32(i)`; on an invalid child
    /// (`IL ≥ n` or `k_i = 0`) it retries with `0x01 ‖ IR ‖ ser32(i)`.
    pub(crate) fn child(&self, index: u32) -> Self {
        let index_be = index.to_be_bytes();
        let mut i = if index >= HARDENED {
            let key_bytes = Zeroizing::new(self.key.to_bytes());
            hmac_sha512(&self.chain_code, &[&[0u8], key_bytes.as_slice(), &index_be])
        } else {
            hmac_sha512(&self.chain_code, &[&self.public_bytes(), &index_be])
        };
        loop {
            if let Some(il) = parse_scalar(&i[..32]) {
                let key = il + self.key;
                if !bool::from(key.is_zero()) {
                    let mut chain_code = [0u8; 32];
                    chain_code.copy_from_slice(&i[32..]);
                    return Self { key, chain_code };
                }
            }
            let retry = hmac_sha512(&self.chain_code, &[&[1u8], &i[32..], &index_be]);
            i = retry;
        }
    }

    pub(crate) fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.key.to_bytes());
        out
    }

    /// Compressed SEC1 public point of this node's key.
    pub(crate) fn public_bytes(&self) -> [u8; 33] {
        let scalar = NonZeroScalar::new(self.key).expect("node keys are non-zero by construction");
        let point = PublicKey::from_secret_scalar(&scalar).to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    #[cfg(test)]
    fn chain_code(&self) -> [u8; 32] {
        self.chain_code
    }
}

/// Derived secret at `m/44'/TSPP_COIN_TYPE'/account'/change'/0'` (all levels
/// hardened).
pub(crate) fn derive_wallet_key(
    wallet_seed: &[u8],
    account: u32,
    change: u32,
) -> Result<Zeroizing<[u8; 32]>, KeypairError> {
    if account >= HARDENED {
        return Err(KeypairError::DerivationIndexTooLarge);
    }
    let mut node = ExtendedKey::master(wallet_seed);
    for index in [44, TSPP_COIN_TYPE, account, change, 0] {
        node = node.child(index | HARDENED);
    }
    Ok(node.secret_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ShieldedKeypair, SigningKey, ViewingKey};

    const HARD: u32 = HARDENED;

    fn walk(seed_hex: &str, path: &[u32]) -> ExtendedKey {
        let seed = hex::decode(seed_hex).unwrap();
        let mut node = ExtendedKey::master(&seed);
        for &index in path {
            node = node.child(index);
        }
        node
    }

    fn assert_node(node: &ExtendedKey, chain_code: &str, private: &str, public: &str) {
        assert_eq!(hex::encode(node.chain_code()), chain_code);
        assert_eq!(hex::encode(node.secret_bytes().as_slice()), private);
        assert_eq!(hex::encode(node.public_bytes()), public);
    }

    // SLIP-0010 test vector 1 for nist256p1, seed 000102030405060708090a0b0c0d0e0f.
    #[test]
    fn slip10_nist256p1_vector_1() {
        let seed = "000102030405060708090a0b0c0d0e0f";
        assert_node(
            &walk(seed, &[]),
            "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
            "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
            "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8",
        );
        assert_node(
            &walk(seed, &[HARD]),
            "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11",
            "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c",
            "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c",
        );
        assert_node(
            &walk(seed, &[HARD, 1]),
            "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c",
            "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129",
            "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844",
        );
        assert_node(
            &walk(seed, &[HARD, 1, 2 | HARD, 2, 1000000000]),
            "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
            "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119",
            "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4",
        );
    }

    // SLIP-0010 test vector 2 for nist256p1 (64-byte seed).
    #[test]
    fn slip10_nist256p1_vector_2() {
        let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c99969\
                    3908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        assert_node(
            &walk(seed, &[]),
            "96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d",
            "eaa31c2e46ca2962227cf21d73a7ef0ce8b31c756897521eb6c7b39796633357",
            "02c9e16154474b3ed5b38218bb0463e008f89ee03e62d22fdcc8014beab25b48fa",
        );
        assert_node(
            &walk(seed, &[0, 2147483647 | HARD, 1, 2147483646 | HARD, 2]),
            "3bfb29ee8ac4484f09db09c2079b520ea5616df7820f071a20320366fbe226a7",
            "bb0a77ba01cc31d77205d51d08bd313b979a71ef4de9b062f8958297e746bd67",
            "020ee02e18967237cf62672983b253ee62fa4dd431f8243bfeccdf39dbe181387f",
        );
    }

    // SLIP-0010 "derivation retry" vector: deriving m/28578H hits an invalid
    // child key and exercises the 0x01‖IR‖ser32(i) retry branch.
    #[test]
    fn slip10_nist256p1_derivation_retry() {
        let seed = "000102030405060708090a0b0c0d0e0f";
        assert_node(
            &walk(seed, &[28578 | HARD]),
            "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2",
            "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669",
            "02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7",
        );
        assert_node(
            &walk(seed, &[28578 | HARD, 33941]),
            "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071",
            "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a",
            "0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120",
        );
    }

    // SLIP-0010 "seed retry" vector: the first master HMAC yields an invalid
    // key and exercises the master retry loop.
    #[test]
    fn slip10_nist256p1_seed_retry() {
        let seed = "a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446";
        assert_node(
            &walk(seed, &[]),
            "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c",
            "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f",
            "0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20",
        );
    }

    // The declared spec literal. The spec's own derivation formula does not
    // reproduce it (flagged as a spec gap); the literal is normative.
    #[test]
    fn coin_type_is_pinned() {
        assert_eq!(TSPP_COIN_TYPE, 1_445_561_917);
    }

    #[test]
    fn wallet_paths_are_deterministic_and_distinct() {
        let seed = [7u8; 64];
        let signing = derive_wallet_key(&seed, 0, CHANGE_SIGNING).unwrap();
        let signing_again = derive_wallet_key(&seed, 0, CHANGE_SIGNING).unwrap();
        let viewing = derive_wallet_key(&seed, 0, CHANGE_VIEWING).unwrap();
        let other_account = derive_wallet_key(&seed, 1, CHANGE_SIGNING).unwrap();
        assert_eq!(signing.as_slice(), signing_again.as_slice());
        assert_ne!(signing.as_slice(), viewing.as_slice());
        assert_ne!(signing.as_slice(), other_account.as_slice());

        assert_eq!(
            derive_wallet_key(&seed, HARDENED, CHANGE_SIGNING).unwrap_err(),
            KeypairError::DerivationIndexTooLarge
        );
    }

    #[test]
    fn from_seed_reproduces_the_shielded_keypair() {
        let seed = [9u8; 64];
        let a = ShieldedKeypair::from_seed(&seed, 0).unwrap();
        let b = ShieldedKeypair::from_seed(&seed, 0).unwrap();
        assert_eq!(a.signing_pubkey(), b.signing_pubkey());
        assert_eq!(a.viewing_pubkey(), b.viewing_pubkey());
        assert_eq!(a.owner_hash().unwrap(), b.owner_hash().unwrap());

        let signing = SigningKey::from_seed(&seed, 0).unwrap();
        let viewing = ViewingKey::from_seed(&seed, 0).unwrap();
        assert_eq!(a.signing_pubkey(), signing.pubkey());
        assert_eq!(a.viewing_pubkey(), viewing.pubkey());
        assert_ne!(
            signing.secret_bytes().as_slice(),
            viewing.secret_bytes().as_slice()
        );
    }
}
