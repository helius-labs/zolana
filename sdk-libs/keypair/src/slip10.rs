//! SLIP-0010 hierarchical key derivation for NIST P-256 (`Nist256p1`).
//!
//! Master-key generation and private-parent -> private-child derivation
//! (CKDpriv) per SLIP-0010, including the seed and derivation retry rules.
//! Conformance is pinned by the official `nist256p1` test vectors, including
//! both retry vectors.

use hmac::{Hmac, Mac};
use p256::{
    elliptic_curve::{sec1::ToEncodedPoint, Field, PrimeField},
    FieldBytes, NonZeroScalar, PublicKey as P256PublicKey, Scalar, SecretKey,
};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::KeypairError;

const CURVE_SEED_KEY: &[u8] = b"Nist256p1 seed";

/// Hardened-index bit per BIP-32 / SLIP-0010.
pub const HARDENED: u32 = 0x8000_0000;

/// A retry triggers with probability ~2^-32 per round (SLIP-0010's P-256 bound),
/// so eight consecutive failures are ~2^-256; the bound exists only to turn an
/// implementation bug into an error instead of a hang.
const MAX_RETRIES: usize = 8;

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac =
        <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC-SHA512 accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn scalar_from_slice(bytes: &[u8]) -> Option<Scalar> {
    Option::from(Scalar::from_repr(*FieldBytes::from_slice(bytes)))
}

fn chain_code_from_slice(bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(bytes);
    out
}

/// Master extended key: `I = HMAC-SHA512("Nist256p1 seed", seed)`; retry with
/// `seed := I` while `I_L` is zero or not a valid scalar.
fn master(seed: &[u8]) -> Result<(Scalar, Zeroizing<[u8; 32]>), KeypairError> {
    let mut data = Zeroizing::new(seed.to_vec());
    for _ in 0..MAX_RETRIES {
        let i = hmac_sha512(CURVE_SEED_KEY, &[data.as_slice()]);
        let (il, ir) = i.split_at(32);
        if let Some(key) = scalar_from_slice(il) {
            if !bool::from(key.is_zero()) {
                return Ok((key, chain_code_from_slice(ir)));
            }
        }
        data = Zeroizing::new(i.to_vec());
    }
    Err(KeypairError::Slip10Derivation)
}

/// CKDpriv: a hardened child hashes `0x00 || ser256(k_par) || ser32(i)`, a
/// normal child `ser_P(point(k_par)) || ser32(i)`; retry with
/// `0x01 || I_R || ser32(i)` while `I_L >= n` or the child key is zero.
fn child(
    parent: &Scalar,
    chain_code: &[u8; 32],
    index: u32,
) -> Result<(Scalar, Zeroizing<[u8; 32]>), KeypairError> {
    let index_bytes = index.to_be_bytes();
    let mut i = if index >= HARDENED {
        let mut parent_bytes = Zeroizing::new([0u8; 32]);
        parent_bytes.copy_from_slice(&parent.to_repr());
        hmac_sha512(chain_code, &[&[0u8], parent_bytes.as_slice(), &index_bytes])
    } else {
        let nonzero = Option::<NonZeroScalar>::from(NonZeroScalar::new(*parent))
            .ok_or(KeypairError::ZeroScalar)?;
        let point = P256PublicKey::from_secret_scalar(&nonzero).to_encoded_point(true);
        hmac_sha512(chain_code, &[point.as_bytes(), &index_bytes])
    };
    for _ in 0..MAX_RETRIES {
        let (il, ir) = i.split_at(32);
        if let Some(tweak) = scalar_from_slice(il) {
            let key = tweak + parent;
            if !bool::from(key.is_zero()) {
                return Ok((key, chain_code_from_slice(ir)));
            }
        }
        let retry = hmac_sha512(chain_code, &[&[1u8], ir, &index_bytes]);
        i = retry;
    }
    Err(KeypairError::Slip10Derivation)
}

/// The extended private key at `path` over `seed`; indices carry the hardened
/// bit themselves.
fn derive(seed: &[u8], path: &[u32]) -> Result<(Scalar, Zeroizing<[u8; 32]>), KeypairError> {
    let (mut key, mut chain_code) = master(seed)?;
    for &index in path {
        let (child_key, child_chain) = child(&key, &chain_code, index)?;
        key = child_key;
        chain_code = child_chain;
    }
    Ok((key, chain_code))
}

/// `SLIP-0010-P256(seed, path)` as a P-256 secret key.
pub(crate) fn derive_secret_key(seed: &[u8], path: &[u32]) -> Result<SecretKey, KeypairError> {
    let (key, _) = derive(seed, path)?;
    let nonzero =
        Option::<NonZeroScalar>::from(NonZeroScalar::new(key)).ok_or(KeypairError::ZeroScalar)?;
    Ok(SecretKey::from(nonzero))
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u32 = HARDENED;

    fn assert_vector(seed_hex: &str, path: &[u32], chain_hex: &str, key_hex: &str, pub_hex: &str) {
        let seed = hex::decode(seed_hex).expect("seed hex");
        let (key, chain_code) = derive(&seed, path).expect("derive");
        assert_eq!(hex::encode(chain_code.as_slice()), chain_hex, "chain code");
        assert_eq!(hex::encode(key.to_repr()), key_hex, "private key");
        let nonzero = Option::<NonZeroScalar>::from(NonZeroScalar::new(key)).expect("non-zero");
        let public = P256PublicKey::from_secret_scalar(&nonzero);
        assert_eq!(
            hex::encode(public.to_encoded_point(true).as_bytes()),
            pub_hex,
            "public key"
        );
    }

    /// SLIP-0010 test vector 1 for nist256p1.
    #[test]
    fn slip10_nist256p1_vector_1() {
        let seed = "000102030405060708090a0b0c0d0e0f";
        assert_vector(
            seed,
            &[],
            "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
            "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
            "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8",
        );
        assert_vector(
            seed,
            &[H],
            "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11",
            "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c",
            "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c",
        );
        assert_vector(
            seed,
            &[H, 1],
            "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c",
            "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129",
            "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844",
        );
        assert_vector(
            seed,
            &[H, 1, 2 | H],
            "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318",
            "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7",
            "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0",
        );
        assert_vector(
            seed,
            &[H, 1, 2 | H, 2],
            "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0",
            "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa",
            "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20",
        );
        assert_vector(
            seed,
            &[H, 1, 2 | H, 2, 1_000_000_000],
            "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
            "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119",
            "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4",
        );
    }

    /// SLIP-0010 test vector 2 for nist256p1.
    #[test]
    fn slip10_nist256p1_vector_2() {
        let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        assert_vector(
            seed,
            &[],
            "96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d",
            "eaa31c2e46ca2962227cf21d73a7ef0ce8b31c756897521eb6c7b39796633357",
            "02c9e16154474b3ed5b38218bb0463e008f89ee03e62d22fdcc8014beab25b48fa",
        );
        assert_vector(
            seed,
            &[0],
            "84e9c258bb8557a40e0d041115b376dd55eda99c0042ce29e81ebe4efed9b86a",
            "d7d065f63a62624888500cdb4f88b6d59c2927fee9e6d0cdff9cad555884df6e",
            "039b6df4bece7b6c81e2adfeea4bcf5c8c8a6e40ea7ffa3cf6e8494c61a1fc82cc",
        );
        assert_vector(
            seed,
            &[0, 2147483647 | H],
            "f235b2bc5c04606ca9c30027a84f353acf4e4683edbd11f635d0dcc1cd106ea6",
            "96d2ec9316746a75e7793684ed01e3d51194d81a42a3276858a5b7376d4b94b9",
            "02f89c5deb1cae4fedc9905f98ae6cbf6cbab120d8cb85d5bd9a91a72f4c068c76",
        );
        assert_vector(
            seed,
            &[0, 2147483647 | H, 1],
            "7c0b833106235e452eba79d2bdd58d4086e663bc8cc55e9773d2b5eeda313f3b",
            "974f9096ea6873a915910e82b29d7c338542ccde39d2064d1cc228f371542bbc",
            "03abe0ad54c97c1d654c1852dfdc32d6d3e487e75fa16f0fd6304b9ceae4220c64",
        );
        assert_vector(
            seed,
            &[0, 2147483647 | H, 1, 2147483646 | H],
            "5794e616eadaf33413aa309318a26ee0fd5163b70466de7a4512fd4b1a5c9e6a",
            "da29649bbfaff095cd43819eda9a7be74236539a29094cd8336b07ed8d4eff63",
            "03cb8cb067d248691808cd6b5a5a06b48e34ebac4d965cba33e6dc46fe13d9b933",
        );
        assert_vector(
            seed,
            &[0, 2147483647 | H, 1, 2147483646 | H, 2],
            "3bfb29ee8ac4484f09db09c2079b520ea5616df7820f071a20320366fbe226a7",
            "bb0a77ba01cc31d77205d51d08bd313b979a71ef4de9b062f8958297e746bd67",
            "020ee02e18967237cf62672983b253ee62fa4dd431f8243bfeccdf39dbe181387f",
        );
    }

    /// SLIP-0010 derivation-retry vector for nist256p1: deriving m/28578'
    /// requires the `0x01 || I_R || ser32(i)` retry.
    #[test]
    fn slip10_nist256p1_derivation_retry() {
        let seed = "000102030405060708090a0b0c0d0e0f";
        assert_vector(
            seed,
            &[28578 | H],
            "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2",
            "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669",
            "02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7",
        );
        assert_vector(
            seed,
            &[28578 | H, 33941],
            "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071",
            "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a",
            "0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120",
        );
    }

    /// SLIP-0010 seed-retry vector for nist256p1: master-key generation
    /// requires the `S := I` retry.
    #[test]
    fn slip10_nist256p1_seed_retry() {
        assert_vector(
            "a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446",
            &[],
            "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c",
            "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f",
            "0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20",
        );
    }
}
