//! Canonical `no_std`-compatible merge field math, used by the on-chain
//! `merge_transact` instruction. Every function mirrors the merge circuit
//! (`prover/server/circuits/spp_merge`) byte-for-byte; the client cross-checks the
//! same vectors via `zolana-keypair`, so byte order is load-bearing.

pub use zolana_hasher::primitives::{ciphertext_hash, pack33};
use zolana_hasher::{
    primitives::{bool_fe, hash_field},
    Hasher, HasherError, Poseidon,
};

const P256_PUBKEY_LEN: usize = 33;

/// Validates the SEC1 prefix (`0x02` even y, `0x03` odd y) and returns
/// `(y_is_odd, x)`.
fn parse_compressed(
    compressed: &[u8; P256_PUBKEY_LEN],
) -> Result<(bool, [u8; 32]), HasherError> {
    let prefix = compressed[0];
    if prefix != 0x02 && prefix != 0x03 {
        return Err(HasherError::InvalidInputLength(usize::from(prefix), 0));
    }
    let mut x = [0u8; 32];
    if let Some(src) = compressed.get(1..P256_PUBKEY_LEN) {
        x.copy_from_slice(src);
    }
    Ok((prefix == 0x03, x))
}

/// `pk_field` of a SEC1-compressed P256 public key, matching the circuit's
/// `Poseidon(bool_fe(y_is_odd), hash_field(x))` (spec: Pubkey Field Encoding,
/// viewing keys).
pub fn pk_field_compressed(compressed: &[u8; P256_PUBKEY_LEN]) -> Result<[u8; 32], HasherError> {
    let (y_is_odd, x) = parse_compressed(compressed)?;
    let x_hash = hash_field(&x)?;
    Poseidon::hashv(&[&bool_fe(y_is_odd), &x_hash])
}

/// Owner-identity `pk_field` of a SEC1-compressed P256 public key: the parity-free
/// `hash_field(x)` (the y-parity is carried in the encrypted data, not the owner
/// identity), so a P256 owner has the same pk_field shape as an ed25519 owner.
/// Matches the circuit `OwnerPkFieldGadget` and keypair
/// `PublicKey::owner_pk_field`. The compressed prefix is still validated.
pub fn owner_pk_field_compressed(
    compressed: &[u8; P256_PUBKEY_LEN],
) -> Result<[u8; 32], HasherError> {
    let (_, x) = parse_compressed(compressed)?;
    hash_field(&x)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_to_33(s: &str) -> [u8; 33] {
        let v = hex_to_vec(s);
        let mut out = [0u8; 33];
        out.copy_from_slice(&v);
        out
    }

    // Cross-checks `pack33` and `ciphertext_hash` against the `matches_circuit_vector`
    // fixture in `sdk-libs/keypair/src/merge.rs`, which is itself validated against
    // the Go circuit via `test.IsSolved`.
    const TX_VIEWING_PK_HEX: &str =
        "02fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003eac8";
    const CIPHERTEXT_HEX: &str = "d52cccc7053c653d83c840fcb12c3a1dd6ac2263a9f4c705d784dfd894234b6b5271590160bddbb7191a0eeb96646aa5397e0acb27b605aec6f1ceadcd2726cab1a675d511f202";
    const CT_HASH_HEX: &str = "2418c4f8d103a80bcc365a28f6172e7cd9cbfe71a301c19f775a64187ed2f453";

    #[test]
    fn ciphertext_hash_matches_circuit_vector() {
        let ciphertext = hex_to_vec(CIPHERTEXT_HEX);
        let got = ciphertext_hash(&ciphertext).unwrap();
        assert_eq!(got.to_vec(), hex_to_vec(CT_HASH_HEX));
    }

    #[test]
    fn pack33_low_high_split() {
        let pk = hex_to_33(TX_VIEWING_PK_HEX);
        let (lo, hi) = pack33(&pk);
        assert_eq!(lo[0], 0);
        assert_eq!(&lo[1..32], &pk[0..31]);
        assert_eq!(&hi[0..30], &[0u8; 30]);
        assert_eq!(hi[30], pk[31]);
        assert_eq!(hi[31], pk[32]);
    }

    #[test]
    fn pk_field_rejects_bad_prefix() {
        let mut pk = [0u8; 33];
        pk[0] = 0x04;
        assert!(pk_field_compressed(&pk).is_err());
        pk[0] = 0x00;
        assert!(pk_field_compressed(&pk).is_err());
    }

    #[test]
    fn pk_field_distinguishes_parity() {
        let mut even = hex_to_33(TX_VIEWING_PK_HEX);
        even[0] = 0x02;
        let mut odd = even;
        odd[0] = 0x03;
        let even_hash = pk_field_compressed(&even).unwrap();
        let odd_hash = pk_field_compressed(&odd).unwrap();
        assert_ne!(even_hash, odd_hash);
        assert_eq!(even_hash, pk_field_compressed(&even).unwrap());
    }
}
