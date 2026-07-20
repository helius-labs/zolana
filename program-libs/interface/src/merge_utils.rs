//! Canonical `no_std`-compatible merge field math, used by the on-chain
//! `merge_transact` instruction. Every function mirrors the merge circuit
//! (`prover/server/circuits/spp_merge`) byte-for-byte; the client cross-checks the
//! same vectors via `zolana-keypair`, so byte order is load-bearing.

pub use zolana_hasher::primitives::pack_be;
use zolana_hasher::{primitives::hash_bytes, HasherError};

const P256_PUBKEY_LEN: usize = 33;

/// Validates the SEC1 prefix (`0x02` even y, `0x03` odd y) and returns the
/// 32-byte x-coordinate.
fn parse_compressed(compressed: &[u8; P256_PUBKEY_LEN]) -> Result<[u8; 32], HasherError> {
    let prefix = compressed[0];
    if prefix != 0x02 && prefix != 0x03 {
        return Err(HasherError::InvalidInputLength(usize::from(prefix), 0));
    }
    let mut x = [0u8; 32];
    if let Some(src) = compressed.get(1..P256_PUBKEY_LEN) {
        x.copy_from_slice(src);
    }
    Ok(x)
}

/// Viewing-key `pk_field`: `hash_bytes(sec1_compressed)` over the full 33-byte
/// SEC1 point (parity prefix included), so it identifies the exact point used for
/// ECDH and is distinct from the 32-byte owner encoding (spec: Pubkey Field
/// Encoding). The prefix is validated first.
pub fn pk_field_compressed(compressed: &[u8; P256_PUBKEY_LEN]) -> Result<[u8; 32], HasherError> {
    parse_compressed(compressed)?;
    hash_bytes(compressed)
}

/// Owner-identity proof-input hash: `hash_bytes(x)` over the 32-byte x-coordinate
/// only (the y-parity is carried in the encrypted data, not the owner identity),
/// so a P256 owner has the same shape as an Ed25519 owner. Matches the circuit
/// `OwnerPkFieldGadget` and keypair `PublicKey::owner_proof_input_hash`.
pub fn owner_proof_input_hash_compressed(
    compressed: &[u8; P256_PUBKEY_LEN],
) -> Result<[u8; 32], HasherError> {
    let x = parse_compressed(compressed)?;
    hash_bytes(&x)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec1(prefix: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = prefix;
        for (i, b) in pk.iter_mut().enumerate().skip(1) {
            *b = i as u8;
        }
        pk
    }

    #[test]
    fn pk_field_rejects_bad_prefix() {
        let mut pk = sec1(0x02);
        pk[0] = 0x04;
        assert!(pk_field_compressed(&pk).is_err());
        assert!(owner_proof_input_hash_compressed(&pk).is_err());
        pk[0] = 0x00;
        assert!(pk_field_compressed(&pk).is_err());
    }

    #[test]
    fn viewing_pk_field_depends_on_parity() {
        // Viewing key hashes the full SEC1 point, so parity changes the field.
        let even = sec1(0x02);
        let mut odd = even;
        odd[0] = 0x03;
        assert_ne!(
            pk_field_compressed(&even).unwrap(),
            pk_field_compressed(&odd).unwrap()
        );
    }

    #[test]
    fn owner_proof_input_hash_ignores_parity() {
        // Owner identity hashes only x, so parity does not change the field.
        let even = sec1(0x02);
        let mut odd = even;
        odd[0] = 0x03;
        assert_eq!(
            owner_proof_input_hash_compressed(&even).unwrap(),
            owner_proof_input_hash_compressed(&odd).unwrap()
        );
    }

    #[test]
    fn owner_and_viewing_fields_differ() {
        // Distinct domain tags separate the two encodings even over the same x.
        let pk = sec1(0x02);
        assert_ne!(
            owner_proof_input_hash_compressed(&pk).unwrap(),
            pk_field_compressed(&pk).unwrap()
        );
    }
}
