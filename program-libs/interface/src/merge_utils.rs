//! Canonical `no_std`-compatible merge field math, used by the on-chain
//! `merge_transact` instruction. Every function mirrors the merge circuit
//! (`prover/server/circuits/spp_merge`) byte-for-byte; the client cross-checks the
//! same vectors via `zolana-keypair`, so byte order is load-bearing.

use light_hasher::{Hasher, HasherError, Poseidon};

const P256_PUBKEY_LEN: usize = 33;

/// `pk_field` of a SEC1-compressed P256 public key, matching the circuit's
/// `Poseidon(bool_fe(y_is_odd), Poseidon(x_low_128, x_high_128))`. The compressed
/// encoding is `prefix(1) || x(32)`, with `prefix == 0x02` for even y and `0x03`
/// for odd y; `x_high_128` is the high 16 bytes of `x` and `x_low_128` the low 16,
/// each right-aligned, matching the keypair `hash_field` split.
pub fn pk_field_compressed(compressed: &[u8; P256_PUBKEY_LEN]) -> Result<[u8; 32], HasherError> {
    let prefix = compressed[0];
    if prefix != 0x02 && prefix != 0x03 {
        return Err(HasherError::InvalidInputLength(usize::from(prefix), 0));
    }
    let y_is_odd = prefix == 0x03;
    let x = compressed
        .get(1..P256_PUBKEY_LEN)
        .ok_or(HasherError::InvalidInputLength(0, P256_PUBKEY_LEN - 1))?;
    let high = x.get(0..16).ok_or(HasherError::InvalidInputLength(0, 16))?;
    let low = x.get(16..32).ok_or(HasherError::InvalidInputLength(16, 32))?;
    let x_hash = Poseidon::hashv(&[&right_align_16(low), &right_align_16(high)])?;
    Poseidon::hashv(&[&bool_fe(y_is_odd), &x_hash])
}

/// `pack33` mirrors `Pack33To2FECircuit`: `lo[1..32] = b[0..31]` and the trailing
/// two bytes go into `hi[30..32]`. Returns `(lo, hi)`.
pub fn pack33(b: &[u8; P256_PUBKEY_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    if let (Some(dst), Some(src)) = (lo.get_mut(1..32), b.get(0..31)) {
        dst.copy_from_slice(src);
    }
    let mut hi = [0u8; 32];
    if let Some(byte) = b.get(31) {
        hi[30] = *byte;
    }
    if let Some(byte) = b.get(32) {
        hi[31] = *byte;
    }
    (lo, hi)
}

/// Poseidon hash of a ciphertext, mirroring `PoseidonHash(PackBytesBE(ct, 16))`:
/// 16-byte big-endian chunks right-aligned into field elements (last chunk may be
/// short), then `Poseidon::hashv` over all chunks.
pub fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], HasherError> {
    let chunks: Vec<[u8; 32]> = ciphertext.chunks(16).map(right_align_16).collect();
    let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    Poseidon::hashv(&refs)
}

fn right_align_16(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    if let (Some(dst), Some(src)) = (out.get_mut(32 - len..32), bytes.get(..len)) {
        dst.copy_from_slice(src);
    }
    out
}

fn bool_fe(b: bool) -> [u8; 32] {
    let mut fe = [0u8; 32];
    if b {
        fe[31] = 1;
    }
    fe
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
