use alloc::vec::Vec;

use crate::OutputDataEncoding;

/// Scheme byte of a PoseidonCtrV1 merge output body. A `merge_transact` or
/// `merge_ring_v2` output publishes it inside
/// [`OutputDataEncoding::VerifiablyEncrypted`] (the merge proof binds the
/// ciphertext), a `merge_ring` output inside [`OutputDataEncoding::Encrypted`]
/// (the ring merge proof does not).
pub const MERGE_OUTPUT_SCHEME: u8 = 6;

/// Bytes of the per-proof salt the merge output ciphertext is padded under.
pub const MERGE_OUTPUT_SALT_LEN: usize = 16;

/// Bytes of the merge output ciphertext: three field elements.
pub const MERGE_OUTPUT_CIPHERTEXT_LEN: usize = 3 * 32;

/// Bytes of the encrypted part of a merge output body: the salt, then the
/// ciphertext.
pub const MERGE_OUTPUT_BODY_LEN: usize = MERGE_OUTPUT_SALT_LEN + MERGE_OUTPUT_CIPHERTEXT_LEN;

/// A merge output's published data, borrowed from the merge instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeOutputDataRef<'a> {
    pub salt: &'a [u8; MERGE_OUTPUT_SALT_LEN],
    pub ciphertext: &'a [[u8; 32]],
    /// Elements written before the salt, the output `ring_data_hash` a ring
    /// merge binds, empty on `merge_transact`.
    pub prefix: &'a [[u8; 32]],
    pub binding: MergeCiphertextBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeCiphertextBinding {
    Proven,
    Unverified,
}

/// The ring data hash leads, as it does in the ring merge instruction data.
pub fn encode_merge_output_data(data: MergeOutputDataRef<'_>) -> Vec<u8> {
    let mut blob = Vec::with_capacity(
        1 + MERGE_OUTPUT_SALT_LEN + 32 * (data.prefix.len() + data.ciphertext.len()),
    );
    blob.push(MERGE_OUTPUT_SCHEME);
    blob.extend_from_slice(data.prefix.as_flattened());
    blob.extend_from_slice(data.salt);
    blob.extend_from_slice(data.ciphertext.as_flattened());
    let encoding = match data.binding {
        MergeCiphertextBinding::Unverified => OutputDataEncoding::Encrypted(blob),
        MergeCiphertextBinding::Proven => OutputDataEncoding::VerifiablyEncrypted(blob),
    };
    borsh::to_vec(&encoding).expect("borsh serialization into a Vec cannot fail")
}

/// Splits a merge output body (after the scheme byte) into the ring merge
/// output `ring_data_hash` and the encrypted part, `salt || ciphertext`. `None`
/// for any other length.
pub fn split_merge_output_body(body: &[u8]) -> Option<(Option<&[u8; 32]>, &[u8])> {
    match body.len() {
        MERGE_OUTPUT_BODY_LEN => Some((None, body)),
        len if len == 32 + MERGE_OUTPUT_BODY_LEN => {
            let (ring_data_hash, encrypted) = body.split_at(32);
            Some((Some(ring_data_hash.try_into().ok()?), encrypted))
        }
        _ => None,
    }
}
