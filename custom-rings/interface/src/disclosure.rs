//! Byte layout of the auditor disclosure. The circuit packs the plaintext into
//! 31-byte big-endian chunks and masks each chunk with the disclosure stream.

use zolana_hasher::primitives::{pack_be_chunks, PACK_BE_CHUNK_BYTES};

/// The hidden owner's Ed25519 key, zero outside an anonymous ring.
pub const DISCLOSURE_SENDER_LEN: usize = 32;
/// `tree_id(2) || leaf_index(8) || amount(8) || asset(32) || blinding(32)`,
/// zero padded.
pub const DISCLOSURE_INPUT_LEN: usize = 96;
/// `identity_tag(1) || identity_key(32) || nullifier_pk(32) || amount(8) ||
/// asset(32) || blinding(32) || data_hash(32) || ring_data_hash(32)`, zero padded.
pub const DISCLOSURE_OUTPUT_LEN: usize = 224;
pub const AUDIT_INPUT_SLOTS: usize = 4;
pub const AUDIT_OUTPUT_SLOTS: usize = 4;

/// The published slots of one disclosure. Inputs are disclosed only in an
/// anonymous ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisclosureShape {
    pub anonymous: bool,
    pub inputs: usize,
    pub outputs: usize,
}

impl DisclosureShape {
    /// `None` outside the slot counts the circuit discloses.
    pub const fn plaintext_len(self) -> Option<usize> {
        if self.outputs == 0 || self.outputs > AUDIT_OUTPUT_SLOTS {
            return None;
        }
        let inputs = if self.anonymous {
            if self.inputs == 0 || self.inputs > AUDIT_INPUT_SLOTS {
                return None;
            }
            self.inputs
        } else {
            0
        };
        Some(
            DISCLOSURE_SENDER_LEN
                + inputs * DISCLOSURE_INPUT_LEN
                + self.outputs * DISCLOSURE_OUTPUT_LEN,
        )
    }

    pub const fn field_count(self) -> Option<usize> {
        match self.plaintext_len() {
            Some(len) => Some(pack_be_chunks(len)),
            None => None,
        }
    }
}

/// Splits the plaintext into fields exactly as the circuit packs it.
pub fn pack_disclosure(plaintext: &[u8]) -> Vec<[u8; 32]> {
    plaintext
        .chunks(PACK_BE_CHUNK_BYTES)
        .map(|chunk| {
            let mut field = [0u8; 32];
            field[32 - chunk.len()..].copy_from_slice(chunk);
            field
        })
        .collect()
}

/// Inverts [`pack_disclosure`], `None` when a field holds bytes outside its chunk.
pub fn unpack_disclosure(fields: &[[u8; 32]], len: usize) -> Option<Vec<u8>> {
    if fields.len() != pack_be_chunks(len) {
        return None;
    }
    let mut plaintext = Vec::with_capacity(len);
    for (index, field) in fields.iter().enumerate() {
        let chunk = (len - index * PACK_BE_CHUNK_BYTES).min(PACK_BE_CHUNK_BYTES);
        let (pad, bytes) = field.split_at(32 - chunk);
        if pad.iter().any(|byte| *byte != 0) {
            return None;
        }
        plaintext.extend_from_slice(bytes);
    }
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_count_follows_the_mode_and_the_published_slots() {
        let shape = |anonymous, inputs, outputs| DisclosureShape {
            anonymous,
            inputs,
            outputs,
        };
        assert_eq!(shape(false, 4, 2).field_count(), Some(16));
        assert_eq!(shape(false, 0, 1).field_count(), Some(9));
        assert_eq!(shape(true, 2, 2).field_count(), Some(22));
        assert_eq!(shape(true, 3, 4).field_count(), Some(40));
        assert_eq!(shape(true, 4, 2).field_count(), Some(28));
        assert_eq!(shape(true, 0, 2).field_count(), None);
        assert_eq!(shape(true, 5, 2).field_count(), None);
        assert_eq!(shape(false, 2, 0).field_count(), None);
        assert_eq!(shape(false, 2, 5).field_count(), None);
    }

    #[test]
    fn unpacking_rejects_bytes_outside_a_chunk() {
        let plaintext: Vec<u8> = (0..70).collect();
        let fields = pack_disclosure(&plaintext);
        assert_eq!(fields.len(), 3);
        assert_eq!(
            unpack_disclosure(&fields, 70).as_deref(),
            Some(&plaintext[..])
        );
        assert_eq!(unpack_disclosure(&fields, 94), None);
        let mut widened = fields.clone();
        widened[2][23] = 1;
        assert_eq!(unpack_disclosure(&widened, 70), None);
        let mut widened = fields;
        widened[0][0] = 1;
        assert_eq!(unpack_disclosure(&widened, 70), None);
    }
}
