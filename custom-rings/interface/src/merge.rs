use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_hash_chain_from_slice},
    primitives::{hash_bytes, pack_be, pack_be_chunks, right_align},
    HasherError,
};
use zolana_interface::instruction::instruction_data::merge_transact::MergeTransactIxData;

use crate::{
    bytes::Bytes, error::CustomRingError, CustomRingProof, AUDIT_CIPHERTEXT_LEN,
    TAGGED_X25519_KEY_LEN,
};

/// Owner key, nullifier pk, mint, amount and output blinding ahead of the input commitments.
pub const MERGE_DISCLOSURE_HEADER_LEN: usize = 32 + 32 + 32 + 8 + 32;
pub const MERGE_DISCLOSURE_INFO: &[u8; 10] = b"CRING/mrg1";
pub const MERGE_ANONYMOUS_PUBLIC_INPUT_ELEMENTS: usize = 12;
const MERGE_ANONYMOUS_DOMAIN: &[u8; 4] = b"CRMG";

/// SPP merge widths whose anonymous merge, disclosure and nullifier accounts fit one v1 transaction.
pub const ANONYMOUS_MERGE_WIDTHS: [usize; 2] = [8, 24];
/// `expiry_unix_ts u64 || proof.a` open the SPP merge body ahead of `proof.b`.
const MERGE_B_OFFSET: usize = core::mem::size_of::<u64>() + 32;

/// Plaintext bytes of the disclosure of a merge of `width` circuit slots.
pub const fn merge_disclosure_len(width: usize) -> usize {
    MERGE_DISCLOSURE_HEADER_LEN + 32 * width
}

/// Masked fields of the disclosure, the plaintext zero padded to whole 31-byte chunks.
pub const fn merge_disclosure_field_count(width: usize) -> usize {
    pack_be_chunks(merge_disclosure_len(width))
}

/// The SPP merge body with `proof.b` compressed, the program resolves `registry_root_index` to its root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingMergeIxData {
    pub registry_root_index: u8,
    pub output_ring_data_hash: [u8; 32],
    /// Present exactly in an anonymous ring, whose SPP merge skips the escrow key.
    pub disclosure: Option<MergeDisclosure>,
    pub merge: MergeTransactIxData,
}

/// The auditor's opening of an anonymous merge, proven against the SPP merge it precedes.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeDisclosure {
    pub proof: CustomRingProof,
    pub eph_pk: [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub fields: Vec<[u8; 32]>,
}

#[cfg(not(target_os = "solana"))]
impl CustomRingMergeIxData {
    /// The bytes after the instruction tag.
    pub fn serialize(&self) -> Result<Vec<u8>, CustomRingError> {
        let body = self.merge.serialize().map_err(invalid_data)?;
        let (head, rest) = body
            .split_at_checked(MERGE_B_OFFSET)
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let tail = rest
            .get(self.merge.proof.b.len()..)
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let b = solana_bn254::compression::prelude::alt_bn128_g2_compress_be(&self.merge.proof.b)
            .map_err(|_| CustomRingError::InvalidSppProofPoint)?;
        Ok([
            &[self.registry_root_index][..],
            &self.output_ring_data_hash,
            &wincode::serialize(&self.disclosure).map_err(invalid_data)?,
            head,
            &b,
            tail,
        ]
        .concat())
    }
}

#[cfg(not(target_os = "solana"))]
fn invalid_data<E>(_: E) -> CustomRingError {
    CustomRingError::InvalidInstructionData
}

/// Borrowed view of the compact request, the SPP merge body read around its compressed `b`.
pub struct CustomRingMergeIxDataRef<'a> {
    pub registry_root_index: u8,
    pub output_ring_data_hash: &'a [u8; 32],
    pub disclosure: Option<MergeDisclosureRef<'a>>,
    head: &'a [u8; MERGE_B_OFFSET],
    compressed_b: &'a [u8; 64],
    tail: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeDisclosureRef<'a> {
    pub proof: &'a CustomRingProof,
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub fields: &'a [[u8; 32]],
}

impl<'a> CustomRingMergeIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidInstructionData);
        let registry_root_index = bytes.byte()?;
        let output_ring_data_hash = bytes.array()?;
        let disclosure = MergeDisclosureRef::read(&mut bytes)?;
        let head = bytes.array()?;
        let compressed_b = bytes.array()?;
        Ok(Self {
            registry_root_index,
            output_ring_data_hash,
            disclosure,
            head,
            compressed_b,
            tail: bytes.rest(),
        })
    }

    /// The SPP merge body the program forwards, `proof.b` decompressed, SPP's parser reads the rest.
    pub fn spp_merge_body(&self) -> Result<Vec<u8>, CustomRingError> {
        let b = groth16_solana::decompression::decompress_g2(self.compressed_b)
            .map_err(|_| CustomRingError::InvalidSppProofPoint)?;
        Ok([&self.head[..], &b, self.tail].concat())
    }
}

impl<'a> MergeDisclosureRef<'a> {
    /// The wincode option ahead of the SPP body.
    fn read(bytes: &mut Bytes<'a>) -> Result<Option<Self>, CustomRingError> {
        match bytes.byte()? {
            0 => return Ok(None),
            1 => {}
            _ => return Err(CustomRingError::InvalidInstructionData),
        }
        let proof = bytes.pod()?;
        let eph_pk = bytes.array()?;
        let ciphertext = bytes.array()?;
        let count = bytes.byte()?;
        Ok(Some(Self {
            proof,
            eph_pk,
            ciphertext,
            fields: bytes.fields(usize::from(count))?,
        }))
    }
}

/// The anonymous merge statement, `prover/server/custom_rings/circuits/merge/circuit.go`.
pub struct MergeAnonymousPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub output_utxo_hash: &'a [u8; 32],
    pub first_nullifier: &'a [u8; 32],
    /// `hash_bytes` of the ring program id, the value the merged notes commit.
    pub ring_id: &'a [u8; 32],
    pub auditor_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    /// The SPP output ciphertext salt, the merge pad reuses it.
    pub salt: &'a [u8; 16],
    pub fields: &'a [[u8; 32]],
}

impl MergeAnonymousPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&self.elements()?)
    }

    pub fn elements(
        &self,
    ) -> Result<[[u8; 32]; MERGE_ANONYMOUS_PUBLIC_INPUT_ELEMENTS], HasherError> {
        let [auditor_lo, auditor_hi] = pack_be(self.auditor_pk);
        let [eph_lo, eph_hi] = pack_be(self.eph_pk);
        Ok([
            right_align(MERGE_ANONYMOUS_DOMAIN),
            *self.private_tx_hash,
            *self.output_utxo_hash,
            *self.first_nullifier,
            *self.ring_id,
            auditor_lo,
            auditor_hi,
            eph_lo,
            eph_hi,
            hash_bytes(self.ciphertext)?,
            right_align(self.salt),
            create_hash_chain_4_from_slice(self.fields)?,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_statement_matches_the_go_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/ring-merge-anonymous.json"
        ))
        .unwrap();
        let bytes = |value: &serde_json::Value| -> Vec<u8> {
            hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
        };
        let array = |value: &serde_json::Value| -> [u8; 32] { bytes(value).try_into().unwrap() };
        let request = &vector["request"];
        let fields: Vec<[u8; 32]> = vector["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(array)
            .collect();
        let statement = MergeAnonymousPublicInput {
            private_tx_hash: &array(&request["privateTxHash"]),
            output_utxo_hash: &array(&request["outputUtxoHash"]),
            first_nullifier: &array(&request["firstNullifier"]),
            ring_id: &array(&request["ringProgramId"]),
            auditor_pk: &bytes(&vector["auditor_pk"]).try_into().unwrap(),
            eph_pk: &bytes(&vector["eph_pk"]).try_into().unwrap(),
            ciphertext: &array(&vector["envelope_ciphertext"]),
            salt: &bytes(&vector["salt"]).try_into().unwrap(),
            fields: &fields,
        };
        let elements: Vec<[u8; 32]> = vector["elements"]
            .as_array()
            .unwrap()
            .iter()
            .map(array)
            .collect();
        assert_eq!(statement.elements().unwrap().to_vec(), elements);
        assert_eq!(
            statement.hash().unwrap(),
            array(&vector["public_input_hash"])
        );
        assert_eq!(fields.len(), merge_disclosure_field_count(8));
    }

    #[test]
    fn disclosure_widths_match_the_go_circuit() {
        assert_eq!([8, 24, 52].map(merge_disclosure_field_count), [13, 30, 59]);
    }
}
