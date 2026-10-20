use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_hash_chain_from_slice},
    primitives::{hash_bytes, pack_be_chunks, right_align},
    HasherError,
};
use zolana_interface::instruction::instruction_data::merge_transact::{
    MergeTransactIxData, MergeTransactIxDataRef,
};

use crate::{pack_2fe, CustomRingProof, AUDIT_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN};

/// Owner key, nullifier pk, mint, amount and output blinding ahead of the input commitments.
pub const MERGE_DISCLOSURE_HEADER_LEN: usize = 32 + 32 + 32 + 8 + 32;
pub const MERGE_DISCLOSURE_INFO: &[u8; 10] = b"CRING/mrg1";
pub const MERGE_ANONYMOUS_PUBLIC_INPUT_ELEMENTS: usize = 13;
const MERGE_ANONYMOUS_DOMAIN: &[u8; 4] = b"CRMG";

/// SPP merge widths whose anonymous merge, disclosure and nullifier accounts fit one v1 transaction.
pub const ANONYMOUS_MERGE_WIDTHS: [usize; 2] = [8, 24];

/// Plaintext bytes of the disclosure of a merge of `width` circuit slots.
pub const fn merge_disclosure_len(width: usize) -> usize {
    MERGE_DISCLOSURE_HEADER_LEN + 32 * width
}

/// Masked fields of the disclosure, the plaintext zero padded to whole 31-byte chunks.
pub const fn merge_disclosure_field_count(width: usize) -> usize {
    pack_be_chunks(merge_disclosure_len(width))
}

/// Compact ring-program merge request. The ring program replaces the root
/// history index with the authenticated root before forwarding to SPP.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
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

impl CustomRingMergeIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Borrowed view of the compact request. The merge body and proof alias the
/// instruction buffer, including the variable-length nullifier list.
pub struct CustomRingMergeIxDataRef<'a> {
    pub registry_root_index: u8,
    pub output_ring_data_hash: &'a [u8; 32],
    pub disclosure: Option<MergeDisclosureRef<'a>>,
    pub merge: MergeTransactIxDataRef<'a>,
    /// Exact serialized SPP merge body, reused when forwarding the instruction.
    pub merge_body: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeDisclosureRef<'a> {
    pub proof: &'a CustomRingProof,
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub fields: &'a [[u8; 32]],
}

impl<'a> CustomRingMergeIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let (registry_root_index, body) = data
            .split_first()
            .ok_or(wincode::ReadError::Custom("missing root index"))?;
        let (output_ring_data_hash, body) = body
            .split_first_chunk::<32>()
            .ok_or(wincode::ReadError::Custom("missing ring data hash"))?;
        let (disclosure, body) = MergeDisclosureRef::parse(body)?;
        Ok(Self {
            registry_root_index: *registry_root_index,
            output_ring_data_hash,
            disclosure,
            merge: MergeTransactIxDataRef::from_bytes(body)?,
            merge_body: body,
        })
    }
}

impl<'a> MergeDisclosureRef<'a> {
    /// Reads the wincode option ahead of the SPP body.
    fn parse(data: &'a [u8]) -> Result<(Option<Self>, &'a [u8]), wincode::ReadError> {
        let truncated = || wincode::ReadError::Custom("truncated merge disclosure");
        let (present, data) = data.split_first().ok_or_else(truncated)?;
        match present {
            0 => return Ok((None, data)),
            1 => {}
            _ => return Err(wincode::ReadError::Custom("invalid merge disclosure tag")),
        }
        let (proof, data) = data
            .split_first_chunk::<{ CustomRingProof::SIZE }>()
            .ok_or_else(truncated)?;
        let (eph_pk, data) = data.split_first_chunk().ok_or_else(truncated)?;
        let (ciphertext, data) = data.split_first_chunk().ok_or_else(truncated)?;
        let (count, data) = data.split_first().ok_or_else(truncated)?;
        let (fields, data) = data
            .split_at_checked(32 * usize::from(*count))
            .ok_or_else(truncated)?;
        Ok((
            Some(Self {
                proof: bytemuck::from_bytes(proof),
                eph_pk,
                ciphertext,
                fields: fields.as_chunks().0,
            }),
            data,
        ))
    }
}

/// The anonymous merge statement, `prover/server/custom_rings/circuits/merge/circuit.go`.
pub struct MergeAnonymousPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub output_utxo_hash: &'a [u8; 32],
    pub first_nullifier: &'a [u8; 32],
    /// `hash_bytes` of the ring program id, the value the merged notes commit.
    pub ring_id: &'a [u8; 32],
    pub member_registry_root: &'a [u8; 32],
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
        let auditor = pack_2fe(self.auditor_pk);
        let eph = pack_2fe(self.eph_pk);
        Ok([
            right_align(MERGE_ANONYMOUS_DOMAIN),
            *self.private_tx_hash,
            *self.output_utxo_hash,
            *self.first_nullifier,
            *self.ring_id,
            *self.member_registry_root,
            auditor.lo,
            auditor.hi,
            eph.lo,
            eph.hi,
            hash_bytes(self.ciphertext)?,
            right_align(self.salt),
            create_hash_chain_4_from_slice(self.fields)?,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlainGroth16Proof;
    use zolana_interface::instruction::instruction_data::merge_transact::{
        MergeOutputEncryption, MergeProof,
    };

    fn request(disclosure: Option<MergeDisclosure>) -> CustomRingMergeIxData {
        CustomRingMergeIxData {
            registry_root_index: 3,
            output_ring_data_hash: [8; 32],
            disclosure,
            merge: MergeTransactIxData {
                expiry_unix_ts: 42,
                proof: MergeProof::zeroed(),
                output_utxo_hash: [1; 32],
                output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                    salt: [2; 16],
                    ciphertext: [[3; 32]; 3],
                },
                private_tx_hash: [4; 32],
                nullifiers: vec![[5; 32]],
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
                cache_slot: None,
            },
        }
    }

    #[test]
    fn the_view_reads_the_owned_layout_and_keeps_the_exact_spp_body() {
        let disclosure = MergeDisclosure {
            proof: CustomRingProof {
                groth16: PlainGroth16Proof {
                    proof_a: [9; 32],
                    proof_b: [10; 64],
                    proof_c: [11; 32],
                },
                commitment: [12; 32],
                commitment_pok: [13; 32],
            },
            eph_pk: [4; 33],
            ciphertext: [14; 32],
            fields: vec![[15; 32]; merge_disclosure_field_count(8)],
        };
        for disclosure in [None, Some(disclosure)] {
            let request = request(disclosure);
            let mut bytes = request.serialize().unwrap();
            let view = CustomRingMergeIxDataRef::from_bytes(&bytes).unwrap();
            assert_eq!(view.registry_root_index, 3);
            assert_eq!(view.output_ring_data_hash, &[8; 32]);
            assert_eq!(view.merge.nullifiers, request.merge.nullifiers);
            assert_eq!(view.merge_body, request.merge.serialize().unwrap());
            match (&view.disclosure, &request.disclosure) {
                (Some(view), Some(owned)) => {
                    assert_eq!(view.proof, &owned.proof);
                    assert_eq!(view.eph_pk, &owned.eph_pk);
                    assert_eq!(view.ciphertext, &owned.ciphertext);
                    assert_eq!(view.fields, owned.fields);
                }
                (None, None) => {}
                _ => panic!("the view changed the disclosure presence"),
            }
            bytes.push(0);
            assert!(CustomRingMergeIxDataRef::from_bytes(&bytes).is_err());
        }
        let mut invalid = request(None).serialize().unwrap();
        invalid[33] = 2;
        assert!(CustomRingMergeIxDataRef::from_bytes(&invalid).is_err());
    }

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
            member_registry_root: &array(&request["memberRegistryRoot"]),
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
