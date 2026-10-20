//! Host mirror of the anonymous merge disclosure (`prover/server/custom_rings/circuits/merge`).

use custom_ring_interface::{
    merge_disclosure_field_count, merge_disclosure_len, pack_disclosure, unpack_disclosure,
    AUDIT_CIPHERTEXT_LEN, MERGE_DISCLOSURE_HEADER_LEN, MERGE_DISCLOSURE_INFO,
};
use zeroize::Zeroizing;
use zolana_hasher::primitives::PACK_BE_CHUNK_BYTES;
use zolana_interface::instruction::instruction_data::merge_transact::MERGE_SUPPORTED_INPUT_COUNTS;
use zolana_keypair::{random_salt, X25519Keypair, X25519Pubkey};

use super::{domain_stream, open_stream, seal_stream, Result, MERGE_DISCLOSURE_DOMAIN};
use crate::AuditError;

/// What an anonymous merge discloses, enough to recompute its output commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeOpening {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub mint: [u8; 32],
    pub amount: u64,
    pub output_blinding: [u8; 32],
    /// One per circuit slot, zero for padding.
    pub input_commitments: Vec<[u8; 32]>,
}

/// The sealed disclosure key and masked fields of one merge, with the secrets its proof witnesses.
pub struct MergeDisclosureEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub disclosure_key: Zeroizing<[u8; 32]>,
    pub eph_pk: X25519Pubkey,
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
    pub fields: Vec<[u8; 32]>,
}

impl MergeOpening {
    /// The circuit packs whole 31-byte chunks, so the plaintext is zero padded to a chunk boundary.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let width = self.input_commitments.len();
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            merge_disclosure_field_count(width) * PACK_BE_CHUNK_BYTES,
        ));
        plaintext.extend_from_slice(&self.owner_key);
        plaintext.extend_from_slice(&self.nullifier_pk);
        plaintext.extend_from_slice(&self.mint);
        plaintext.extend_from_slice(&self.amount.to_be_bytes());
        plaintext.extend_from_slice(&self.output_blinding);
        for commitment in &self.input_commitments {
            plaintext.extend_from_slice(commitment);
        }
        plaintext.resize(merge_disclosure_field_count(width) * PACK_BE_CHUNK_BYTES, 0);
        plaintext
    }

    fn decode(plaintext: &[u8], width: usize) -> Result<Self> {
        let (opening, padding) = plaintext
            .split_at_checked(merge_disclosure_len(width))
            .ok_or(AuditError::DisclosureShape)?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(AuditError::DisclosurePadding);
        }
        let (header, commitments) = opening.split_at(MERGE_DISCLOSURE_HEADER_LEN);
        let take = |at: usize| -> [u8; 32] {
            let mut value = [0; 32];
            value.copy_from_slice(&header[at..at + 32]);
            value
        };
        let mut amount = [0; 8];
        amount.copy_from_slice(&header[96..104]);
        Ok(Self {
            owner_key: take(0),
            nullifier_pk: take(32),
            mint: take(64),
            amount: u64::from_be_bytes(amount),
            output_blinding: take(104),
            input_commitments: commitments.as_chunks::<32>().0.to_vec(),
        })
    }
}

impl MergeDisclosureEncryption {
    /// `salt` is the SPP merge output salt, the statement binds the pad to it.
    pub fn new(opening: &MergeOpening, salt: [u8; 16], auditor_pk: &X25519Pubkey) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        key[..16].copy_from_slice(&random_salt());
        key[16..].copy_from_slice(&random_salt());
        Self::seal(opening, salt, auditor_pk, X25519Keypair::new(), key)
    }

    fn seal(
        opening: &MergeOpening,
        salt: [u8; 16],
        auditor_pk: &X25519Pubkey,
        ephemeral: X25519Keypair,
        disclosure_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        if !MERGE_SUPPORTED_INPUT_COUNTS.contains(&opening.input_commitments.len()) {
            return Err(AuditError::DisclosureShape);
        }
        let mut ciphertext = *disclosure_key;
        seal_stream(
            &ephemeral,
            auditor_pk,
            MERGE_DISCLOSURE_INFO,
            &mut ciphertext,
        )?;
        let fields = domain_stream(
            MERGE_DISCLOSURE_DOMAIN,
            &disclosure_key,
            salt,
            &pack_disclosure(&opening.encode()),
            true,
        )?;
        Ok(Self {
            ephemeral_sk: ephemeral.secret_bytes(),
            disclosure_key,
            eph_pk: ephemeral.pubkey(),
            ciphertext,
            fields,
        })
    }
}

/// Opens a disclosure the ring program verified, the caller checks the opening against the settled output.
pub fn open_merge_disclosure(
    auditor: &X25519Keypair,
    eph_pk: &X25519Pubkey,
    ciphertext: &[u8; AUDIT_CIPHERTEXT_LEN],
    salt: [u8; 16],
    fields: &[[u8; 32]],
) -> Result<MergeOpening> {
    let width = MERGE_SUPPORTED_INPUT_COUNTS
        .into_iter()
        .find(|width| merge_disclosure_field_count(*width) == fields.len())
        .ok_or(AuditError::DisclosureShape)?;
    let mut key = Zeroizing::new(*ciphertext);
    open_stream(auditor, eph_pk, MERGE_DISCLOSURE_INFO, &mut *key)?;
    let chunks = Zeroizing::new(domain_stream(
        MERGE_DISCLOSURE_DOMAIN,
        &key,
        salt,
        fields,
        false,
    )?);
    let plaintext = Zeroizing::new(
        unpack_disclosure(&chunks, chunks.len() * PACK_BE_CHUNK_BYTES)
            .ok_or(AuditError::DisclosureField)?,
    );
    MergeOpening::decode(&plaintext, width)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Vector(serde_json::Value);

    impl Vector {
        fn load() -> Self {
            Self(
                serde_json::from_str(include_str!(
                    "../../../../test-vectors/ring-merge-anonymous.json"
                ))
                .expect("vector"),
            )
        }

        fn bytes(&self, key: &str) -> Vec<u8> {
            hex::decode(self.0[key].as_str().expect("hex").trim_start_matches("0x")).expect("hex")
        }

        fn array<const N: usize>(&self, key: &str) -> [u8; N] {
            self.bytes(key).try_into().expect("length")
        }

        fn fields(&self, key: &str) -> Vec<[u8; 32]> {
            self.0[key]
                .as_array()
                .expect("fields")
                .iter()
                .map(|value| {
                    hex::decode(value.as_str().expect("hex").trim_start_matches("0x"))
                        .expect("hex")
                        .try_into()
                        .expect("field")
                })
                .collect()
        }

        fn opening(&self) -> MergeOpening {
            let request = &self.0["request"];
            MergeOpening {
                owner_key: hex::decode(
                    request["ownerKey"]
                        .as_str()
                        .expect("owner")
                        .trim_start_matches("0x"),
                )
                .expect("hex")
                .try_into()
                .expect("owner key"),
                nullifier_pk: self.array("nullifier_pk"),
                mint: self.array("mint"),
                amount: self.0["amount"].as_u64().expect("amount"),
                output_blinding: self.array("output_blinding"),
                input_commitments: self.fields("input_commitments"),
            }
        }
    }

    /// Sealing under the vector's keys reproduces the Go fields, opening them returns the opening.
    #[test]
    fn the_disclosure_matches_the_go_vector() {
        let vector = Vector::load();
        let request = &vector.0["request"];
        let hex32 = |key: &str| -> [u8; 32] {
            hex::decode(request[key].as_str().expect("hex").trim_start_matches("0x"))
                .expect("hex")
                .try_into()
                .expect("32 bytes")
        };
        let opening = vector.opening();
        assert_eq!(
            &opening.encode()[..merge_disclosure_len(8)],
            vector.bytes("plaintext")
        );
        let auditor = X25519Keypair::from_bytes(&vector.array("auditor_sk"));
        let sealed = MergeDisclosureEncryption::seal(
            &opening,
            vector.array("salt"),
            &auditor.pubkey(),
            X25519Keypair::from_bytes(&hex32("ephSk")),
            Zeroizing::new(hex32("disclosureKey")),
        )
        .expect("seal");
        assert_eq!(sealed.fields, vector.fields("fields"));
        assert_eq!(sealed.ciphertext, vector.array::<32>("envelope_ciphertext"));
        assert_eq!(sealed.eph_pk.as_bytes(), &vector.array::<33>("eph_pk"));
        let opened = open_merge_disclosure(
            &auditor,
            &sealed.eph_pk,
            &sealed.ciphertext,
            vector.array("salt"),
            &sealed.fields,
        )
        .expect("open");
        assert_eq!(opened, opening);
        let mut other_salt = vector.array::<16>("salt");
        other_salt[0] ^= 1;
        assert!(!matches!(
            open_merge_disclosure(&auditor, &sealed.eph_pk, &sealed.ciphertext, other_salt, &sealed.fields),
            Ok(wrong) if wrong == opening
        ));
    }
}
