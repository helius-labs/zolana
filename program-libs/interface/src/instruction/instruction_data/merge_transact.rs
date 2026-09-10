use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

pub const MERGE_SUPPORTED_INPUT_COUNTS: [usize; 2] = [8, 36];

pub const MAX_MERGE_INPUTS: usize = 36;

pub const MERGE_DEFAULT_INPUT_COUNT: usize = 8;

/// The vanilla Groth16 proof carried by the merge instructions: `a || b || c`,
/// 192 bytes. `a` and `c` are compressed G1 points (32 bytes each), `b` is the
/// raw big-endian G2 point (128 bytes). The merge circuit carries no P256
/// gadget, so there is no BSB22 commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeProof {
    pub a: [u8; 32],
    pub b: [u8; 128],
    pub c: [u8; 32],
}

impl MergeProof {
    /// Serialized length: the three points back to back, no tag.
    pub const LEN: usize = 192;

    /// A zeroed proof, used as a placeholder before the real proof is attached
    /// and as a dummy in tests.
    pub const fn zeroed() -> Self {
        Self {
            a: [0u8; 32],
            b: [0u8; 128],
            c: [0u8; 32],
        }
    }
}

/// Zero-copy view of [`MergeProof`]: every point aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeProofRef<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 128],
    pub c: &'a [u8; 32],
}

/// `merge_transact` instruction data (spec: SPP `merge_transact`).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeTransactIxData {
    pub expiry_unix_ts: u64,
    pub proof: MergeProof,
    pub output_utxo_hash: [u8; 32],
    /// When true the owner identity (`pk_field(user_signing_pk)`) is derived from
    /// the registry account's ed25519 `owner` instead of its P256 `owner_p256`.
    pub eddsa_owner: bool,
    pub private_tx_hash: [u8; 32],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
}

impl MergeTransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Read config for the borrowed view: identical to the default config used by
/// [`MergeTransactIxData::serialize`]; every sequence carries an explicit
/// `FixIntLen<u8>` override, so the config choice never surfaces on the wire.
pub(crate) type RefConfig = wincode::config::Configuration<
    true,
    { wincode::config::DEFAULT_PREALLOCATION_SIZE_LIMIT },
    FixIntLen<u16>,
>;

/// Zero-copy view of [`MergeTransactIxData`]. The proof points alias the
/// instruction buffer; only the small element vectors are read owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeTransactIxDataRef<'a> {
    pub expiry_unix_ts: u64,
    pub proof: MergeProofRef<'a>,
    pub output_utxo_hash: &'a [u8; 32],
    pub eddsa_owner: bool,
    pub private_tx_hash: &'a [u8; 32],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
}

impl<'a> MergeTransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize(data, RefConfig::new())?;
        parsed.validate_shape()?;
        Ok(parsed)
    }

    pub(crate) fn validate_shape(&self) -> Result<(), wincode::ReadError> {
        if !MERGE_SUPPORTED_INPUT_COUNTS.contains(&self.nullifiers.len()) {
            return Err(wincode::ReadError::Custom("unsupported merge shape"));
        }
        Ok(())
    }
}

/// `external_data_hash` public input for the merge instructions. Domain-separated
/// by the instruction's discriminator (`merge_transact` or `merge_ring`) so a
/// preimage cannot be reused across instructions. Computed identically by the
/// client and the program. For `merge_ring`, the output `ring_data_hash` is
/// bound directly as a public-input-hash element, so it does not enter this
/// preimage.
pub struct MergeExternalDataHash<'a> {
    pub spp_instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub output_utxo_hash: &'a [u8; 32],
}

impl MergeExternalDataHash<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let mut preimage = Vec::new();
        preimage.push(self.spp_instruction_discriminator);
        preimage.extend_from_slice(&self.expiry_unix_ts.to_be_bytes());
        preimage.extend_from_slice(self.output_utxo_hash);
        Sha256BE::hash(&preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: 42,
            proof: MergeProof {
                a: [1u8; 32],
                b: [2u8; 128],
                c: [3u8; 32],
            },
            output_utxo_hash: [9u8; 32],
            nullifiers: (0..MERGE_DEFAULT_INPUT_COUNT as u8)
                .map(|i| [i; 32])
                .collect(),
            utxo_tree_root_index: 4,
            nullifier_tree_root_index: 10,
            private_tx_hash: [3u8; 32],
            eddsa_owner: false,
        }
    }

    #[test]
    fn round_trips_owned_and_ref() {
        let owned = data();
        let bytes = owned.serialize().unwrap();
        let view = MergeTransactIxDataRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.expiry_unix_ts, owned.expiry_unix_ts);
        assert_eq!(view.proof.a, &owned.proof.a);
        assert_eq!(view.proof.b, &owned.proof.b);
        assert_eq!(view.proof.c, &owned.proof.c);
        assert_eq!(view.output_utxo_hash, &owned.output_utxo_hash);
        assert_eq!(view.nullifiers, owned.nullifiers);
        assert_eq!(view.utxo_tree_root_index, owned.utxo_tree_root_index);
        assert_eq!(
            view.nullifier_tree_root_index,
            owned.nullifier_tree_root_index
        );
        assert_eq!(view.private_tx_hash, &owned.private_tx_hash);
        assert_eq!(view.eddsa_owner, owned.eddsa_owner);
    }

    #[test]
    fn fixed_shape_wire_length_matches_the_protocol_contract() {
        let bytes = data().serialize().expect("serialize merge instruction");

        assert_eq!(bytes.len(), 270 + 32 * MERGE_DEFAULT_INPUT_COUNT);
    }

    #[test]
    fn rejects_wrong_shape() {
        let mut owned = data();
        owned.nullifiers.pop();
        let bytes = owned.serialize().unwrap();
        assert!(MergeTransactIxDataRef::from_bytes(&bytes).is_err());
    }

    fn hash_of(discriminator: u8, expiry: u64, output: &[u8; 32]) -> [u8; 32] {
        MergeExternalDataHash {
            spp_instruction_discriminator: discriminator,
            expiry_unix_ts: expiry,
            output_utxo_hash: output,
        }
        .hash()
        .unwrap()
    }

    #[test]
    fn external_data_hash_is_injective() {
        let base = hash_of(crate::instruction::tag::MERGE_TRANSACT, 1, &[1u8; 32]);
        assert_ne!(
            base,
            hash_of(crate::instruction::tag::MERGE_TRANSACT, 2, &[1u8; 32])
        );
        assert_ne!(
            base,
            hash_of(crate::instruction::tag::MERGE_TRANSACT, 1, &[2u8; 32])
        );
        assert_ne!(
            base,
            hash_of(crate::instruction::tag::RING_MERGE_TRANSACT, 1, &[1u8; 32])
        );
    }
}
