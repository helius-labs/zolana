use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

use super::transact::{P256Proof, P256ProofRef};

/// Number of input slots a merge proof spends (8-in/1-out shape). Dummy slots
/// carry distinct, in-window nullifiers and valid root indices.
pub const MERGE_INPUT_COUNT: usize = 8;

/// Byte length of the `encrypted_utxo` payload, the unified output encoding
/// `borsh(OutputDataEncoding::VerifiablyEncrypted([scheme(1) || tx_viewing_pk(33) ||
/// ciphertext(71)]))`: borsh enum tag(1) || vec len u32-le(4) || blob(105).
pub const MERGE_ENCRYPTED_UTXO_LEN: usize = 110;

/// First byte every merge `encrypted_utxo` must carry: the borsh
/// `OutputDataEncoding::VerifiablyEncrypted` discriminant.
pub const MERGE_ENCRYPTED_UTXO_TYPE_PREFIX: u8 = 2;

/// `merge_transact` instruction data (spec: SPP `merge_transact`).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeTransactIxData {
    pub expiry_unix_ts: u64,
    /// The merge circuit is P256-only, so the proof is always the BSB22-committed
    /// five-tuple; the layout is shared with `transact`'s P256 rail.
    pub proof: P256Proof,
    pub output_utxo_hash: [u8; 32],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub utxo_tree_root_index: Vec<u16>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub nullifier_tree_root_index: Vec<u16>,
    pub private_tx_hash: [u8; 32],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub encrypted_utxo: Vec<u8>,
    /// When true the owner identity (`pk_field(user_signing_pk)`) is derived from
    /// the registry account's ed25519 `owner` instead of its P256 `owner_p256`.
    pub eddsa_owner: bool,
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
/// [`MergeTransactIxData::serialize`], except sequences without an explicit
/// `FixIntLen` carry a `u16` length prefix, matching `encrypted_utxo`'s
/// `FixIntLen<u16>` while the element vectors keep their `FixIntLen<u8>` override.
pub(crate) type RefConfig = wincode::config::Configuration<
    true,
    { wincode::config::DEFAULT_PREALLOCATION_SIZE_LIMIT },
    FixIntLen<u16>,
>;

/// Zero-copy view of [`MergeTransactIxData`]. The large payloads (the proof
/// points and `encrypted_utxo`) alias the instruction buffer; only the small
/// element vectors are read owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeTransactIxDataRef<'a> {
    pub expiry_unix_ts: u64,
    pub proof: P256ProofRef<'a>,
    pub output_utxo_hash: &'a [u8; 32],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub utxo_tree_root_index: Vec<u16>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub nullifier_tree_root_index: Vec<u16>,
    pub private_tx_hash: &'a [u8; 32],
    pub encrypted_utxo: &'a [u8],
    pub eddsa_owner: bool,
}

impl<'a> MergeTransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize(data, RefConfig::new())?;
        parsed.validate_shape()?;
        Ok(parsed)
    }

    /// Enforce the fixed 8-in/1-out merge shape and output blob length. Shared with
    /// `merge_zone`, which embeds a `MergeTransactIxDataRef`.
    pub(crate) fn validate_shape(&self) -> Result<(), wincode::ReadError> {
        if self.nullifiers.len() != MERGE_INPUT_COUNT
            || self.utxo_tree_root_index.len() != MERGE_INPUT_COUNT
            || self.nullifier_tree_root_index.len() != MERGE_INPUT_COUNT
            || self.encrypted_utxo.len() != MERGE_ENCRYPTED_UTXO_LEN
        {
            return Err(wincode::ReadError::Custom("invalid merge shape"));
        }
        Ok(())
    }

    /// `tx_viewing_pk = encrypted_utxo[6..39]` (after the borsh tag(1) + vec
    /// len(4) + scheme(1) prefix).
    pub fn tx_viewing_pk(&self) -> Result<&'a [u8; 33], wincode::ReadError> {
        self.encrypted_utxo
            .get(6..39)
            .and_then(|s| s.try_into().ok())
            .ok_or(wincode::ReadError::Custom("encrypted_utxo too short"))
    }

    /// `ciphertext = encrypted_utxo[39..110]`.
    pub fn ciphertext(&self) -> Result<&'a [u8], wincode::ReadError> {
        self.encrypted_utxo
            .get(39..MERGE_ENCRYPTED_UTXO_LEN)
            .ok_or(wincode::ReadError::Custom("encrypted_utxo too short"))
    }
}

/// `external_data_hash` public input for the merge instructions. Domain-separated
/// by the instruction's discriminator (`merge_transact` or `merge_zone`) so a
/// preimage cannot be reused across instructions. Computed identically by the
/// client and the program.
pub struct MergeExternalDataHash<'a> {
    pub spp_instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub output_utxo_hash: &'a [u8; 32],
    pub encrypted_utxo: &'a [u8],
}

impl MergeExternalDataHash<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let mut preimage = Vec::new();
        preimage.push(self.spp_instruction_discriminator);
        preimage.extend_from_slice(&self.expiry_unix_ts.to_be_bytes());
        preimage.extend_from_slice(self.output_utxo_hash);
        preimage.extend_from_slice(&(self.encrypted_utxo.len() as u16).to_be_bytes());
        preimage.extend_from_slice(self.encrypted_utxo);
        Sha256BE::hash(&preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: 42,
            proof: P256Proof {
                a: [1u8; 32],
                b: [2u8; 64],
                c: [3u8; 32],
                commitment: [4u8; 32],
                commitment_pok: [5u8; 32],
            },
            output_utxo_hash: [9u8; 32],
            nullifiers: (0..MERGE_INPUT_COUNT as u8).map(|i| [i; 32]).collect(),
            utxo_tree_root_index: (0..MERGE_INPUT_COUNT as u16).collect(),
            nullifier_tree_root_index: (10..10 + MERGE_INPUT_COUNT as u16).collect(),
            private_tx_hash: [3u8; 32],
            encrypted_utxo: (0..MERGE_ENCRYPTED_UTXO_LEN as u16)
                .map(|i| i as u8)
                .collect(),
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
        assert_eq!(view.proof.commitment, &owned.proof.commitment);
        assert_eq!(view.proof.commitment_pok, &owned.proof.commitment_pok);
        assert_eq!(view.output_utxo_hash, &owned.output_utxo_hash);
        assert_eq!(view.nullifiers, owned.nullifiers);
        assert_eq!(view.utxo_tree_root_index, owned.utxo_tree_root_index);
        assert_eq!(
            view.nullifier_tree_root_index,
            owned.nullifier_tree_root_index
        );
        assert_eq!(view.private_tx_hash, &owned.private_tx_hash);
        assert_eq!(view.encrypted_utxo, owned.encrypted_utxo.as_slice());
        assert_eq!(view.eddsa_owner, owned.eddsa_owner);
        // Blob accessors.
        assert_eq!(view.tx_viewing_pk().unwrap(), &owned.encrypted_utxo[6..39]);
        assert_eq!(view.ciphertext().unwrap(), &owned.encrypted_utxo[39..110]);
    }

    #[test]
    fn fixed_shape_wire_length_matches_the_protocol_contract() {
        let bytes = data().serialize().expect("serialize merge instruction");

        assert_eq!(bytes.len(), 380 + 36 * MERGE_INPUT_COUNT);
    }

    #[test]
    fn round_trips_eddsa_owner_flag() {
        let mut owned = data();
        owned.eddsa_owner = true;
        let bytes = owned.serialize().unwrap();
        let view = MergeTransactIxDataRef::from_bytes(&bytes).unwrap();
        assert!(view.eddsa_owner);
    }

    #[test]
    fn rejects_wrong_shape() {
        let mut owned = data();
        owned.nullifiers.pop();
        let bytes = owned.serialize().unwrap();
        assert!(MergeTransactIxDataRef::from_bytes(&bytes).is_err());

        let mut owned = data();
        owned.encrypted_utxo.pop();
        let bytes = owned.serialize().unwrap();
        assert!(MergeTransactIxDataRef::from_bytes(&bytes).is_err());
    }

    fn hash_of(expiry: u64, output: &[u8; 32], blob: &[u8]) -> [u8; 32] {
        MergeExternalDataHash {
            spp_instruction_discriminator: crate::instruction::tag::MERGE_TRANSACT,
            expiry_unix_ts: expiry,
            output_utxo_hash: output,
            encrypted_utxo: blob,
        }
        .hash()
        .unwrap()
    }

    #[test]
    fn external_data_hash_is_injective() {
        let blob = [5u8; MERGE_ENCRYPTED_UTXO_LEN];
        let base = hash_of(1, &[1u8; 32], &blob);
        assert_ne!(base, hash_of(2, &[1u8; 32], &blob));
        assert_ne!(base, hash_of(1, &[2u8; 32], &blob));
        let mut other = blob;
        other[0] = 6;
        assert_ne!(base, hash_of(1, &[1u8; 32], &other));
    }
}
