use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

pub const MERGE_DEFAULT_INPUT_COUNT: usize = 24;

pub const MAX_MERGE_INPUTS: usize = 54;

pub const MERGE_SUPPORTED_INPUT_COUNTS: [usize; 3] =
    [8, MERGE_DEFAULT_INPUT_COUNT, MAX_MERGE_INPUTS];

pub const MERGE_CIPHERTEXT_LEN: usize = 40;

/// The Groth16 proof carried by the merge instructions: `a || b || c`,
/// 192 bytes. `a` and `c` are compressed G1 points (32 bytes each), `b` is the
/// raw big-endian G2 point (128 bytes).
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

/// The BSB22 commitment and its proof of knowledge that the P-256 default-merge
/// circuit adds to its Groth16 proof. The ring merge circuit has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeProofCommitment {
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeProofCommitmentRef<'a> {
    pub commitment: &'a [u8; 32],
    pub commitment_pok: &'a [u8; 32],
}

/// The default-merge output amount and mint, encrypted to the owner's viewing
/// key: the sender's SEC1-compressed ephemeral key and the 40-byte ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeEnvelope {
    pub ephemeral_pk: [u8; 33],
    pub ciphertext: [u8; MERGE_CIPHERTEXT_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeEnvelopeRef<'a> {
    pub ephemeral_pk: &'a [u8; 33],
    pub ciphertext: &'a [u8; MERGE_CIPHERTEXT_LEN],
}

/// The fields `merge_transact` and `merge_ring` share.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeBody {
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
    /// Selects the single cache slot the merged output is written to, and
    /// requires the writable cache account followed by its signing writer.
    /// Both merge instructions reject extra accounts, including when this is
    /// `None`.
    pub cache_slot: Option<u8>,
}

/// `merge_transact` instruction data (spec: SPP `merge_transact`). The
/// default rail always carries the proof commitment and the encrypted output
/// envelope, so neither is optional.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeTransactIxData {
    pub body: MergeBody,
    pub proof_commitment: MergeProofCommitment,
    pub envelope: MergeEnvelope,
}

impl MergeTransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Read config for the borrowed views: identical to the default config used by
/// [`MergeTransactIxData::serialize`]; every sequence carries an explicit
/// `FixIntLen<u8>` override, so the config choice never surfaces on the wire.
pub(crate) type RefConfig = wincode::config::Configuration<
    true,
    { wincode::config::DEFAULT_PREALLOCATION_SIZE_LIMIT },
    FixIntLen<u16>,
>;

/// Zero-copy view of [`MergeBody`]. The proof points alias the instruction
/// buffer; only the small element vectors are read owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeBodyRef<'a> {
    pub expiry_unix_ts: u64,
    pub proof: MergeProofRef<'a>,
    pub output_utxo_hash: &'a [u8; 32],
    pub eddsa_owner: bool,
    pub private_tx_hash: &'a [u8; 32],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
    pub cache_slot: Option<u8>,
}

impl MergeBodyRef<'_> {
    /// The instruction carries only the leading nullifiers; the circuit
    /// [`merge_circuit_width`] selects pads the rest with compact padding.
    pub(crate) fn validate_shape(&self) -> Result<(), wincode::ReadError> {
        if merge_circuit_width(self.nullifiers.len()).is_none() {
            return Err(wincode::ReadError::Custom("unsupported merge shape"));
        }
        Ok(())
    }
}

/// Zero-copy view of [`MergeTransactIxData`].
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeTransactIxDataRef<'a> {
    pub body: MergeBodyRef<'a>,
    pub proof_commitment: MergeProofCommitmentRef<'a>,
    pub envelope: MergeEnvelopeRef<'a>,
}

impl<'a> MergeTransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize(data, RefConfig::new())?;
        parsed.body.validate_shape()?;
        Ok(parsed)
    }
}

/// The narrowest supported merge circuit that holds `input_count` nullifiers,
/// or `None` for zero or more than [`MAX_MERGE_INPUTS`]. Slots past the sent
/// nullifiers are compact padding with nullifier 0.
pub fn merge_circuit_width(input_count: usize) -> Option<usize> {
    if input_count == 0 {
        return None;
    }
    MERGE_SUPPORTED_INPUT_COUNTS
        .into_iter()
        .find(|width| input_count <= *width)
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
    pub cache: Option<(&'a [u8; 32], u8)>,
}

impl MergeExternalDataHash<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let mut preimage = Vec::new();
        preimage.push(self.spp_instruction_discriminator);
        preimage.extend_from_slice(&self.expiry_unix_ts.to_be_bytes());
        preimage.extend_from_slice(self.output_utxo_hash);
        preimage.push(u8::from(self.cache.is_some()));
        if let Some((address, slot)) = self.cache {
            preimage.extend_from_slice(address);
            preimage.push(slot);
        }
        Sha256BE::hash(&preimage)
    }
}
