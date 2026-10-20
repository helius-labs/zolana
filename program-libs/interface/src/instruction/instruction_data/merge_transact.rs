use arrayvec::{ArrayVec, CapacityError};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::{
    primitives::{is_canonical_bn254_scalar_be, right_align},
    sha256::Sha256BE,
    Hasher, HasherError,
};

pub const MERGE_DEFAULT_INPUT_COUNT: usize = 24;

pub const MAX_MERGE_INPUTS: usize = 52;

pub const MERGE_SUPPORTED_INPUT_COUNTS: [usize; 3] =
    [8, MERGE_DEFAULT_INPUT_COUNT, MAX_MERGE_INPUTS];

/// Per-proof pad nonce of the merge output ciphertext, in bytes.
pub const MERGE_OUTPUT_CIPHERTEXT_SALT_LEN: usize = 16;

/// Field elements in the merge output ciphertext: the output amount and the
/// two `hash_bytes_32` chunks of its mint.
pub const MERGE_OUTPUT_CIPHERTEXT_ELEMENTS: usize = 3;

/// The vanilla Groth16 proof carried by the merge instructions: `a || b || c`,
/// 192 bytes. `a` and `c` are compressed G1 points (32 bytes each), `b` is the
/// raw big-endian G2 point (128 bytes). Merge proofs carry no lookup commitment.
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

/// Most public-input elements any [`MergeOutputEncryption`] scheme appends.
pub const MAX_MERGE_OUTPUT_ENCRYPTION_PUBLIC_INPUTS: usize = 4;

/// The merged output's amount and mint encrypted for its owner, so the owner
/// can rebuild the output from the merge transaction alone. The variant is the
/// scheme: on `merge_transact` it must equal the scheme in the owner's registry
/// record and it selects the verifying key. Both merge proofs bind its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum MergeOutputEncryption {
    /// Poseidon counter mode under `Poseidon("TMOK", nsk, nullifiers[0])`,
    /// padded under the per-proof `salt`; `ciphertext` holds the amount and
    /// the two `hash_bytes_32` chunks of the mint.
    #[wincode(tag = 1)]
    PoseidonCtrV1 {
        salt: [u8; MERGE_OUTPUT_CIPHERTEXT_SALT_LEN],
        ciphertext: [[u8; 32]; MERGE_OUTPUT_CIPHERTEXT_ELEMENTS],
    },
}

impl MergeOutputEncryption {
    /// Whether every ciphertext element is a canonical BN254 scalar. A
    /// non-canonical encoding would reduce to the same public input as its
    /// canonical twin, so the program rejects it before verification.
    pub fn is_canonical(&self) -> bool {
        match self {
            Self::PoseidonCtrV1 { ciphertext, .. } => {
                ciphertext.iter().all(is_canonical_bn254_scalar_be)
            }
        }
    }

    /// Appends the scheme's elements of the merge public-input hash, in
    /// circuit order, after the owner binding. PoseidonCtrV1: the
    /// right-aligned salt, then the three ciphertext elements. Each scheme has
    /// its own circuit, so the element count may differ per scheme, up to
    /// [`MAX_MERGE_OUTPUT_ENCRYPTION_PUBLIC_INPUTS`].
    pub fn append_public_inputs<const N: usize>(
        &self,
        inputs: &mut ArrayVec<[u8; 32], N>,
    ) -> Result<(), CapacityError> {
        match self {
            Self::PoseidonCtrV1 { salt, ciphertext } => {
                inputs
                    .try_push(right_align(salt))
                    .map_err(CapacityError::simplify)?;
                inputs.try_extend_from_slice(ciphertext)
            }
        }
    }
}

/// `merge_transact` instruction data (spec: SPP `merge_transact`).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeTransactIxData {
    pub expiry_unix_ts: u64,
    pub proof: MergeProof,
    pub output_utxo_hash: [u8; 32],
    pub output_encryption: MergeOutputEncryption,
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
    pub output_encryption: MergeOutputEncryption,
    pub private_tx_hash: &'a [u8; 32],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
    pub cache_slot: Option<u8>,
}

impl<'a> MergeTransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize_exact(data, RefConfig::new())?;
        parsed.validate_shape()?;
        Ok(parsed)
    }

    /// The instruction carries only the leading nullifiers; the circuit
    /// [`merge_circuit_width`] selects pads the rest with compact padding.
    pub(crate) fn validate_shape(&self) -> Result<(), wincode::ReadError> {
        if merge_circuit_width(self.nullifiers.len()).is_none() {
            return Err(wincode::ReadError::Custom("unsupported merge shape"));
        }
        Ok(())
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
