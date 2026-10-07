use core::fmt;

use num_bigint::BigUint;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use zeroize::Zeroizing;
use zolana_interface::{tree_slot::TreeSlot, INPUT_TREES, N_PUBLIC_SLOTS};
use zolana_keypair::{constants::P256_UNCOMPRESSED_PUBKEY_LEN, KeypairError};
use zolana_transaction::instructions::merge::MergeOutputEnvelope;

use super::ProofInputUtxo;

use crate::prover::{field::be, proving_key::hex};

/// One public tree slot of a proof request: the raw `u16` id of a tree inputs
/// may be spent from and the two roots SPP resolved for it. An unused slot is
/// all zero. Mirrors Go `common.TreeSlotParams`.
#[derive(Debug, Clone, Default)]
pub struct TreeSlotFields {
    pub id: BigUint,
    pub utxo_root: BigUint,
    pub nullifier_root: BigUint,
}

impl From<&TreeSlot> for TreeSlotFields {
    fn from(slot: &TreeSlot) -> Self {
        Self {
            id: be(&slot.id),
            utxo_root: be(&slot.utxo_root),
            nullifier_root: be(&slot.nullifier_root),
        }
    }
}

impl TreeSlotFields {
    /// Encode the fixed-width slot array every proof request carries.
    pub fn encode_all(slots: &[TreeSlot; INPUT_TREES]) -> [Self; INPUT_TREES] {
        core::array::from_fn(|index| slots.get(index).map(Self::from).unwrap_or_default())
    }
}

/// One spend input. Mirrors txcircuit.Input.
#[derive(Clone)]
pub struct TransferInput {
    pub utxo: ProofInputUtxo,
    pub is_dummy: BigUint,
    pub state_path_elements: Vec<BigUint>,
    pub state_path_index: BigUint,
    pub nullifier_low_value: BigUint,
    pub nullifier_next_value: BigUint,
    pub nullifier_low_path_elements: Vec<BigUint>,
    pub nullifier_low_path_index: BigUint,
    /// Private index into the request's tree slots. It selects the pair of
    /// roots this input is proven against, so the roots themselves are
    /// published once per tree rather than once per input.
    pub tree_slot: BigUint,
    pub nullifier: BigUint,
    pub owner_pk_hash: BigUint,
    /// The secret this input is nullified with, absent until the owner's
    /// [`ProofAuthority`](crate::authority::ProofAuthority) fills it in.
    ///
    /// `None` is a real input of that authority's owner, waiting to be
    /// completed; `Some(0)` a padding slot, whose secret is genuinely zero and
    /// public; `Some(s)` another owner's input, which arrived complete. Without
    /// the `Option` the two zeros are indistinguishable and an uncompleted real
    /// input would prove as a dummy, so serialization refuses a `None` rather
    /// than sending one.
    pub nullifier_secret: Option<BigUint>,
}

/// Debug shows whether the nullifier secret is present but never its value.
impl fmt::Debug for TransferInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferInput")
            .field("utxo", &self.utxo)
            .field("is_dummy", &self.is_dummy)
            .field("state_path_elements", &self.state_path_elements)
            .field("state_path_index", &self.state_path_index)
            .field("nullifier_low_value", &self.nullifier_low_value)
            .field("nullifier_next_value", &self.nullifier_next_value)
            .field(
                "nullifier_low_path_elements",
                &self.nullifier_low_path_elements,
            )
            .field("nullifier_low_path_index", &self.nullifier_low_path_index)
            .field("tree_slot", &self.tree_slot)
            .field("nullifier", &self.nullifier)
            .field("owner_pk_hash", &self.owner_pk_hash)
            .field(
                "nullifier_secret",
                &self.nullifier_secret.as_ref().map(|_| REDACTED),
            )
            .finish()
    }
}

/// One output. Mirrors txcircuit.Output.
#[derive(Debug, Clone)]
pub struct TransferOutput {
    pub utxo: ProofInputUtxo,
    pub is_dummy: BigUint,
    pub hash: BigUint,
    /// Public owner tag (`signing_pubkey.hash()`) and witnessed `nullifier_pk`,
    /// from which both confidential circuits recompute `owner_hash`. Dummy
    /// output tags must identify a transaction participant.
    pub owner_pk_hash: BigUint,
    pub nullifier_pk: BigUint,
}

/// Flat, pre-computed witness for the 8-in/1-out merge circuit. Mirrors
/// prover/server/prover/merge/params.go MergeParameters. The per-input and output
/// witness reuses [`TransferInput`]/[`TransferOutput`] (assembled the same way as
/// a transfer); the merge circuit ignores the transfer-only `ownerPkHash`
/// and per-input `nullifierSecret` (the secret is shared, below).
#[derive(Clone)]
pub struct MergeInputs {
    pub inputs: Vec<TransferInput>,
    pub output: TransferOutput,
    /// The trees inputs may be spent from, one slot per tree; every input
    /// selects one privately. Unused slots are all zero and sit at the end.
    pub tree_slots: [TreeSlotFields; INPUT_TREES],
    /// Raw `u16` id of the tree the merged output is appended to.
    pub output_tree_id: BigUint,
    /// Shared owner identity: `owner_pk_hash` carries the owner's pk_field on
    /// both owner rails.
    pub owner_pk_hash: BigUint,
    pub user_nullifier_pk: BigUint,
    pub user_nullifier_secret: BigUint,
    pub external_data_hash: BigUint,
    pub private_tx_hash: BigUint,
    /// Merges always legitimately pad with dummy slots, so the dummy-input
    /// guard is `1` here.
    pub allow_dummy_inputs: BigUint,
    pub public_input_hash: BigUint,
    /// Policy-ring merge only: the output ring-data hash the calling ring
    /// program carries in the instruction/event, asserted against
    /// `Output.RingDataHash`. `0` for the default merge.
    pub output_ring_data_hash: BigUint,
    /// Policy-ring merge only: the ring program's `pk_field`, the merge-ring
    /// circuit's top-level public input. `0` for the default merge.
    pub ring_program_id: BigUint,
    pub mint: [u8; 32],
    pub envelope: Option<MergeEnvelopeInputs>,
}

/// Debug redacts the shared nullifier secret: it nullifies every UTXO of the
/// owner, so it must not reach logs.
impl fmt::Debug for MergeInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MergeInputs")
            .field("inputs", &self.inputs)
            .field("output", &self.output)
            .field("tree_slots", &self.tree_slots)
            .field("output_tree_id", &self.output_tree_id)
            .field("owner_pk_hash", &self.owner_pk_hash)
            .field("user_nullifier_pk", &self.user_nullifier_pk)
            .field("user_nullifier_secret", &REDACTED)
            .field("external_data_hash", &self.external_data_hash)
            .field("private_tx_hash", &self.private_tx_hash)
            .field("allow_dummy_inputs", &self.allow_dummy_inputs)
            .field("public_input_hash", &self.public_input_hash)
            .field("output_ring_data_hash", &self.output_ring_data_hash)
            .field("ring_program_id", &self.ring_program_id)
            .field("mint", &self.mint)
            .field("envelope", &self.envelope)
            .finish()
    }
}

#[derive(Clone)]
pub struct MergeEnvelopeInputs {
    pub viewing_pk: [u8; P256_UNCOMPRESSED_PUBKEY_LEN],
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
}

/// Debug redacts the ephemeral secret: with it anyone decrypts the envelope.
impl fmt::Debug for MergeEnvelopeInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MergeEnvelopeInputs")
            .field("viewing_pk", &self.viewing_pk)
            .field("ephemeral_sk", &REDACTED)
            .finish()
    }
}

struct Redacted;

const REDACTED: Redacted = Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl MergeEnvelopeInputs {
    pub fn new(envelope: &MergeOutputEnvelope) -> Result<Self, KeypairError> {
        Ok(Self {
            viewing_pk: envelope.recipient().to_uncompressed()?,
            ephemeral_sk: envelope.ephemeral().secret_bytes(),
        })
    }
}

impl Serialize for MergeEnvelopeInputs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ephemeral_sk = Zeroizing::new(hex(self.ephemeral_sk.as_slice()));
        let mut fields = serializer.serialize_struct("MergeEnvelopeInputs", 2)?;
        fields.serialize_field("viewingPk", &hex(&self.viewing_pk))?;
        fields.serialize_field("ephemeralSk", ephemeral_sk.as_str())?;
        fields.end()
    }
}

/// Flat witness for the batch address-append circuit used by the nullifier tree
/// forester. Mirrors prover/server/prover/nullifier_tree/params.go
/// BatchAddressAppendParameters.
#[derive(Debug, Clone)]
pub struct BatchAddressAppendInputs {
    pub public_input_hash: BigUint,
    pub old_root: BigUint,
    pub new_root: BigUint,
    pub hashchain_hash: BigUint,
    pub start_index: u64,
    pub low_element_values: Vec<BigUint>,
    pub low_element_indices: Vec<BigUint>,
    pub low_element_next_values: Vec<BigUint>,
    pub new_element_values: Vec<BigUint>,
    pub low_element_proofs: Vec<Vec<BigUint>>,
    pub new_element_proofs: Vec<Vec<BigUint>>,
    pub tree_height: u32,
    pub batch_size: u32,
}

/// Flat, pre-computed witness for the Solana-only spp_transaction circuit. This
/// rail has no P256 gadget, so there is no P256 pubkey/signature/message-hash.
/// Mirrors prover/server/prover/transfer_eddsa_only/params.go TransferParameters.
#[derive(Debug, Clone)]
pub struct TransferInputs {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    /// The trees inputs may be spent from, one slot per tree; every input
    /// selects one privately. Unused slots are all zero and sit at the end.
    pub tree_slots: [TreeSlotFields; INPUT_TREES],
    /// Raw `u16` id of the tree every output is appended to.
    pub output_tree_id: BigUint,
    /// The transaction's private random root seed. The circuit derives the
    /// output blinding seed and the private transaction blinding from it, so
    /// neither is sent.
    pub blinding_seed: BigUint,
    pub external_data_hash: BigUint,
    pub private_tx_hash: BigUint,
    /// Uniform public transfer slots (slot 0 = SOL leg, slot 1 = SPL leg); idle
    /// slots are (0, 0).
    pub public_assets: [BigUint; N_PUBLIC_SLOTS],
    pub public_amounts: [BigUint; N_PUBLIC_SLOTS],
    pub ring_program_id: BigUint,
    pub signer_pk_hashes: Vec<BigUint>,
    /// The dummy-input policy packed with every input's tree index, from
    /// `zolana_interface::tree_slot::pack_input_flags`.
    pub input_flags: BigUint,
    pub published_output_owner_pk_hashes: Vec<BigUint>,
    pub cache: CacheReadInputs,
    pub public_input_hash: BigUint,
}

/// Flat witness for the custom-ring P256 transaction circuit.
#[derive(Debug, Clone)]
pub struct TransferP256Inputs {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    /// The trees inputs may be spent from, one slot per tree; every input
    /// selects one privately. Unused slots are all zero and sit at the end.
    pub tree_slots: [TreeSlotFields; INPUT_TREES],
    /// Raw `u16` id of the tree every output is appended to.
    pub output_tree_id: BigUint,
    /// The transaction's private random root seed. See
    /// [`TransferInputs::blinding_seed`].
    pub blinding_seed: BigUint,
    pub external_data_hash: BigUint,
    pub private_tx_hash: BigUint,
    pub p256_pub_x: BigUint,
    pub p256_pub_y: BigUint,
    pub p256_sig_r: BigUint,
    pub p256_sig_s: BigUint,
    /// Full SHA-256 digest split into big-endian 128-bit limbs. The low limb is
    /// the final 16 digest bytes; the high limb is the first 16 bytes.
    pub p256_message_hash_low: BigUint,
    pub p256_message_hash_high: BigUint,
    /// Program-derived public hash of the P256 x-coordinate when the shared
    /// owner spends a default-ring UTXO; zero for ring-only P256 and for
    /// address slots, which never publish the owner.
    pub default_p256_owner_pk_hash: BigUint,
    pub public_assets: [BigUint; N_PUBLIC_SLOTS],
    pub public_amounts: [BigUint; N_PUBLIC_SLOTS],
    pub ring_program_id: BigUint,
    pub signer_pk_hashes: Vec<BigUint>,
    /// The dummy-input policy packed with every input's tree index, from
    /// `zolana_interface::tree_slot::pack_input_flags`.
    pub input_flags: BigUint,
    pub published_output_owner_pk_hashes: Vec<BigUint>,
    pub cache: CacheReadInputs,
    pub public_input_hash: BigUint,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheReadInputs {
    pub tree_id: BigUint,
    pub read_hash_chain: BigUint,
    pub read_hashes: Vec<BigUint>,
    pub is_cached: Vec<bool>,
    pub read_index: Vec<usize>,
}
