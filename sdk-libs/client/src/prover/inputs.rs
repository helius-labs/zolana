use num_bigint::BigUint;
use zolana_interface::{tree_slot::TreeSlot, INPUT_TREES, N_PUBLIC_SLOTS};
use zolana_transaction::{instructions::types::SppProofInputUtxo, ProofInputUtxo};

use crate::{
    error::ClientError,
    prover::field::be,
    rpc::{NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT},
};

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
#[derive(Debug, Clone)]
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
    pub nullifier_secret: BigUint,
}

impl TransferInput {
    /// Padding input over the sender's chosen random `blinding` (secret 0). It
    /// is hashed under `tree_id`, the tree it was assigned; the caller supplies
    /// the owner hash and the tree slot. The circuit skips ownership and state
    /// inclusion for it but still checks nullifier non-inclusion, so the
    /// nullifier returned here must be the one the caller fetched a
    /// non-inclusion witness for.
    pub fn new_dummy(
        blinding: &[u8; 32],
        tree_id: u16,
        owner_pk_hash: &[u8; 32],
    ) -> Result<(Self, [u8; 32]), ClientError> {
        let mut spend = SppProofInputUtxo::new_dummy().in_tree(tree_id);
        spend.utxo.blinding = *blinding;
        let nullifier = spend.nullifier()?;
        Ok((
            Self {
                utxo: ProofInputUtxo::try_from(&spend)?,
                is_dummy: BigUint::from(1u8),
                state_path_elements: vec![BigUint::ZERO; STATE_TREE_HEIGHT],
                state_path_index: BigUint::ZERO,
                nullifier_low_value: BigUint::ZERO,
                nullifier_next_value: BigUint::ZERO,
                nullifier_low_path_elements: vec![BigUint::ZERO; NULLIFIER_TREE_HEIGHT],
                nullifier_low_path_index: BigUint::ZERO,
                tree_slot: BigUint::ZERO,
                nullifier: be(&nullifier),
                owner_pk_hash: be(owner_pk_hash),
                nullifier_secret: BigUint::ZERO,
            },
            nullifier,
        ))
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
#[derive(Debug, Clone)]
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
    pub public_input_hash: BigUint,
}
