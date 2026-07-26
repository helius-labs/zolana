use num_bigint::BigUint;
use zolana_interface::N_PUBLIC_SLOTS;
use zolana_transaction::{instructions::types::SppProofInputUtxo, ProofInputUtxo};

use crate::{
    error::ClientError,
    prover::field::be,
    rpc::{NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT},
};

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
    pub utxo_tree_root: BigUint,
    pub nullifier_tree_root: BigUint,
    pub nullifier: BigUint,
    pub owner_pk_hash: BigUint,
    pub nullifier_secret: BigUint,
}

impl TransferInput {
    /// Padding input over the sender's chosen random `blinding` (secret 0). The roots,
    /// indices, and owner hash are mirrored from the first real input by the caller;
    /// the circuit skips ownership, inclusion, and the nullifier check for it.
    pub fn new_dummy(
        blinding: &[u8; 32],
        utxo_tree_root: &[u8; 32],
        nullifier_tree_root: &[u8; 32],
        owner_pk_hash: &[u8; 32],
    ) -> Result<(Self, [u8; 32]), ClientError> {
        let mut spend = SppProofInputUtxo::new_dummy();
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
                utxo_tree_root: be(utxo_tree_root),
                nullifier_tree_root: be(nullifier_tree_root),
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
    /// Confidential variant: the public owner tag (`signing_pubkey.hash()`) and
    /// the witnessed `nullifier_pk`, from which the circuit recomputes `owner_hash`.
    /// Both 0 for a dummy output (the circuit leaves its owner tag unconstrained).
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
    /// Shared owner identity: `owner_pk_hash` carries the owner's pk_field on
    /// both owner rails.
    pub owner_pk_hash: BigUint,
    pub user_nullifier_pk: BigUint,
    pub user_nullifier_secret: BigUint,
    /// Single-use nonce driving the in-circuit output-blinding and
    /// dummy-nullifier derivations; folded into the public-input hash.
    pub merge_view_tag: BigUint,
    pub external_data_hash: BigUint,
    pub private_tx_hash: BigUint,
    /// Merges always legitimately pad with dummy slots, so the dummy-input
    /// guard is `1` here.
    pub allow_dummy_inputs: BigUint,
    pub public_input_hash: BigUint,
    /// Policy-zone merge only: the output zone-data hash the calling zone
    /// program carries in the instruction/event, asserted against
    /// `Output.ZoneDataHash`. `0` for the default merge.
    pub output_zone_data_hash: BigUint,
    /// Policy-zone merge only: the zone program's `pk_field`, the merge-zone
    /// circuit's top-level public input. `0` for the default merge.
    pub zone_program_id: BigUint,
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
    pub external_data_hash: BigUint,
    pub private_tx_hash: BigUint,
    /// Uniform public movement slots (slot 0 = SOL leg, slot 1 = SPL leg); idle
    /// slots are (0, 0).
    pub public_assets: [BigUint; N_PUBLIC_SLOTS],
    pub public_amounts: [BigUint; N_PUBLIC_SLOTS],
    pub zone_program_id: BigUint,
    pub payer_pubkey_hash: BigUint,
    pub allow_dummy_inputs: BigUint,
    pub public_input_hash: BigUint,
}
