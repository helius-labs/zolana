use std::fmt;

use num_bigint::BigUint;
use spr_interface::{tree_slot::TreeSlot, INPUT_TREES, N_PUBLIC_SLOTS};

use super::ProofInputUtxo;

use crate::prover::field::be;

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

/// One spend input. Mirrors txcircuit.Input. Its `Debug` redacts the
/// nullifier secret.
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
/// and per-input `nullifierSecret` (the secret is shared, below). Its `Debug`
/// redacts the owner's nullifier secret.
#[derive(Clone)]
pub struct MergeInputs {
    pub inputs: Vec<TransferInput>,
    pub output: TransferOutput,
    /// The trees inputs may be spent from, one slot per tree; every input
    /// selects one privately. Unused slots are all zero and sit at the end.
    pub tree_slots: [TreeSlotFields; INPUT_TREES],
    /// Raw `u16` id of the tree the merged output is appended to.
    pub output_tree_id: BigUint,
    /// The `hash_bytes_32` chunks of the merged mint; the circuit derives the
    /// asset from them and encrypts them for the owner.
    pub mint_chunks: [BigUint; 2],
    /// Per-proof pad nonce of the output ciphertext, a public input of the
    /// default merge only; the merge-ring request omits it.
    pub output_ciphertext_salt: BigUint,
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
/// Owner signatures are checked by the Solana transaction.
/// Mirrors prover/server/prover/transfer_eddsa/params.go TransferParameters.
/// Its `Debug` redacts the blinding seed and every input's nullifier secret.
#[derive(Clone)]
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
    /// `spr_interface::tree_slot::pack_input_flags`.
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

// The `Debug` impls below destructure every field, so a field added later
// does not compile until it is printed or redacted here.

/// Shows whether the secret is filled in, never its value.
impl fmt::Debug for TransferInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            utxo,
            is_dummy,
            state_path_elements,
            state_path_index,
            nullifier_low_value,
            nullifier_next_value,
            nullifier_low_path_elements,
            nullifier_low_path_index,
            tree_slot,
            nullifier,
            owner_pk_hash,
            nullifier_secret,
        } = self;
        formatter
            .debug_struct("TransferInput")
            .field("utxo", utxo)
            .field("is_dummy", is_dummy)
            .field("state_path_elements", state_path_elements)
            .field("state_path_index", state_path_index)
            .field("nullifier_low_value", nullifier_low_value)
            .field("nullifier_next_value", nullifier_next_value)
            .field("nullifier_low_path_elements", nullifier_low_path_elements)
            .field("nullifier_low_path_index", nullifier_low_path_index)
            .field("tree_slot", tree_slot)
            .field("nullifier", nullifier)
            .field("owner_pk_hash", owner_pk_hash)
            .field(
                "nullifier_secret",
                &nullifier_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl fmt::Debug for MergeInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            inputs,
            output,
            tree_slots,
            output_tree_id,
            mint_chunks,
            output_ciphertext_salt,
            owner_pk_hash,
            user_nullifier_pk,
            user_nullifier_secret: _,
            external_data_hash,
            private_tx_hash,
            allow_dummy_inputs,
            public_input_hash,
            output_ring_data_hash,
            ring_program_id,
        } = self;
        formatter
            .debug_struct("MergeInputs")
            .field("inputs", inputs)
            .field("output", output)
            .field("tree_slots", tree_slots)
            .field("output_tree_id", output_tree_id)
            .field("mint_chunks", mint_chunks)
            .field("output_ciphertext_salt", output_ciphertext_salt)
            .field("owner_pk_hash", owner_pk_hash)
            .field("user_nullifier_pk", user_nullifier_pk)
            .field("user_nullifier_secret", &"<redacted>")
            .field("external_data_hash", external_data_hash)
            .field("private_tx_hash", private_tx_hash)
            .field("allow_dummy_inputs", allow_dummy_inputs)
            .field("public_input_hash", public_input_hash)
            .field("output_ring_data_hash", output_ring_data_hash)
            .field("ring_program_id", ring_program_id)
            .finish()
    }
}

impl fmt::Debug for TransferInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            inputs,
            outputs,
            tree_slots,
            output_tree_id,
            blinding_seed: _,
            external_data_hash,
            private_tx_hash,
            public_assets,
            public_amounts,
            ring_program_id,
            signer_pk_hashes,
            input_flags,
            published_output_owner_pk_hashes,
            cache,
            public_input_hash,
        } = self;
        formatter
            .debug_struct("TransferInputs")
            .field("inputs", inputs)
            .field("outputs", outputs)
            .field("tree_slots", tree_slots)
            .field("output_tree_id", output_tree_id)
            .field("blinding_seed", &"<redacted>")
            .field("external_data_hash", external_data_hash)
            .field("private_tx_hash", private_tx_hash)
            .field("public_assets", public_assets)
            .field("public_amounts", public_amounts)
            .field("ring_program_id", ring_program_id)
            .field("signer_pk_hashes", signer_pk_hashes)
            .field("input_flags", input_flags)
            .field(
                "published_output_owner_pk_hashes",
                published_output_owner_pk_hashes,
            )
            .field("cache", cache)
            .field("public_input_hash", public_input_hash)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{
        ConfidentialEddsaTransferInputs, EddsaAuthorization, MergeProofResult, TransferProofResult,
    };

    /// No other fixture field holds it. `Debug` prints a `BigUint` in decimal.
    fn secret() -> BigUint {
        BigUint::from_bytes_be(&[0x5a; 32])
    }

    fn input(nullifier_secret: Option<BigUint>) -> TransferInput {
        TransferInput {
            utxo: ProofInputUtxo::default(),
            is_dummy: BigUint::ZERO,
            state_path_elements: Vec::new(),
            state_path_index: BigUint::ZERO,
            nullifier_low_value: BigUint::ZERO,
            nullifier_next_value: BigUint::ZERO,
            nullifier_low_path_elements: Vec::new(),
            nullifier_low_path_index: BigUint::ZERO,
            tree_slot: BigUint::ZERO,
            nullifier: BigUint::from(9u8),
            owner_pk_hash: BigUint::ZERO,
            nullifier_secret,
        }
    }

    fn output() -> TransferOutput {
        TransferOutput {
            utxo: ProofInputUtxo::default(),
            is_dummy: BigUint::ZERO,
            hash: BigUint::ZERO,
            owner_pk_hash: BigUint::ZERO,
            nullifier_pk: BigUint::ZERO,
        }
    }

    fn transfer() -> TransferInputs {
        TransferInputs {
            inputs: vec![input(Some(secret()))],
            outputs: vec![output()],
            tree_slots: Default::default(),
            output_tree_id: BigUint::ZERO,
            blinding_seed: secret(),
            external_data_hash: BigUint::ZERO,
            private_tx_hash: BigUint::ZERO,
            public_assets: Default::default(),
            public_amounts: Default::default(),
            ring_program_id: BigUint::ZERO,
            signer_pk_hashes: Vec::new(),
            input_flags: BigUint::ZERO,
            published_output_owner_pk_hashes: Vec::new(),
            cache: CacheReadInputs::default(),
            public_input_hash: BigUint::ZERO,
        }
    }

    fn merge() -> MergeInputs {
        MergeInputs {
            inputs: vec![input(Some(secret()))],
            output: output(),
            tree_slots: Default::default(),
            output_tree_id: BigUint::ZERO,
            mint_chunks: Default::default(),
            output_ciphertext_salt: BigUint::ZERO,
            owner_pk_hash: BigUint::ZERO,
            user_nullifier_pk: BigUint::ZERO,
            user_nullifier_secret: secret(),
            external_data_hash: BigUint::ZERO,
            private_tx_hash: BigUint::ZERO,
            allow_dummy_inputs: BigUint::from(1u8),
            public_input_hash: BigUint::ZERO,
            output_ring_data_hash: BigUint::ZERO,
            ring_program_id: BigUint::ZERO,
        }
    }

    fn assert_redacted(value: &impl fmt::Debug) {
        for printed in [format!("{value:?}"), format!("{value:#?}")] {
            assert!(!printed.contains(&secret().to_string()), "{printed}");
            assert!(printed.contains("<redacted>"), "{printed}");
        }
    }

    #[test]
    fn debug_output_redacts_every_secret() {
        assert_redacted(&input(Some(secret())));
        assert_redacted(&transfer());
        assert_redacted(&merge());
        assert_redacted(&ConfidentialEddsaTransferInputs {
            transfer: transfer(),
            authorization: EddsaAuthorization {
                owner_public_key: [1; 32],
                owner_signature: [2; 64],
                message_digest: [3; 32],
            },
        });
        assert_redacted(&TransferProofResult {
            inputs: transfer(),
            public_input_hash: [0; 32],
            nullifiers: Vec::new(),
            output_hashes: Vec::new(),
            private_tx_hash: [0; 32],
            tree_contexts: Vec::new(),
            tree_ids: Vec::new(),
            input_tree_indexes: Vec::new(),
            cache_access: None,
        });
        assert_redacted(&MergeProofResult {
            inputs: merge(),
            public_input_hash: [0; 32],
            nullifiers: Vec::new(),
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            output_hash: [0; 32],
            private_tx_hash: [0; 32],
            external_data_hash: [0; 32],
            expiry_unix_ts: 0,
            cache_slot: None,
            ring_program_id: None,
            output_ring_data_hash: [0; 32],
            output_ciphertext_salt: Default::default(),
            output_ciphertext: Default::default(),
        });
    }

    /// Whether an input still waits for its authority stays visible.
    #[test]
    fn debug_output_shows_a_missing_secret() {
        assert!(format!("{:?}", input(None)).contains("nullifier_secret: None"));
        assert!(format!("{:?}", input(Some(BigUint::ZERO)))
            .contains(r#"nullifier_secret: Some("<redacted>")"#));
    }
}
