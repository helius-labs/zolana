use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::hash_chain::{create_hash_chain_from_slice, HashChain};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::merge_transact::MergeTransactIxDataRef,
    verifying_keys::{merge_36_1, merge_8_1, merge_ring_36_1, merge_ring_8_1},
};

use crate::instructions::verifier;

/// The owner-binding tail of the merge public-input hash, which differs by
/// variant. Modeling it as an enum keeps the two shapes mutually exclusive: the
/// default merge cannot carry a ring id, and the policy-ring merge cannot carry
/// owner-identity fields. The variant also selects the verifying key.
pub enum MergeOwnerBinding {
    /// Default merge (`merge_transact`): owner identity bound from the user
    /// registry record -- `pk_field(owner_p256)`. Verified against
    /// `merge_<n_inputs>_1`.
    Registry { signing_pk_field: [u8; 32] },
    /// Policy-ring merge (`merge_ring`): `pk_field(ring_program_id)` from the
    /// calling `ring_config`, plus the output `ring_data_hash` the ring program
    /// selected; the proof asserts it against the output's
    /// `Output.Utxo.RingDataHash`. Verified against `merge_ring_<n_inputs>_1`.
    Ring {
        ring_program_id: [u8; 32],
        output_ring_data_hash: [u8; 32],
    },
}

/// Derived public inputs the program resolves from the tree (and, for the default
/// merge, the registry), folded into the merge public-input hash alongside the
/// instruction fields.
pub struct MergeProofInputs {
    /// Left-folded chains over the per-input roots, in `ix.nullifiers` order.
    /// `input_count` is how many were folded and must equal the instruction's
    /// declared input count when the public input is assembled.
    pub utxo_root_chain: [u8; 32],
    pub nullifier_tree_root_chain: [u8; 32],
    pub input_count: u8,
    pub external_data_hash: [u8; 32],
    pub allow_dummy_inputs: [u8; 32],
    pub owner_binding: MergeOwnerBinding,
}

pub struct MergeProof<'a, 'data> {
    ix: &'a MergeTransactIxDataRef<'data>,
    // Borrowed rather than owned so assembling the proof does not copy the
    // derived inputs onto this frame on top of the caller's copy.
    derived: &'a MergeProofInputs,
}

impl<'a, 'data> MergeProof<'a, 'data> {
    pub fn new(ix: &'a MergeTransactIxDataRef<'data>, derived: &'a MergeProofInputs) -> Self {
        Self { ix, derived }
    }

    #[inline(never)]
    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let p = &self.ix.proof;
        let encoding_err = ShieldedPoolError::InvalidTransactProofEncoding;
        let proof = verifier::CompressedGroth16Proof {
            a: p.a,
            b: p.b,
            c: p.c,
            commitment: None,
        };
        let vk = self.verifying_key()?;
        verifier::verify_groth16(
            proof,
            public_input_hash,
            vk,
            encoding_err,
            ShieldedPoolError::TransactProofVerificationFailed,
        )
    }

    /// Select the verifying key from the owner binding and the declared input
    /// count.
    ///
    /// Both halves are load-bearing. The rail differs in what the
    /// public-input-hash tail binds (`merge_ring` commits `ring_program_id`), and
    /// the input count differs in the constraint system itself, because the
    /// hash prefix folds three chains whose length is the input count. Merge
    /// instruction data carries no circuit selector, so the count is implicit in
    /// `nullifiers.len()`; a shape with no key must be refused here rather than
    /// verified against a key for a different width.
    fn verifying_key(&self) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
        let input_count = self.ix.nullifiers.len();
        let vk = match (&self.derived.owner_binding, input_count) {
            (MergeOwnerBinding::Registry { .. }, 8) => &merge_8_1::VERIFYINGKEY,
            (MergeOwnerBinding::Registry { .. }, 36) => &merge_36_1::VERIFYINGKEY,
            (MergeOwnerBinding::Ring { .. }, 8) => &merge_ring_8_1::VERIFYINGKEY,
            (MergeOwnerBinding::Ring { .. }, 36) => &merge_ring_36_1::VERIFYINGKEY,
            // Unreachable through the instruction parse, which rejects any count
            // outside MERGE_SUPPORTED_INPUT_COUNTS. Kept fail-closed so adding a
            // count to that set without a key here cannot fall through to the
            // wrong verifying key.
            _ => return Err(ShieldedPoolError::InvalidMergeShape.into()),
        };
        Ok(vk)
    }

    /// The Poseidon hash chain the circuit folds into its single public input
    /// (`prover/server/circuits/spp_merge/{default,ring}.go`).
    ///
    /// Both variants share the same 7 leading elements (including the
    /// proof-wide dummy-input policy);
    /// the default merge then folds the owner's signing `pk_field` (bound from
    /// the user registry), while the policy-ring merge omits owner identity (no
    /// registry to bind it against) and appends the output `ring_data_hash` and
    /// `ring_program_id`.
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        let mut nullifiers = HashChain::new();
        for nullifier in self.ix.nullifiers.try_iter() {
            nullifiers.push(nullifier.map_err(|_| ProgramError::InvalidInstructionData)?)?;
        }
        let nullifiers = nullifiers.finish();
        // The root chains were folded over `ix.nullifiers`; requiring the folded
        // count to match replaces the bounds the fixed-width arrays gave.
        if usize::from(self.derived.input_count) != self.ix.nullifiers.len() {
            return Err(ShieldedPoolError::InvalidMergeShape.into());
        }
        let utxo_roots = self.derived.utxo_root_chain;
        let nullifier_tree_roots = self.derived.nullifier_tree_root_chain;

        let prefix = [
            nullifiers,
            *self.ix.output_utxo_hash,
            utxo_roots,
            nullifier_tree_roots,
            *self.ix.private_tx_hash,
            self.derived.external_data_hash,
            self.derived.allow_dummy_inputs,
        ];
        let prefix_hash = create_hash_chain_from_slice(&prefix)?;

        match &self.derived.owner_binding {
            MergeOwnerBinding::Ring {
                ring_program_id,
                output_ring_data_hash,
            } => create_hash_chain_from_slice(&[
                prefix_hash,
                *output_ring_data_hash,
                *ring_program_id,
            ])
            .map_err(Into::into),
            MergeOwnerBinding::Registry { signing_pk_field } => {
                create_hash_chain_from_slice(&[prefix_hash, *signing_pk_field]).map_err(Into::into)
            }
        }
    }
}
