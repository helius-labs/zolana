use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::merge_transact::{MergeTransactIxDataRef, MERGE_INPUT_COUNT},
    verifying_keys::{merge_8_1, merge_ring_8_1},
};

use crate::instructions::verifier;

/// The owner-binding tail of the merge public-input hash, which differs by
/// variant. Modeling it as an enum keeps the two shapes mutually exclusive: the
/// default merge cannot carry a ring id, and the policy-ring merge cannot carry
/// owner-identity fields. The variant also selects the verifying key.
pub enum MergeOwnerBinding {
    /// Default merge (`merge_transact`): owner identity bound from the user
    /// registry record -- `pk_field(owner_p256)`. Verified against `merge_8_1`.
    Registry { signing_pk_field: [u8; 32] },
    /// Policy-ring merge (`merge_ring`): `pk_field(ring_program_id)` from the
    /// calling `ring_config`, plus the output `ring_data_hash` the ring program
    /// selected; the proof asserts it against the output's
    /// `Output.Utxo.RingDataHash`. Verified against `merge_ring_8_1`.
    Ring {
        ring_program_id: [u8; 32],
        output_ring_data_hash: [u8; 32],
    },
}

/// Derived public inputs the program resolves from the tree (and, for the default
/// merge, the registry), folded into the merge public-input hash alongside the
/// instruction fields.
pub struct MergeProofInputs {
    pub utxo_roots: [[u8; 32]; MERGE_INPUT_COUNT],
    pub nullifier_tree_roots: [[u8; 32]; MERGE_INPUT_COUNT],
    pub external_data_hash: [u8; 32],
    pub allow_dummy_inputs: [u8; 32],
    pub owner_binding: MergeOwnerBinding,
}

pub struct MergeProof<'a> {
    ix: &'a MergeTransactIxDataRef<'a>,
    derived: MergeProofInputs,
}

impl<'a> MergeProof<'a> {
    pub fn new(ix: &'a MergeTransactIxDataRef<'a>, derived: MergeProofInputs) -> Self {
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
        // The policy-ring merge (`merge_ring`) commits `ring_program_id`, so it uses
        // its own verifying key; the default-ring merge uses `merge_8_1`.
        let vk = match self.derived.owner_binding {
            MergeOwnerBinding::Registry { .. } => &merge_8_1::VERIFYINGKEY,
            MergeOwnerBinding::Ring { .. } => &merge_ring_8_1::VERIFYINGKEY,
        };
        verifier::verify_groth16(
            proof,
            public_input_hash,
            vk,
            encoding_err,
            ShieldedPoolError::TransactProofVerificationFailed,
        )
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
        let nullifiers = create_hash_chain_from_slice(&self.ix.nullifiers)?;
        let utxo_roots = create_hash_chain_from_slice(&self.derived.utxo_roots)?;
        let nullifier_tree_roots =
            create_hash_chain_from_slice(&self.derived.nullifier_tree_roots)?;

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
