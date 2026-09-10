use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{error::ProgramError, ProgramResult};
use tinyvec::ArrayVec;
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::merge_transact::MergeTransactIxDataRef,
    tree_slot::{populated_tree_slots_hash_chain, TreeSlot},
    verifying_keys::{merge_36_1, merge_8_1, merge_ring_36_1, merge_ring_8_1},
};

use crate::instructions::verifier;

/// The 7 shared prefix elements plus the widest variant tail (2 on the
/// policy-ring merge).
const MERGE_PUBLIC_INPUT_FIELDS: usize = 9;

/// The owner-binding tail of the merge public-input hash, which differs by
/// variant. Modeling it as an enum keeps the two shapes mutually exclusive: the
/// default merge cannot carry a ring id, and the policy-ring merge cannot carry
/// owner-identity fields. The variant also selects the verifying key.
pub enum MergeOwnerBinding {
    /// Default merge (`merge_transact`): owner identity bound from the user
    /// registry record -- the tagged owner identity of the registered key.
    /// Verified against `merge_<n_inputs>_1`.
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

/// Derived public inputs the program resolves from the trees (and, for the
/// default merge, the registry), folded into the merge public-input hash
/// alongside the instruction fields.
pub struct MergeProofInputs {
    /// Tree slot 0: `input_tree`'s id and the roots every input references.
    /// The circuit's remaining `INPUT_TREES - 1` slots stay all zero.
    pub tree_slot: TreeSlot,
    /// `tree_id_field` of the tree the merged output is appended to.
    pub output_tree_id: [u8; 32],
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
        let vk = self.verifying_key()?;
        verifier::verify_groth16(
            proof,
            public_input_hash,
            vk,
            encoding_err,
            ShieldedPoolError::TransactProofVerificationFailed,
        )
    }

    fn verifying_key(&self) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
        let vk = match (&self.derived.owner_binding, self.ix.nullifiers.len()) {
            (MergeOwnerBinding::Registry { .. }, 8) => &merge_8_1::VERIFYINGKEY,
            (MergeOwnerBinding::Registry { .. }, 36) => &merge_36_1::VERIFYINGKEY,
            (MergeOwnerBinding::Ring { .. }, 8) => &merge_ring_8_1::VERIFYINGKEY,
            (MergeOwnerBinding::Ring { .. }, 36) => &merge_ring_36_1::VERIFYINGKEY,
            _ => return Err(ShieldedPoolError::InvalidMergeShape.into()),
        };
        Ok(vk)
    }

    /// The 4-input Poseidon hash chain the circuit folds into its single public
    /// input (`prover/server/circuits/spp_merge/{default,ring}.go`, prefix from
    /// `spp_merge/shared/transaction.go` `CommonPublicInputs.Prefix`).
    ///
    /// Both variants share the same 7 leading elements (nullifier chain, output
    /// hash, tree slot chain, output tree id, private tx hash, external data
    /// hash, dummy-input policy); the default merge then appends the owner's
    /// signing identity (bound from the user registry), while the policy-ring
    /// merge omits owner identity (no registry to bind it against) and appends
    /// the output `ring_data_hash` and `ring_program_id`. The 8 or 9 elements
    /// are folded once: the 4-input fold does not compose over a prefix hash.
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        // The circuit's `TreeSlotsHashChain` over `[slot0, 0, 0, 0, 0]`: one
        // slot hash folded onto the precomputed four-slot zero suffix.
        let mut fields: ArrayVec<[[u8; 32]; MERGE_PUBLIC_INPUT_FIELDS]> = ArrayVec::new();
        fields.extend_from_slice(&[
            create_hash_chain_4_from_slice(&self.ix.nullifiers)?,
            *self.ix.output_utxo_hash,
            populated_tree_slots_hash_chain(core::slice::from_ref(&self.derived.tree_slot))?,
            self.derived.output_tree_id,
            *self.ix.private_tx_hash,
            self.derived.external_data_hash,
            self.derived.allow_dummy_inputs,
        ]);
        match &self.derived.owner_binding {
            MergeOwnerBinding::Ring {
                ring_program_id,
                output_ring_data_hash,
            } => fields.extend_from_slice(&[*output_ring_data_hash, *ring_program_id]),
            MergeOwnerBinding::Registry { signing_pk_field } => fields.push(*signing_pk_field),
        }
        create_hash_chain_4_from_slice(fields.as_slice()).map_err(Into::into)
    }
}
