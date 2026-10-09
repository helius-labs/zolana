use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_hasher::zero_suffix_hash_chain::create_padded_right_hash_chain_4;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::merge_transact::{
            merge_circuit_width, MergeBodyRef, MergeEnvelopeRef, MergeProofCommitmentRef,
        },
        tag::{MERGE_TRANSACT, RING_MERGE_TRANSACT},
    },
    merge_utils::merge_envelope_public_elements,
    tree_slot::{populated_tree_slots_hash_chain, TreeSlot},
    verifying_keys::{
        merge_24_1, merge_54_1, merge_8_1, merge_ring_24_1, merge_ring_54_1, merge_ring_8_1,
    },
};

use crate::instructions::verifier;

/// The owner-binding tail of the merge public-input hash, which differs by
/// variant. Modeling it as an enum keeps the two shapes mutually exclusive: the
/// default merge cannot carry a ring id, and the policy-ring merge cannot carry
/// the registry's signing identity. The variant also selects the verifying key
/// and carries the default rail's proof commitment and encrypted envelope, which
/// the ring rail does not have.
pub enum MergeOwnerBinding<'a> {
    /// Default merge (`merge_transact`): owner identity bound from the user
    /// registry record -- both the signing identity and nullifier public key.
    /// Verified against `merge_<n_inputs>_1`.
    Default {
        signing_pk_field: [u8; 32],
        nullifier_pk: [u8; 32],
        viewing_pk: [u8; 33],
        proof_commitment: MergeProofCommitmentRef<'a>,
        envelope: MergeEnvelopeRef<'a>,
    },
    /// Policy-ring merge (`merge_ring`): `pk_field(ring_program_id)` from the
    /// calling `ring_config`, plus the output `ring_data_hash` the ring program
    /// selected; the proof asserts it against the output's
    /// `Output.Utxo.RingDataHash`. Verified against `merge_ring_<n_inputs>_1`.
    Ring {
        ring_program_id: [u8; 32],
        output_ring_data_hash: [u8; 32],
    },
}

impl MergeOwnerBinding<'_> {
    /// The instruction each binding belongs to, which domain-separates the
    /// external data hash exactly as the binding selects the verifying key.
    pub fn instruction_tag(&self) -> u8 {
        match self {
            MergeOwnerBinding::Default { .. } => MERGE_TRANSACT,
            MergeOwnerBinding::Ring { .. } => RING_MERGE_TRANSACT,
        }
    }
}

/// Derived public inputs the program resolves from the trees (and, for the
/// default merge, the registry), folded into the merge public-input hash
/// alongside the instruction fields.
pub struct MergeProofInputs<'a> {
    /// Tree slot 0: `input_tree`'s id and the roots every input references.
    /// The circuit's remaining `INPUT_TREES - 1` slots stay all zero.
    pub tree_slot: TreeSlot,
    /// `tree_id_field` of the tree the merged output is appended to.
    pub output_tree_id: [u8; 32],
    pub external_data_hash: [u8; 32],
    pub allow_dummy_inputs: [u8; 32],
    pub owner_binding: MergeOwnerBinding<'a>,
}

pub struct MergeProof<'a> {
    ix: &'a MergeBodyRef<'a>,
    derived: MergeProofInputs<'a>,
}

impl<'a> MergeProof<'a> {
    pub fn new(ix: &'a MergeBodyRef<'a>, derived: MergeProofInputs<'a>) -> Self {
        Self { ix, derived }
    }

    #[inline(never)]
    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let p = &self.ix.proof;
        let encoding_err = ShieldedPoolError::InvalidTransactProofEncoding;
        let proof = verifier::Groth16Proof {
            a: p.a,
            b: p.b,
            c: p.c,
            commitment: match &self.derived.owner_binding {
                MergeOwnerBinding::Default {
                    proof_commitment, ..
                } => Some((proof_commitment.commitment, proof_commitment.commitment_pok)),
                MergeOwnerBinding::Ring { .. } => None,
            },
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

    /// The circuit width the sent nullifiers select; slots past them are
    /// compact padding.
    fn circuit_width(&self) -> Result<usize, ProgramError> {
        merge_circuit_width(self.ix.nullifiers.len())
            .ok_or(ShieldedPoolError::InvalidMergeShape.into())
    }

    fn verifying_key(&self) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
        let vk = match (&self.derived.owner_binding, self.circuit_width()?) {
            (MergeOwnerBinding::Default { .. }, 8) => &merge_8_1::VERIFYINGKEY,
            (MergeOwnerBinding::Default { .. }, 24) => &merge_24_1::VERIFYINGKEY,
            (MergeOwnerBinding::Default { .. }, 54) => &merge_54_1::VERIFYINGKEY,
            (MergeOwnerBinding::Ring { .. }, 8) => &merge_ring_8_1::VERIFYINGKEY,
            (MergeOwnerBinding::Ring { .. }, 24) => &merge_ring_24_1::VERIFYINGKEY,
            (MergeOwnerBinding::Ring { .. }, 54) => &merge_ring_54_1::VERIFYINGKEY,
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
    /// signing identity and nullifier public key (from the registry) followed by
    /// the envelope elements, while the policy-ring merge omits that identity (no
    /// registry to bind it against) and appends the output `ring_data_hash` and
    /// `ring_program_id`.
    ///
    /// Invariant: HashChain4 folds its first element alone and then three
    /// elements per Poseidon call, so the 7-element prefix (1 + 3 + 3) ends on
    /// a complete group. Continuing the chain from the prefix hash with the
    /// variant tail therefore equals folding the whole chain at once
    /// (9 elements for the ring rail, 13 for the default rail), which is what
    /// the circuit computes. A prefix length that left a partial group would
    /// break this equality.
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        // The circuit's `TreeSlotsHashChain` over `[slot0, 0, 0, 0, 0]`: one
        // slot hash folded onto the precomputed four-slot zero suffix.
        let prefix_hash = create_hash_chain_4_from_slice(&[
            create_padded_right_hash_chain_4(&self.ix.nullifiers, self.circuit_width()?)?,
            *self.ix.output_utxo_hash,
            populated_tree_slots_hash_chain(core::slice::from_ref(&self.derived.tree_slot))?,
            self.derived.output_tree_id,
            *self.ix.private_tx_hash,
            self.derived.external_data_hash,
            self.derived.allow_dummy_inputs,
        ])?;
        match &self.derived.owner_binding {
            MergeOwnerBinding::Ring {
                ring_program_id,
                output_ring_data_hash,
            } => create_hash_chain_4_from_slice(&[
                prefix_hash,
                *output_ring_data_hash,
                *ring_program_id,
            ]),
            MergeOwnerBinding::Default {
                signing_pk_field,
                nullifier_pk,
                viewing_pk,
                envelope,
                ..
            } => {
                let [recipient_lo, ephemeral_lo, packed, ciphertext_tail] =
                    merge_envelope_public_elements(
                        viewing_pk,
                        envelope.ephemeral_pk,
                        envelope.ciphertext,
                    );
                create_hash_chain_4_from_slice(&[
                    prefix_hash,
                    *signing_pk_field,
                    *nullifier_pk,
                    recipient_lo,
                    ephemeral_lo,
                    packed,
                    ciphertext_tail,
                ])
            }
        }
        .map_err(Into::into)
    }
}
