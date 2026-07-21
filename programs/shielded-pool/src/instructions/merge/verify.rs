use pinocchio::{error::ProgramError, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::merge_transact::{MergeTransactIxDataRef, MERGE_INPUT_COUNT},
    merge_utils::{ciphertext_hash, pack33, pk_field_compressed},
    verifying_keys::{merge_8_1, merge_zone_8_1},
};

use crate::instructions::verifier;

const PROOF_ERR: ShieldedPoolError = ShieldedPoolError::TransactProofVerificationFailed;

/// The owner-binding tail of the merge public-input hash, which differs by
/// variant. Modeling it as an enum keeps the two shapes mutually exclusive: the
/// default merge cannot carry a zone id, and the policy-zone merge cannot carry
/// owner-identity fields. The variant also selects the verifying key.
pub enum MergeOwnerBinding {
    /// Default merge (`merge_transact`): owner identity bound from the user
    /// registry record -- `pk_field(owner_p256)` and `pk_field(viewing_pubkey)`.
    /// Verified against `merge_8_1`.
    Registry {
        signing_pk_field: [u8; 32],
        viewing_pk_field: [u8; 32],
    },
    /// Policy-zone merge (`merge_zone`): `pk_field(zone_program_id)` from the
    /// calling `zone_config`. Owner identity is omitted -- a policy zone has no
    /// registry to bind it against. Verified against `merge_zone_8_1`.
    Zone { zone_program_id: [u8; 32] },
}

/// Derived public inputs the program resolves from the tree (and, for the default
/// merge, the registry), folded into the merge public-input hash alongside the
/// instruction fields.
pub struct MergeProofInputs {
    pub utxo_roots: [[u8; 32]; MERGE_INPUT_COUNT],
    pub nullifier_tree_roots: [[u8; 32]; MERGE_INPUT_COUNT],
    pub external_data_hash: [u8; 32],
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
        // The merge circuit is P256-only, so the proof is always the
        // BSB22-committed five-tuple ([`P256ProofRef`], the layout `transact`'s
        // P256 rail shares).
        let p = &self.ix.proof;
        let encoding_err = ShieldedPoolError::InvalidTransactProofEncoding;
        let proof = verifier::CompressedGroth16Proof {
            a: p.a,
            b: p.b,
            c: p.c,
            commitment: Some((p.commitment, p.commitment_pok)),
        };
        // The policy-zone merge (`merge_zone`) commits `zone_program_id`, so it uses
        // its own verifying key; the default-zone merge uses `merge_8_1`.
        let vk = match self.derived.owner_binding {
            MergeOwnerBinding::Registry { .. } => &merge_8_1::VERIFYINGKEY,
            MergeOwnerBinding::Zone { .. } => &merge_zone_8_1::VERIFYINGKEY,
        };
        verifier::verify_groth16(proof, public_input_hash, vk, encoding_err, PROOF_ERR)
    }

    /// The Poseidon hash chain the circuit folds into its single public input
    /// (`prover/server/circuits/spp_merge/circuit.go` `mergePublicInputHash`).
    ///
    /// Both variants share the same 9 leading elements; the default merge then
    /// folds the owner's signing and viewing `pk_field` (bound from the user
    /// registry) for 11 total, while the policy-zone merge omits owner identity
    /// (no registry to bind it against) and appends `zone_program_id` as the
    /// final element for 10 total.
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        let tx_viewing_pk = self
            .ix
            .tx_viewing_pk()
            .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
        let ciphertext = self
            .ix
            .ciphertext()
            .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
        let (tx_viewing_pk_lo, tx_viewing_pk_hi) = pack33(tx_viewing_pk);
        let ct_hash = ciphertext_hash(ciphertext).map_err(|_| PROOF_ERR)?;

        let nullifiers = hash_chain(&self.ix.nullifiers)?;
        let utxo_roots = hash_chain(&self.derived.utxo_roots)?;
        let nullifier_tree_roots = hash_chain(&self.derived.nullifier_tree_roots)?;

        match &self.derived.owner_binding {
            MergeOwnerBinding::Zone { zone_program_id } => hash_chain(&[
                nullifiers,
                *self.ix.output_utxo_hash,
                utxo_roots,
                nullifier_tree_roots,
                *self.ix.private_tx_hash,
                self.derived.external_data_hash,
                tx_viewing_pk_lo,
                tx_viewing_pk_hi,
                ct_hash,
                *zone_program_id,
            ]),
            MergeOwnerBinding::Registry {
                signing_pk_field,
                viewing_pk_field,
            } => hash_chain(&[
                nullifiers,
                *self.ix.output_utxo_hash,
                utxo_roots,
                nullifier_tree_roots,
                *self.ix.private_tx_hash,
                self.derived.external_data_hash,
                *signing_pk_field,
                *viewing_pk_field,
                tx_viewing_pk_lo,
                tx_viewing_pk_hi,
                ct_hash,
            ]),
        }
    }
}

/// `pk_field` of a compressed P256 key, used by the processor to derive the
/// registry-bound owner identity inputs.
pub fn pk_field(compressed: &[u8; 33]) -> Result<[u8; 32], ProgramError> {
    pk_field_compressed(compressed).map_err(|_| ShieldedPoolError::InvalidUserRecord.into())
}

fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], ProgramError> {
    verifier::hash_chain(items, PROOF_ERR)
}
