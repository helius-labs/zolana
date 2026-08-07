//! High-level builder for the 8-in/1-out policy-ring merge proof
//! (`merge_ring`). It shares the whole merge flow with the default merge
//! ([`crate::prover::merge::MergeProver::common`]) and differs in two deltas: the merged
//! output and every input are bound to a shared `ring_program_id`, which is
//! appended as the final element of the merge public-input hash (SPP binds it
//! from the CPI-calling `ring_config`); and the owner signing `pk_field` is
//! omitted from the public inputs (a policy ring has no registry to bind owner
//! identity against).

use solana_address::Address;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_keypair::{NullifierKey, PublicKey};
use zolana_transaction::{
    instructions::merge_ring::PreparedMergeRing, utxo::program_id_proof_input_hash,
    SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        merge::{MergeProofResult, MergeProver},
        transact::{
            assembly::TransferSpendInput,
            witness::{attach_input_proofs, SpendProof},
        },
    },
    rpc::NonInclusionProof,
};

/// Policy-ring merge consolidates up to 8 inputs sharing one owner, asset,
/// nullifier secret, and `ring_program_id` into one output. Identical to
/// [`crate::prover::merge::MergeProver`] except for the shared `ring_program_id`
/// and the output `ring_data_hash` folded into the public-input hash.
pub struct MergeRingProver {
    pub inputs: Vec<TransferSpendInput>,
    pub output: SppProofOutputUtxo,
    /// Validity deadline; bound into `external_data_hash`, which the circuit treats
    /// as opaque and `merge_ring` recomputes from the instruction.
    pub expiry_unix_ts: u64,
    /// Owner identity shared by every input: the scheme-tagged signing pubkey
    /// (recomputes `user_owner_hash`) and the nullifier key (recomputes the shared
    /// `nullifier_pk` and every input nullifier).
    pub signing_pubkey: PublicKey,
    pub nullifier_key: NullifierKey,
    /// Ring program every input and the output are owned by. Its `pk_field`
    /// (`program_id_proof_input_hash(&Some(ring))` == on-chain `solana_pk_hash(ring)`) is the
    /// final public-input element and the value SPP binds from `ring_config`.
    pub ring_program_id: Address,
}

impl MergeRingProver {
    pub fn build(mut self) -> Result<MergeProofResult, ClientError> {
        // Stamp the shared ring on every input UTXO and the output so the per-UTXO
        // ring_program_id field matches the public-input commitment below.
        for spend in &mut self.inputs {
            if spend.proof.is_some() {
                spend.utxo.ring_program_id = Some(self.ring_program_id);
            }
        }
        self.output.ring_program_id = Some(self.ring_program_id);

        // The output ring-data hash the ring program selected; the merge-ring
        // circuit asserts it against the output's RingDataHash and folds it into
        // the public-input hash.
        let output_ring_data_hash = self.output.ring_data_hash.unwrap_or([0u8; 32]);

        // A ring merge is the default merge plus a ring binding: reuse its
        // shared computation under the `merge_ring` instruction tag.
        let ring_program_id = self.ring_program_id;
        let prover = MergeProver {
            inputs: self.inputs,
            output: self.output,
            expiry_unix_ts: self.expiry_unix_ts,
            signing_pubkey: self.signing_pubkey,
            nullifier_key: self.nullifier_key,
        };
        let external_data_hash =
            prover.external_data_hash(zolana_interface::instruction::tag::RING_MERGE_TRANSACT)?;
        let merge = prover.common(external_data_hash)?;

        // The policy-ring merge omits the owner-identity public input (no registry
        // binds it) and instead commits the output ring-data hash and the ring's
        // pk_field as the final elements.
        // `ring_program_id_proof_input_hash` equals the on-chain `solana_pk_hash(ring)` the
        // program derives from the calling `ring_config`.
        let ring_program_id_proof_input_hash = program_id_proof_input_hash(&Some(ring_program_id))?;
        let mut elements = merge.head.to_vec();
        elements.extend([output_ring_data_hash, ring_program_id_proof_input_hash]);
        let public_input = create_hash_chain_from_slice(&elements)?;

        Ok(merge.finish(
            public_input,
            be(&ring_program_id_proof_input_hash),
            be(&output_ring_data_hash),
        ))
    }
}

/// A prepared policy-ring merge plus the owner nullifier key and the fetched
/// Merkle proofs, ready to fold into a [`MergeRingProver`]. The nullifier key is
/// the secret the merge circuit proves ownership from; it is not carried on
/// [`PreparedMergeRing`], so the caller supplies it from the keypair.
pub struct MergeRingWitness {
    pub prepared: PreparedMergeRing,
    pub nullifier_key: NullifierKey,
    pub proofs: Vec<SpendProof>,
    pub dummy_nullifier_proofs: Vec<NonInclusionProof>,
}

impl TryFrom<MergeRingWitness> for MergeRingProver {
    type Error = ClientError;

    fn try_from(witness: MergeRingWitness) -> Result<Self, Self::Error> {
        let MergeRingWitness {
            prepared,
            nullifier_key,
            proofs,
            dummy_nullifier_proofs,
        } = witness;
        let PreparedMergeRing {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            ring_program_id,
        } = prepared;

        let spends = attach_input_proofs(inputs, &proofs, &dummy_nullifier_proofs)?;

        Ok(MergeRingProver {
            inputs: spends,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            ring_program_id,
        })
    }
}
