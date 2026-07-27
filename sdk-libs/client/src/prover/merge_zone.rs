//! High-level builder for the 8-in/1-out policy-zone merge proof
//! (`merge_zone`). It shares the whole merge flow with the default merge
//! ([`crate::prover::merge::MergeProver::common`]) and differs in two deltas: the merged
//! output and every input are bound to a shared `zone_program_id`, which is
//! appended as the final element of the merge public-input hash (SPP binds it
//! from the CPI-calling `zone_config`); and the owner signing `pk_field` is
//! omitted from the public inputs (a policy zone has no registry to bind owner
//! identity against).

use solana_address::Address;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_keypair::{NullifierKey, PublicKey};
use zolana_transaction::{
    instructions::merge_zone::PreparedMergeZone, utxo::program_id_proof_input_hash,
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

/// Policy-zone merge consolidates up to 8 inputs sharing one owner, asset,
/// nullifier secret, and `zone_program_id` into one output. Identical to
/// [`crate::prover::merge::MergeProver`] except for the shared `zone_program_id`
/// and the output `zone_data_hash` folded into the public-input hash.
pub struct MergeZoneProver {
    pub inputs: Vec<TransferSpendInput>,
    pub output: SppProofOutputUtxo,
    /// Validity deadline; bound into `external_data_hash`, which the circuit treats
    /// as opaque and `merge_zone` recomputes from the instruction.
    pub expiry_unix_ts: u64,
    /// Owner identity shared by every input: the scheme-tagged signing pubkey
    /// (recomputes `user_owner_hash`) and the nullifier key (recomputes the shared
    /// `nullifier_pk` and every input nullifier).
    pub signing_pubkey: PublicKey,
    pub nullifier_key: NullifierKey,
    /// Zone program every input and the output are owned by. Its `pk_field`
    /// (`program_id_proof_input_hash(&Some(zone))` == on-chain `solana_pk_hash(zone)`) is the
    /// final public-input element and the value SPP binds from `zone_config`.
    pub zone_program_id: Address,
}

impl MergeZoneProver {
    pub fn build(mut self) -> Result<MergeProofResult, ClientError> {
        // Stamp the shared zone on every input UTXO and the output so the per-UTXO
        // zone_program_id field matches the public-input commitment below.
        for spend in &mut self.inputs {
            if spend.proof.is_some() {
                spend.utxo.zone_program_id = Some(self.zone_program_id);
            }
        }
        self.output.zone_program_id = Some(self.zone_program_id);

        // The output zone-data hash the zone program selected; the merge-zone
        // circuit asserts it against the output's ZoneDataHash and folds it into
        // the public-input hash.
        let output_zone_data_hash = self.output.zone_data_hash.unwrap_or([0u8; 32]);

        // A zone merge is the default merge plus a zone binding: reuse its
        // shared computation under the `merge_zone` instruction tag.
        let zone_program_id = self.zone_program_id;
        let merge = MergeProver {
            inputs: self.inputs,
            output: self.output,
            expiry_unix_ts: self.expiry_unix_ts,
            signing_pubkey: self.signing_pubkey,
            nullifier_key: self.nullifier_key,
        }
        .common(zolana_interface::instruction::tag::ZONE_MERGE_TRANSACT)?;

        // The policy-zone merge omits the owner-identity public input (no registry
        // binds it) and instead commits the output zone-data hash and the zone's
        // pk_field as the final elements.
        // `zone_program_id_proof_input_hash` equals the on-chain `solana_pk_hash(zone)` the
        // program derives from the calling `zone_config`.
        let zone_program_id_proof_input_hash = program_id_proof_input_hash(&Some(zone_program_id))?;
        let mut elements = merge.head.to_vec();
        elements.extend([output_zone_data_hash, zone_program_id_proof_input_hash]);
        let public_input = create_hash_chain_from_slice(&elements)?;

        Ok(merge.finish(
            public_input,
            be(&zone_program_id_proof_input_hash),
            be(&output_zone_data_hash),
        ))
    }
}

/// A prepared policy-zone merge plus the owner nullifier key and the fetched
/// Merkle proofs, ready to fold into a [`MergeZoneProver`]. The nullifier key is
/// the secret the merge circuit proves ownership from; it is not carried on
/// [`PreparedMergeZone`], so the caller supplies it from the keypair.
pub struct MergeZoneWitness {
    pub prepared: PreparedMergeZone,
    pub nullifier_key: NullifierKey,
    pub proofs: Vec<SpendProof>,
    pub dummy_nullifier_proofs: Vec<NonInclusionProof>,
}

impl TryFrom<MergeZoneWitness> for MergeZoneProver {
    type Error = ClientError;

    fn try_from(witness: MergeZoneWitness) -> Result<Self, Self::Error> {
        let MergeZoneWitness {
            prepared,
            nullifier_key,
            proofs,
            dummy_nullifier_proofs,
        } = witness;
        let PreparedMergeZone {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            zone_program_id,
        } = prepared;

        let spends = attach_input_proofs(inputs, &proofs, &dummy_nullifier_proofs)?;

        Ok(MergeZoneProver {
            inputs: spends,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            zone_program_id,
        })
    }
}
