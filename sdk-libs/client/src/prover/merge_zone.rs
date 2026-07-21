//! High-level builder for the 8-in/1-out policy-zone merge proof
//! (`merge_zone`). It shares the whole merge flow with the default merge
//! ([`crate::prover::merge::MergeProver::common`]) and differs in two deltas: the merged
//! output and every input are bound to a shared `zone_program_id`, which is
//! appended as the final element of the merge public-input hash (SPP binds it
//! from the CPI-calling `zone_config`); and the owner signing/viewing
//! `pk_field` are omitted from the public inputs (a policy zone has no registry
//! to bind owner identity against).

use p256::SecretKey;
use solana_address::Address;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_keypair::{NullifierKey, P256Pubkey, PublicKey};
use zolana_transaction::{
    instructions::merge_zone::PreparedMergeZone, utxo::program_id_field, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        merge::{MergeProofResult, MergeProver},
        transact::{
            p256_and_eddsa::TransferSpendInput,
            witness::{attach_input_proofs, SpendProof},
        },
    },
};

/// Policy-zone merge consolidates up to 8 inputs sharing one owner, asset,
/// nullifier secret, and `zone_program_id` into one output, verifiably encrypted
/// to the owner's viewing key. Identical to [`crate::prover::merge::MergeProver`]
/// except for the shared `zone_program_id` folded into the public-input hash and
/// stamped on every UTXO.
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
    /// Owner viewing key (encryption recipient) and the ephemeral scalar. The
    /// scalar must be < BN254 modulus so it is a valid circuit witness.
    pub user_viewing_pk: P256Pubkey,
    pub tx_viewing_sk: SecretKey,
    /// Zone program every input and the output are owned by. Its `pk_field`
    /// (`program_id_field(&Some(zone))` == on-chain `solana_pk_hash(zone)`) is the
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

        // A zone merge is the default merge plus a zone binding: reuse its
        // shared computation under the `merge_zone` instruction tag.
        let zone_program_id = self.zone_program_id;
        let merge = MergeProver {
            inputs: self.inputs,
            output: self.output,
            expiry_unix_ts: self.expiry_unix_ts,
            signing_pubkey: self.signing_pubkey,
            nullifier_key: self.nullifier_key,
            user_viewing_pk: self.user_viewing_pk,
            tx_viewing_sk: self.tx_viewing_sk,
        }
        .common(zolana_interface::instruction::tag::ZONE_MERGE_TRANSACT)?;

        // The policy-zone merge omits the owner-identity public inputs (no registry
        // binds them) and instead commits the zone's pk_field as the final element,
        // after the ciphertext hash. `zone_program_id_field` equals the on-chain
        // `solana_pk_hash(zone)` the program derives from the calling `zone_config`.
        let zone_program_id_field = program_id_field(&Some(zone_program_id))?;
        let mut elements = merge.head.to_vec();
        elements.extend([merge.tx_pk_lo, merge.tx_pk_hi, merge.ct_hash, zone_program_id_field]);
        let public_input = create_hash_chain_from_slice(&elements)?;

        // The zone binding is a top-level witness the merge-zone circuit checks;
        // it equals the final hash element and every per-UTXO zone_program_id.
        Ok(merge.finish(public_input, be(&zone_program_id_field)))
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
}

impl TryFrom<MergeZoneWitness> for MergeZoneProver {
    type Error = ClientError;

    fn try_from(witness: MergeZoneWitness) -> Result<Self, Self::Error> {
        let MergeZoneWitness {
            prepared,
            nullifier_key,
            proofs,
        } = witness;
        let PreparedMergeZone {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            user_viewing_pk,
            tx_viewing_sk,
            zone_program_id,
        } = prepared;

        let spends = attach_input_proofs(inputs, &proofs)?;

        Ok(MergeZoneProver {
            inputs: spends,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            user_viewing_pk,
            tx_viewing_sk,
            zone_program_id,
        })
    }
}
