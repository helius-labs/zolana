//! High-level builder for the 8-in/1-out merge proof. It reuses the spp transfer
//! input/output assembly verbatim ([`assemble_inputs`]/[`assemble_outputs`]);
//! only the deterministic output-blinding / dummy-nullifier derivations and the
//! public-input-hash element set are merge-specific.

use num_bigint::BigUint;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_interface::instruction::instruction_data::{
    merge_transact::{MergeExternalDataHash, MergeProof, MergeTransactIxData},
    merge_zone::MergeZoneIxData,
};
use zolana_keypair::{
    merge::merge_dummy_nullifier, NullifierKey, PublicKey, SignatureType,
};
use zolana_transaction::{
    instructions::{merge::PreparedMerge, transact::PrivateTxHash},
    SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        transact::{
            p256_and_eddsa::{assemble_inputs, assemble_outputs, OwnerMode, TransferSpendInput},
            witness::{attach_input_proofs, SpendProof},
        },
        MergeInputs, TransferInput, TransferOutput,
    },
};

/// Merge consolidates up to 8 inputs sharing one owner, asset, and nullifier
/// secret into one output whose blinding is derived from the first input's
/// blinding and the single-use `merge_view_tag`, so the owner recovers it by
/// reconstruction rather than decryption. The owner is either rail: a P256
/// signing key recomputes its pk_field from the witnessed point, a Solana
/// (ed25519) signing key feeds its pk_field directly. The input slots reuse
/// [`TransferSpendInput`] (a `None` proof is a dummy); there is exactly one
/// real output.
pub struct MergeProver {
    pub inputs: Vec<TransferSpendInput>,
    pub output: SppProofOutputUtxo,
    /// Validity deadline; bound into `external_data_hash`, which the circuit treats
    /// as opaque and `merge_transact` recomputes from the instruction.
    pub expiry_unix_ts: u64,
    /// Owner identity shared by every input: the scheme-tagged signing pubkey
    /// (recomputes `user_owner_hash`) and the nullifier key (recomputes the shared
    /// `nullifier_pk` and every input nullifier).
    pub signing_pubkey: PublicKey,
    pub nullifier_key: NullifierKey,
    /// Single-use nonce driving the output-blinding and dummy-nullifier
    /// derivations; SPP inserts it into the nullifier queue, so it cannot be
    /// reused across merges.
    pub merge_view_tag: [u8; 32],
}

/// The built merge witness and the instruction-data ingredients, produced by
/// both [`MergeProver`] (default) and
/// [`crate::prover::merge_zone::MergeZoneProver`] (policy zone); the two rails
/// differ only in their public-input tail and the zone binding inside `inputs`.
#[derive(Debug, Clone)]
pub struct MergeProofResult {
    pub inputs: MergeInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    /// Per-input references into the tree's root caches (length 8; dummy slots
    /// mirror the first real input), for the `merge_transact` instruction data.
    pub utxo_tree_root_indices: Vec<u16>,
    pub nullifier_tree_root_indices: Vec<u16>,
    pub output_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// Recomputed on-chain from the instruction; surfaced so the caller need not
    /// re-derive it.
    pub external_data_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    /// True when the owner is a Solana (ed25519) signer, so `merge_transact` derives
    /// `signing_pk_field` from the registry account owner instead of `owner_p256`.
    pub eddsa_owner: bool,
    /// The single-use merge nonce; stamped into the instruction data and emitted
    /// in the event so the wallet can reconstruct the output.
    pub merge_view_tag: [u8; 32],
}

impl MergeProofResult {
    /// Assemble the `merge_transact` instruction data from this proof result and
    /// the proof (`ProofCompressed::to_merge_proof`). The caller passes the
    /// result to the `MergeTransact` builder with the tree / protocol_config /
    /// user_record accounts.
    pub fn instruction_data(&self, proof: MergeProof) -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: self.expiry_unix_ts,
            proof,
            output_utxo_hash: self.output_hash,
            nullifiers: self.nullifiers.clone(),
            utxo_tree_root_index: self.utxo_tree_root_indices.clone(),
            nullifier_tree_root_index: self.nullifier_tree_root_indices.clone(),
            private_tx_hash: self.private_tx_hash,
            merge_view_tag: self.merge_view_tag,
            eddsa_owner: self.eddsa_owner,
        }
    }

    /// Assemble the `merge_zone` instruction data: the same `merge_transact`
    /// body wrapped in a [`MergeZoneIxData`] with the output `zone_data_hash`
    /// the zone program selected. The caller passes the result to the
    /// `MergeZone` builder with the tree / zone_config accounts.
    pub fn zone_instruction_data(
        &self,
        proof: MergeProof,
        output_zone_data_hash: [u8; 32],
    ) -> MergeZoneIxData {
        MergeZoneIxData {
            output_zone_data_hash,
            merge: self.instruction_data(proof),
        }
    }
}

impl MergeProver {
    pub fn build(self) -> Result<MergeProofResult, ClientError> {
        let merge = self.common(zolana_interface::instruction::tag::MERGE_TRANSACT)?;

        // Owner identity public input: SPP checks the signing pk_field against
        // the owner's registry record; the owner recombines it with their
        // nullifier_pk to get user_owner_hash.
        let mut elements = merge.head.to_vec();
        elements.extend([merge.user_signing_pk_hash, merge.merge_view_tag]);
        let public_input = create_hash_chain_from_slice(&elements)?;

        // Default merge is non-zone; the merge-zone builder sets the zone binding.
        Ok(merge.finish(public_input, BigUint::ZERO, BigUint::ZERO))
    }
}

/// Everything the default ([`MergeProver`]) and policy-zone
/// ([`crate::prover::merge_zone::MergeZoneProver`]) merges compute identically:
/// input/output assembly, the deterministic dummy nullifiers, and the shared
/// public-input prefix. Each rail appends its own public-input tail to
/// [`Self::head`] and calls [`Self::finish`].
pub(crate) struct CommonMerge {
    inputs: Vec<TransferInput>,
    output: TransferOutput,
    nullifiers: Vec<[u8; 32]>,
    utxo_tree_root_indices: Vec<u16>,
    nullifier_tree_root_indices: Vec<u16>,
    /// The public-input prefix both merge circuits share:
    /// `[nullifiers_chain, output_hash, utxo_roots_chain,
    /// nullifier_tree_roots_chain, private_tx_hash, external_data_hash,
    /// allow_dummy_inputs]`.
    pub head: [[u8; 32]; 7],
    output_hash: [u8; 32],
    private_tx_hash: [u8; 32],
    external_data_hash: [u8; 32],
    expiry_unix_ts: u64,
    pub user_signing_pk_hash: [u8; 32],
    pub merge_view_tag: [u8; 32],
    eddsa_owner: bool,
    owner_pk_hash: BigUint,
    user_nullifier_pk: [u8; 32],
    user_nullifier_secret: [u8; 32],
}

impl MergeProver {
    /// The computation both merge rails share, parameterized only by the
    /// instruction tag (`merge_transact` or `merge_zone`) bound into
    /// `external_data_hash`. Callers append their rail's public-input tail to
    /// [`CommonMerge::head`] and call [`CommonMerge::finish`].
    pub(crate) fn common(
        &self,
        spp_instruction_discriminator: u8,
    ) -> Result<CommonMerge, ClientError> {
        // Slot zero must be real: the circuit derives the output blinding from
        // its blinding.
        if self.inputs.first().is_none() || self.inputs[0].proof.is_none() {
            return Err(ClientError::NoInputs);
        }
        let mut assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::Merge)?;

        // Dummy slots publish deterministic nullifiers derived from the merge
        // view tag; override the placeholder nullifiers the generic assembly
        // computed from the dummies' blindings.
        for (i, spend) in self.inputs.iter().enumerate() {
            if spend.proof.is_none() {
                let dummy = merge_dummy_nullifier(&self.merge_view_tag, i as u8)?;
                assembled_inputs.nullifiers[i] = dummy;
                assembled_inputs.inputs[i].nullifier = BigUint::from_bytes_be(&dummy);
            }
        }

        let utxo_tree_root_indices: Vec<u16> = assembled_inputs
            .root_indices
            .iter()
            .map(|(u, _)| *u)
            .collect();
        let nullifier_tree_root_indices: Vec<u16> = assembled_inputs
            .root_indices
            .iter()
            .map(|(_, n)| *n)
            .collect();

        let assembled_outputs = assemble_outputs(std::slice::from_ref(&self.output))?;
        let output_hash = *assembled_outputs
            .output_hashes
            .first()
            .ok_or(ClientError::NoInputs)?;

        // external_data_hash binds the instruction's discriminator, expiry, and
        // output commitment to the proof; the program recomputes it identically.
        let external_data_hash = MergeExternalDataHash {
            spp_instruction_discriminator,
            expiry_unix_ts: self.expiry_unix_ts,
            output_utxo_hash: &output_hash,
        }
        .hash()?;

        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )
        .hash()?;

        let user_signing_pk_hash = self.signing_pubkey.owner_pk_field()?;
        let head = [
            create_hash_chain_from_slice(&assembled_inputs.nullifiers)?,
            output_hash,
            create_hash_chain_from_slice(&assembled_inputs.utxo_roots)?,
            create_hash_chain_from_slice(&assembled_inputs.nullifier_tree_roots)?,
            private_tx,
            external_data_hash,
            super::transact::p256_and_eddsa::bool_field(true),
        ];

        let eddsa_owner = self.signing_pubkey.signature_type()? == SignatureType::Ed25519;
        let owner_pk_hash = BigUint::from_bytes_be(&user_signing_pk_hash);
        let user_nullifier_pk = self.nullifier_key.pubkey()?;
        let mut user_nullifier_secret = [0u8; 32];
        user_nullifier_secret[1..].copy_from_slice(self.nullifier_key.secret());

        let output = assembled_outputs
            .outputs
            .into_iter()
            .next()
            .ok_or(ClientError::NoInputs)?;

        Ok(CommonMerge {
            inputs: assembled_inputs.inputs,
            output,
            nullifiers: assembled_inputs.nullifiers,
            utxo_tree_root_indices,
            nullifier_tree_root_indices,
            head,
            output_hash,
            private_tx_hash: private_tx,
            external_data_hash,
            expiry_unix_ts: self.expiry_unix_ts,
            user_signing_pk_hash,
            merge_view_tag: self.merge_view_tag,
            eddsa_owner,
            owner_pk_hash,
            user_nullifier_pk,
            user_nullifier_secret,
        })
    }
}

impl CommonMerge {
    /// Fold the rail's completed public-input hash, zone binding, and output
    /// zone-data hash (both zero for the default merge) into the final witness
    /// and proof result.
    pub(crate) fn finish(
        self,
        public_input: [u8; 32],
        zone_program_id: BigUint,
        output_zone_data_hash: BigUint,
    ) -> MergeProofResult {
        let inputs = MergeInputs {
            inputs: self.inputs,
            output: self.output,
            owner_pk_hash: self.owner_pk_hash,
            user_nullifier_pk: be(&self.user_nullifier_pk),
            user_nullifier_secret: be(&self.user_nullifier_secret),
            merge_view_tag: be(&self.merge_view_tag),
            external_data_hash: be(&self.external_data_hash),
            private_tx_hash: be(&self.private_tx_hash),
            allow_dummy_inputs: BigUint::from(1u8),
            public_input_hash: be(&public_input),
            output_zone_data_hash,
            zone_program_id,
        };
        MergeProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: self.nullifiers,
            utxo_tree_root_indices: self.utxo_tree_root_indices,
            nullifier_tree_root_indices: self.nullifier_tree_root_indices,
            output_hash: self.output_hash,
            private_tx_hash: self.private_tx_hash,
            external_data_hash: self.external_data_hash,
            expiry_unix_ts: self.expiry_unix_ts,
            eddsa_owner: self.eddsa_owner,
            merge_view_tag: self.merge_view_tag,
        }
    }
}

/// A prepared merge plus the owner nullifier key and the fetched Merkle proofs,
/// ready to fold into a [`MergeProver`]. The nullifier key is the secret the merge
/// circuit proves ownership from; it is not carried on [`PreparedMerge`], so the
/// caller supplies it from the keypair.
pub struct MergeWitness {
    pub prepared: PreparedMerge,
    pub nullifier_key: NullifierKey,
    pub proofs: Vec<SpendProof>,
}

impl TryFrom<MergeWitness> for MergeProver {
    type Error = ClientError;

    fn try_from(witness: MergeWitness) -> Result<Self, Self::Error> {
        let MergeWitness {
            prepared,
            nullifier_key,
            proofs,
        } = witness;
        let PreparedMerge {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            merge_view_tag,
        } = prepared;

        let mut spends = attach_input_proofs(inputs, &proofs, &[])?;
        // Default-merge inputs are plain utxos; no data hashes ride along.
        for spend in &mut spends {
            spend.data_hash = None;
            spend.zone_data_hash = None;
        }

        Ok(MergeProver {
            inputs: spends,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            merge_view_tag,
        })
    }
}
