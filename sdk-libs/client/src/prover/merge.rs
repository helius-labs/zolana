//! High-level builder for the n-in/1-out merge proof, where n is the padded
//! shape the prepared merge chose. It reuses the spp transfer
//! input/output assembly verbatim ([`assemble_inputs`]/[`assemble_outputs`]);
//! only the deterministic output-blinding / dummy-nullifier derivations and the
//! public-input-hash element set are merge-specific.

use num_bigint::BigUint;
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_interface::{
    instruction::instruction_data::{
        merge_ring::MergeRingIxData,
        merge_transact::{MergeExternalDataHash, MergeProof, MergeTransactIxData},
    },
    tree_slot::{tree_id_field, tree_slots_hash_chain},
    INPUT_TREES,
};
use zolana_keypair::{Curve, NullifierKey, PublicKey};
use zolana_transaction::{
    instructions::{
        merge::{merge_dummy_nullifier, merge_private_tx_blinding, PreparedMerge},
        transact::PrivateTxHash,
    },
    SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        transact::{
            assembly::{assemble_inputs, assemble_outputs, OwnerMode, TransferSpendInput},
            witness::{attach_input_proofs, SpendProof},
        },
        MergeInputs, TransferInput, TransferOutput, TreeSlotFields,
    },
    rpc::NonInclusionProof,
};

/// Merge consolidates up to `MAX_MERGE_INPUTS` inputs sharing one owner, asset, and nullifier
/// secret into one output whose blinding is derived from the owner's nullifier
/// secret and the first input's nullifier, so the owner recovers it by
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
    /// Raw id of the tree the merged output is appended to.
    pub output_tree_id: u16,
}

/// The built merge witness and the instruction-data ingredients, produced by
/// both [`MergeProver`] (default) and
/// [`crate::prover::merge_ring::MergeRingProver`] (policy ring); the two rails
/// differ only in their public-input tail and the ring binding inside `inputs`.
#[derive(Debug, Clone)]
pub struct MergeProofResult {
    pub inputs: MergeInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    /// Indexes into `input_tree`'s UTXO and nullifier root caches. Every
    /// input, dummies included, is proven against the same pair of roots;
    /// [`Self::instruction_data`] repeats them per input.
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
    pub output_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// Recomputed on-chain from the instruction; surfaced so the caller need not
    /// re-derive it.
    pub external_data_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    /// True when the owner is a Solana (ed25519) signer, so `merge_transact` derives
    /// `signing_pk_field` from the registry account owner instead of `owner_p256`.
    pub eddsa_owner: bool,
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
            utxo_tree_root_index: vec![self.utxo_tree_root_index; self.nullifiers.len()],
            nullifier_tree_root_index: vec![self.nullifier_tree_root_index; self.nullifiers.len()],
            private_tx_hash: self.private_tx_hash,
            eddsa_owner: self.eddsa_owner,
        }
    }

    /// Assemble the `merge_ring` instruction data: the same `merge_transact`
    /// body wrapped in a [`MergeRingIxData`] with the output `ring_data_hash`
    /// the ring program selected. The caller passes the result to the
    /// `MergeRing` builder with the tree / ring_config accounts.
    pub fn ring_instruction_data(
        &self,
        proof: MergeProof,
        output_ring_data_hash: [u8; 32],
    ) -> MergeRingIxData {
        MergeRingIxData {
            output_ring_data_hash,
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
        elements.push(merge.user_signing_pk_hash);
        let public_input = create_hash_chain_4_from_slice(&elements)?;

        // Default merge is non-ring; the merge-ring builder sets the ring binding.
        Ok(merge.finish(public_input, BigUint::ZERO, BigUint::ZERO))
    }
}

/// Everything the default ([`MergeProver`]) and policy-ring
/// ([`crate::prover::merge_ring::MergeRingProver`]) merges compute identically:
/// input/output assembly, the deterministic dummy nullifiers, and the shared
/// public-input prefix. Each rail appends its own public-input tail to
/// [`Self::head`] and calls [`Self::finish`].
pub(crate) struct CommonMerge {
    inputs: Vec<TransferInput>,
    output: TransferOutput,
    nullifiers: Vec<[u8; 32]>,
    tree_slots: [TreeSlotFields; INPUT_TREES],
    output_tree_id: u16,
    utxo_tree_root_index: u16,
    nullifier_tree_root_index: u16,
    /// The public-input prefix both merge circuits share:
    /// `[nullifiers_chain, output_hash, tree_slots_chain, output_tree_id,
    /// private_tx_hash, external_data_hash, allow_dummy_inputs]`.
    pub head: [[u8; 32]; 7],
    output_hash: [u8; 32],
    private_tx_hash: [u8; 32],
    external_data_hash: [u8; 32],
    expiry_unix_ts: u64,
    pub user_signing_pk_hash: [u8; 32],
    eddsa_owner: bool,
    owner_pk_hash: BigUint,
    user_nullifier_pk: [u8; 32],
    user_nullifier_secret: [u8; 32],
}

impl MergeProver {
    /// The computation both merge rails share, parameterized only by the
    /// instruction tag (`merge_transact` or `merge_ring`) bound into
    /// `external_data_hash`. Callers append their rail's public-input tail to
    /// [`CommonMerge::head`] and call [`CommonMerge::finish`].
    pub(crate) fn common(
        &self,
        spp_instruction_discriminator: u8,
    ) -> Result<CommonMerge, ClientError> {
        // Slot zero must be real: its single-use nullifier seeds the
        // deterministic output blinding and dummy nullifiers.
        if !self
            .inputs
            .first()
            .is_some_and(|first| first.proof.is_some())
        {
            return Err(ClientError::NoInputs);
        }
        let mut assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::Merge)?;

        // Dummy slots publish deterministic nullifiers derived from the
        // owner's nullifier secret and the first real nullifier; override the
        // placeholder nullifiers the generic assembly computed from the
        // dummies' blindings.
        let first_nullifier = *assembled_inputs
            .nullifiers
            .first()
            .ok_or(ClientError::NoInputs)?;
        for ((slot, nullifier), input) in self
            .inputs
            .iter()
            .enumerate()
            .zip(assembled_inputs.nullifiers.iter_mut())
            .zip(assembled_inputs.inputs.iter_mut())
        {
            let (index, spend) = slot;
            if spend.proof.is_some() {
                continue;
            }
            let index = u8::try_from(index).map_err(|_| ClientError::TooManyInputs {
                got: self.inputs.len(),
                max: usize::from(u8::MAX),
            })?;
            let dummy = merge_dummy_nullifier(&self.nullifier_key, &first_nullifier, index)?;
            *nullifier = dummy;
            input.nullifier = BigUint::from_bytes_be(&dummy);
        }

        let assembled_outputs =
            assemble_outputs(std::slice::from_ref(&self.output), self.output_tree_id)?;
        let output_hash = *assembled_outputs
            .output_hashes
            .first()
            .ok_or(ClientError::MissingOutput)?;

        // external_data_hash binds the instruction's discriminator, expiry, and
        // output commitment to the proof; the program recomputes it identically.
        let external_data_hash = MergeExternalDataHash {
            spp_instruction_discriminator,
            expiry_unix_ts: self.expiry_unix_ts,
            output_utxo_hash: &output_hash,
        }
        .hash()?;

        // Merge has no blinding seed: the owner's nullifier secret is
        // already owner-only, and the first nullifier makes the blinding unique
        // to one accepted merge.
        let private_tx_blinding = merge_private_tx_blinding(&self.nullifier_key, &first_nullifier)?;
        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
            &private_tx_blinding,
        )
        .hash()?;

        let user_signing_pk_hash = self.signing_pubkey.owner_proof_input_hash()?;
        let head = [
            create_hash_chain_4_from_slice(&assembled_inputs.nullifiers)?,
            output_hash,
            tree_slots_hash_chain(&assembled_inputs.tree_slots)?,
            tree_id_field(self.output_tree_id),
            private_tx,
            external_data_hash,
            super::transact::assembly::bool_field(true),
        ];

        let eddsa_owner = match self.signing_pubkey.curve()? {
            Curve::Ed25519 | Curve::Pda => true,
            Curve::P256 => false,
        };
        let owner_pk_hash = BigUint::from_bytes_be(&user_signing_pk_hash);
        let user_nullifier_pk = self.nullifier_key.pubkey()?;
        let mut user_nullifier_secret = [0u8; 32];
        user_nullifier_secret[1..].copy_from_slice(&*self.nullifier_key.secret());

        let output = assembled_outputs
            .outputs
            .into_iter()
            .next()
            .ok_or(ClientError::NoInputs)?;

        Ok(CommonMerge {
            inputs: assembled_inputs.inputs,
            output,
            nullifiers: assembled_inputs.nullifiers,
            tree_slots: TreeSlotFields::encode_all(&assembled_inputs.tree_slots),
            output_tree_id: self.output_tree_id,
            utxo_tree_root_index: assembled_inputs.utxo_tree_root_index,
            nullifier_tree_root_index: assembled_inputs.nullifier_tree_root_index,
            head,
            output_hash,
            private_tx_hash: private_tx,
            external_data_hash,
            expiry_unix_ts: self.expiry_unix_ts,
            user_signing_pk_hash,
            eddsa_owner,
            owner_pk_hash,
            user_nullifier_pk,
            user_nullifier_secret,
        })
    }
}

impl CommonMerge {
    /// Fold the rail's completed public-input hash, ring binding, and output
    /// ring-data hash (both zero for the default merge) into the final witness
    /// and proof result.
    pub(crate) fn finish(
        self,
        public_input: [u8; 32],
        ring_program_id: BigUint,
        output_ring_data_hash: BigUint,
    ) -> MergeProofResult {
        let inputs = MergeInputs {
            inputs: self.inputs,
            output: self.output,
            tree_slots: self.tree_slots,
            output_tree_id: BigUint::from(self.output_tree_id),
            owner_pk_hash: self.owner_pk_hash,
            user_nullifier_pk: be(&self.user_nullifier_pk),
            user_nullifier_secret: be(&self.user_nullifier_secret),
            external_data_hash: be(&self.external_data_hash),
            private_tx_hash: be(&self.private_tx_hash),
            allow_dummy_inputs: BigUint::from(1u8),
            public_input_hash: be(&public_input),
            output_ring_data_hash,
            ring_program_id,
        };
        MergeProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: self.nullifiers,
            utxo_tree_root_index: self.utxo_tree_root_index,
            nullifier_tree_root_index: self.nullifier_tree_root_index,
            output_hash: self.output_hash,
            private_tx_hash: self.private_tx_hash,
            external_data_hash: self.external_data_hash,
            expiry_unix_ts: self.expiry_unix_ts,
            eddsa_owner: self.eddsa_owner,
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
    pub dummy_nullifier_proofs: Vec<NonInclusionProof>,
}

impl TryFrom<MergeWitness> for MergeProver {
    type Error = ClientError;

    fn try_from(witness: MergeWitness) -> Result<Self, Self::Error> {
        let MergeWitness {
            prepared,
            nullifier_key,
            proofs,
            dummy_nullifier_proofs,
        } = witness;
        let PreparedMerge {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            output_tree_id,
        } = prepared;

        let mut spends = attach_input_proofs(inputs, &proofs, &dummy_nullifier_proofs)?;
        // Default-merge inputs are plain utxos; no data hashes ride along.
        for spend in &mut spends {
            spend.data_hash = None;
            spend.ring_data_hash = None;
        }

        Ok(MergeProver {
            inputs: spends,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            output_tree_id,
        })
    }
}
