//! High-level builder for the 8-in/1-out policy-zone merge proof
//! (`merge_zone`). It is a faithful clone of the default merge
//! ([`crate::prover::merge`]) with two deltas: the merged output and every input
//! are bound to a shared `zone_program_id`, which is appended as the final
//! element of the merge public-input hash (SPP binds it from the CPI-calling
//! `zone_config`); and the owner signing/viewing `pk_field` are omitted from the
//! public inputs (a policy zone has no registry to bind owner identity against).

use num_bigint::BigUint;
use p256::SecretKey;
use solana_address::Address;
use zolana_interface::instruction::instruction_data::{
    merge_transact::{MergeExternalDataHash, MergeTransactIxData},
    merge_zone::MergeZoneIxData,
};
use zolana_keypair::{
    merge::{encrypt_verifiable, merge_public_contribution, MergeCiphertextPublicInputs},
    NullifierKey, P256Pubkey, PublicKey, SignatureType,
};
use zolana_transaction::{
    instructions::{
        merge_zone::PreparedMergeZone,
        transact::{no_address_hashes, private_tx_hash},
        types::SpendUtxo,
    },
    utxo::program_id_field,
    OutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::{be, hash_chain},
        merge::{
            dummy_p256_xy, merge_encrypted_utxo, merge_plaintext, right_align, signing_xy,
            uncompressed,
        },
        transact::{
            p256_and_eddsa::{assemble_inputs, assemble_outputs, OwnerMode, TransferSpendInput},
            witness::SpendProof,
        },
        MergeInputs,
    },
};

/// Policy-zone merge consolidates up to 8 inputs sharing one owner, asset,
/// nullifier secret, and `zone_program_id` into one output, verifiably encrypted
/// to the owner's viewing key. Identical to [`crate::prover::merge::MergeProver`]
/// except for the shared `zone_program_id` folded into the public-input hash and
/// stamped on every UTXO.
pub struct MergeZoneProver {
    pub inputs: Vec<TransferSpendInput>,
    pub output: OutputUtxo,
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

#[derive(Debug, Clone)]
pub struct MergeZoneProofResult {
    pub inputs: MergeInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    /// Per-input references into the tree's root caches (length 8; dummy slots
    /// mirror the first real input), for the `merge_zone` instruction data.
    pub utxo_tree_root_indices: Vec<u16>,
    pub nullifier_tree_root_indices: Vec<u16>,
    pub output_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// Recomputed on-chain from the instruction; surfaced so the caller need not
    /// re-derive it.
    pub external_data_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    /// The published merge ciphertext and the ephemeral `tx_viewing_pk` the owner
    /// uses to decrypt it back to the merged output's `(amount, asset, blinding)`.
    pub ciphertext: Vec<u8>,
    pub tx_viewing_pk: P256Pubkey,
    /// True when the owner is a Solana (ed25519) signer.
    pub eddsa_owner: bool,
}

impl MergeZoneProofResult {
    /// Assemble the `merge_zone` instruction data from this proof result and the
    /// packed 192-byte proof: the [`MergeTransactIxData`] body wrapped in a
    /// [`MergeZoneIxData`] with the single-use `merge_view_tag` indexing the merged
    /// output. The caller passes the result to the `MergeZone` builder with the
    /// tree / zone_config accounts.
    pub fn instruction_data(&self, proof: [u8; 192], merge_view_tag: [u8; 32]) -> MergeZoneIxData {
        MergeZoneIxData {
            merge_view_tag,
            merge: MergeTransactIxData {
                expiry_unix_ts: self.expiry_unix_ts,
                proof,
                output_utxo_hash: self.output_hash,
                nullifiers: self.nullifiers.clone(),
                utxo_tree_root_index: self.utxo_tree_root_indices.clone(),
                nullifier_tree_root_index: self.nullifier_tree_root_indices.clone(),
                private_tx_hash: self.private_tx_hash,
                encrypted_utxo: merge_encrypted_utxo(&self.tx_viewing_pk, &self.ciphertext),
                eddsa_owner: self.eddsa_owner,
            },
        }
    }
}

impl MergeZoneProver {
    pub fn build(mut self) -> Result<MergeZoneProofResult, ClientError> {
        // Stamp the shared zone on every input UTXO and the output so the per-UTXO
        // zone_program_id field matches the public-input commitment below.
        for spend in &mut self.inputs {
            if spend.proof.is_some() {
                spend.utxo.zone_program_id = Some(self.zone_program_id);
            }
        }
        self.output.zone_program_id = Some(self.zone_program_id);

        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::Merge)?;

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

        // Verifiable encryption of the merged output to the owner's viewing key.
        let plaintext = merge_plaintext(&self.output)?;
        let (ciphertext, tx_viewing_pk) =
            encrypt_verifiable(&self.tx_viewing_sk, &self.user_viewing_pk, &plaintext)?;
        let MergeCiphertextPublicInputs {
            tx_viewing_pk_lo: tx_pk_lo,
            tx_viewing_pk_hi: tx_pk_hi,
            ciphertext_hash: ct_hash,
        } = merge_public_contribution(&tx_viewing_pk, &ciphertext)?;

        // external_data_hash binds the published ciphertext blob and expiry to the
        // proof; merge_zone recomputes it identically from the instruction.
        let encrypted_utxo = merge_encrypted_utxo(&tx_viewing_pk, &ciphertext);
        let external_data_hash = MergeExternalDataHash {
            spp_instruction_discriminator: zolana_interface::instruction::tag::ZONE_MERGE_TRANSACT,
            expiry_unix_ts: self.expiry_unix_ts,
            output_utxo_hash: &output_hash,
            encrypted_utxo: &encrypted_utxo,
        }
        .hash()
        .map_err(|e| ClientError::Hasher(e.to_string()))?;

        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &no_address_hashes(assembled_inputs.input_hashes.len()),
            &external_data_hash,
        )?;

        // Owner signing pk_field, used to feed the ed25519 owner rail's
        // `owner_pk_hash` witness below (not a public input on the zone rail).
        let user_signing_pk_hash = self.signing_pubkey.owner_pk_field()?;

        // The policy-zone merge omits the owner-identity public inputs (no registry
        // binds them) and instead commits the zone's pk_field as the final element,
        // after the ciphertext hash. `zone_program_id_field` equals the on-chain
        // `solana_pk_hash(zone)` the program derives from the calling `zone_config`.
        let zone_program_id_field = program_id_field(&Some(self.zone_program_id))?;
        let public_input = hash_chain(&[
            hash_chain(&assembled_inputs.nullifiers)?,
            output_hash,
            hash_chain(&assembled_inputs.utxo_roots)?,
            hash_chain(&assembled_inputs.nullifier_tree_roots)?,
            private_tx,
            external_data_hash,
            tx_pk_lo,
            tx_pk_hi,
            ct_hash,
            zone_program_id_field,
        ])?;

        // Owner rail select, mirroring the merge circuit: a P256 owner witnesses its
        // real point (pk_field recomputed in-circuit, owner_pk_hash = 0); a
        // Solana owner witnesses a discarded dummy point and feeds its pk_field
        // through owner_pk_hash.
        let eddsa_owner = self.signing_pubkey.signature_type()? == SignatureType::Ed25519;
        let (pub_x, pub_y, owner_pk_hash) = if eddsa_owner {
            let (x, y) = dummy_p256_xy()?;
            (x, y, BigUint::from_bytes_be(&user_signing_pk_hash))
        } else {
            let (x, y) = signing_xy(&self.signing_pubkey.as_p256()?)?;
            (x, y, BigUint::ZERO)
        };
        let user_nullifier_pk = self.nullifier_key.pubkey()?;
        let user_nullifier_secret = right_align(self.nullifier_key.secret());
        let sk_bytes: [u8; 32] = self.tx_viewing_sk.to_bytes().into();
        let user_viewing_pubkey = uncompressed(&self.user_viewing_pk)?
            .iter()
            .map(|b| BigUint::from(*b))
            .collect();

        let output = assembled_outputs
            .outputs
            .into_iter()
            .next()
            .ok_or(ClientError::NoInputs)?;

        let inputs = MergeInputs {
            inputs: assembled_inputs.inputs,
            output,
            p256_pub_x: be(&pub_x),
            p256_pub_y: be(&pub_y),
            owner_pk_hash,
            user_nullifier_pk: be(&user_nullifier_pk),
            user_nullifier_secret: be(&user_nullifier_secret),
            tx_viewing_sk: BigUint::from_bytes_be(&sk_bytes),
            user_viewing_pubkey,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_input_hash: be(&public_input),
            // Top-level public input the merge-zone witness/circuit binds; equals the
            // final hash element and every per-UTXO zone_program_id.
            zone_program_id: be(&zone_program_id_field),
        };

        Ok(MergeZoneProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            utxo_tree_root_indices,
            nullifier_tree_root_indices,
            output_hash,
            private_tx_hash: private_tx,
            external_data_hash,
            expiry_unix_ts: self.expiry_unix_ts,
            ciphertext,
            tx_viewing_pk,
            eddsa_owner,
        })
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

        let mut spends = Vec::with_capacity(inputs.len());
        let mut real_index = 0;
        for spend in inputs {
            let SpendUtxo {
                utxo,
                nullifier_key,
                ..
            } = spend;
            let proof = if utxo.owner.is_zero() {
                None
            } else {
                let proof = proofs
                    .get(real_index)
                    .ok_or(ClientError::MissingInputMerkleProof { index: real_index })?
                    .clone();
                real_index += 1;
                Some(proof)
            };
            spends.push(TransferSpendInput {
                utxo,
                nullifier_key,
                data_hash: None,
                zone_data_hash: None,
                proof,
            });
        }

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
