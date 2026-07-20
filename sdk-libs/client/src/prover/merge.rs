//! High-level builder for the 8-in/1-out merge proof. It reuses the spp transfer
//! input/output assembly verbatim ([`assemble_inputs`]/[`assemble_outputs`]);
//! only the verifiable encryption and the public-input-hash element set are
//! merge-specific.

use num_bigint::BigUint;
use p256::SecretKey;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_hasher::primitives::hash_bytes;
pub(crate) use zolana_hasher::primitives::right_align;
use zolana_interface::instruction::instruction_data::merge_transact::{
    MergeExternalDataHash, MergeTransactIxData,
};
use zolana_keypair::{
    merge::{encrypt_verifiable, merge_public_contribution, MergeCiphertextPublicInputs},
    NullifierKey, P256Pubkey, PublicKey, SignatureType,
};
use zolana_transaction::{
    instructions::{
        merge::PreparedMerge,
        transact::{spp_proof_inputs::asset_proof_input_hash, PrivateTxHash},
        types::SppProofInputUtxo,
    },
    EncryptedScheme, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        transact::{
            p256_and_eddsa::{assemble_inputs, assemble_outputs, OwnerMode, TransferSpendInput},
            witness::SpendProof,
        },
        MergeInputs,
    },
};

/// Merge consolidates up to 8 inputs sharing one owner, asset, and nullifier
/// secret into one output, verifiably encrypted to the owner's viewing key. The
/// owner is either rail: a P256 signing key recomputes its pk_field from the
/// witnessed point, a Solana (ed25519) signing key feeds its pk_field directly.
/// The input slots reuse [`TransferSpendInput`] (a `None` proof is a dummy);
/// there is exactly one real output.
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
    /// Owner viewing key (encryption recipient) and the ephemeral scalar. The
    /// scalar must be < BN254 modulus so it is a valid circuit witness.
    pub user_viewing_pk: P256Pubkey,
    pub tx_viewing_sk: SecretKey,
}

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
    /// The published merge ciphertext and the ephemeral `tx_viewing_pk` the owner
    /// uses to decrypt it back to the merged output's `(amount, asset, blinding)`.
    pub ciphertext: Vec<u8>,
    pub tx_viewing_pk: P256Pubkey,
    /// True when the owner is a Solana (ed25519) signer, so `merge_transact` derives
    /// `signing_pk_field` from the registry account owner instead of `owner_p256`.
    pub eddsa_owner: bool,
}

impl MergeProofResult {
    /// Assemble the `merge_transact` instruction data from this proof result and the
    /// packed 192-byte proof. The caller passes the result to the `MergeTransact`
    /// builder with the tree / protocol_config / user_record accounts.
    pub fn instruction_data(&self, proof: [u8; 192]) -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: self.expiry_unix_ts,
            proof,
            output_utxo_hash: self.output_hash,
            nullifiers: self.nullifiers.clone(),
            utxo_tree_root_index: self.utxo_tree_root_indices.clone(),
            nullifier_tree_root_index: self.nullifier_tree_root_indices.clone(),
            private_tx_hash: self.private_tx_hash,
            encrypted_utxo: merge_encrypted_utxo(&self.tx_viewing_pk, &self.ciphertext),
            eddsa_owner: self.eddsa_owner,
        }
    }
}

impl MergeProver {
    pub fn build(self) -> Result<MergeProofResult, ClientError> {
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
        // proof; merge_transact recomputes it identically from the instruction.
        let encrypted_utxo = merge_encrypted_utxo(&tx_viewing_pk, &ciphertext);
        let external_data_hash = MergeExternalDataHash {
            spp_instruction_discriminator: zolana_interface::instruction::tag::MERGE_TRANSACT,
            expiry_unix_ts: self.expiry_unix_ts,
            output_utxo_hash: &output_hash,
            encrypted_utxo: &encrypted_utxo,
        }
        .hash()?;

        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )
        .hash()?;

        // Owner identity public inputs (pk_field of the signing and viewing keys).
        // SPP checks both against the owner's registry record; the owner recombines
        // the signing pk_field with their nullifier_pk to get user_owner_hash, so
        // the owner need not be carried in the ciphertext.
        let user_signing_pk_hash = self.signing_pubkey.owner_proof_input_hash()?;
        let user_viewing_pk_hash = hash_bytes(self.user_viewing_pk.as_bytes())?;
        let public_input = create_hash_chain_from_slice(&[
            create_hash_chain_from_slice(&assembled_inputs.nullifiers)?,
            output_hash,
            create_hash_chain_from_slice(&assembled_inputs.utxo_roots)?,
            create_hash_chain_from_slice(&assembled_inputs.nullifier_tree_roots)?,
            private_tx,
            external_data_hash,
            user_signing_pk_hash,
            user_viewing_pk_hash,
            tx_pk_lo,
            tx_pk_hi,
            ct_hash,
        ])?;

        // Owner rail select, mirroring the merge circuit: a P256 owner witnesses its
        // real point (pk_field recomputed in-circuit, owner_pk_hash = 0); a
        // Solana owner witnesses a discarded dummy point and feeds its pk_field
        // through owner_pk_hash.
        let eddsa_owner = self.signing_pubkey.signature_type()? == SignatureType::Ed25519;
        let (pub_x, pub_y, owner_pk_hash) = if eddsa_owner {
            let (x, y) = P256Pubkey::generator().xy()?;
            (x, y, BigUint::from_bytes_be(&user_signing_pk_hash))
        } else {
            let (x, y) = self.signing_pubkey.as_p256()?.xy()?;
            (x, y, BigUint::ZERO)
        };
        let user_nullifier_pk = self.nullifier_key.pubkey()?;
        let user_nullifier_secret = right_align(self.nullifier_key.secret());
        let sk_bytes: [u8; 32] = self.tx_viewing_sk.to_bytes().into();
        let user_viewing_pubkey = self.user_viewing_pk.to_uncompressed()?
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
            // Default merge is non-zone; the merge-zone builder sets this.
            zone_program_id: BigUint::ZERO,
        };

        Ok(MergeProofResult {
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

/// Assembles the on-instruction `encrypted_utxo` payload in the unified output
/// encoding `borsh(MessageData::VerifiablyEncrypted([EncryptedScheme::Merge,
/// tx_viewing_pk(33), ciphertext]))`, the same form transact emits and
/// `Wallet::sync` decodes.
pub fn merge_encrypted_utxo(tx_viewing_pk: &P256Pubkey, ciphertext: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(1 + 33 + ciphertext.len());
    blob.push(EncryptedScheme::Merge.as_byte());
    blob.extend_from_slice(tx_viewing_pk.as_bytes());
    blob.extend_from_slice(ciphertext);
    zolana_event::encode_verifiably_encrypted(blob)
}

/// The merge bundle plaintext: amount (u64, 8 BE bytes) || asset field (32 BE
/// bytes) || blinding (31 BE bytes), all read from the merged output.
pub(crate) fn merge_plaintext(output: &SppProofOutputUtxo) -> Result<Vec<u8>, ClientError> {
    let mut pt = Vec::with_capacity(8 + 32 + 31);
    pt.extend_from_slice(&output.amount.to_be_bytes());
    pt.extend_from_slice(&asset_proof_input_hash(&output.asset)?);
    pt.extend_from_slice(&output.blinding);
    Ok(pt)
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
            user_viewing_pk,
            tx_viewing_sk,
        } = prepared;

        let mut spends = Vec::with_capacity(inputs.len());
        let mut real_index = 0;
        for spend in inputs {
            let SppProofInputUtxo {
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

        Ok(MergeProver {
            inputs: spends,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            user_viewing_pk,
            tx_viewing_sk,
        })
    }
}
