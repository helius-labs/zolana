//! High-level builder for the 8-in/1-out merge proof. It reuses the spp transfer
//! input/output assembly verbatim ([`assemble_inputs`]/[`assemble_outputs`]);
//! only the verifiable encryption and the public-input-hash element set are
//! merge-specific.

use num_bigint::BigUint;
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use zolana_interface::instruction::instruction_data::merge_transact::{
    MergeExternalDataHash, MergeTransactIxData,
};
use zolana_keypair::{
    merge::{encrypt_merge, merge_public_contribution, MergeCiphertextPublicInputs},
    NullifierKey, P256Pubkey, PublicKey, SignatureType,
};
use zolana_transaction::{transaction::private_tx_hash, OutputUtxo, MERGE};

use crate::{
    error::ClientError,
    private_transaction::field::{asset_field, be, hash_chain},
    prover::{
        transfer_p256::{assemble_inputs, assemble_outputs, TransferSpendInput},
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
    pub output: OutputUtxo,
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
        let assembled_inputs = assemble_inputs(&self.inputs, true)?;

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
            encrypt_merge(&self.tx_viewing_sk, &self.user_viewing_pk, &plaintext)?;
        let MergeCiphertextPublicInputs {
            tx_viewing_pk_lo: tx_pk_lo,
            tx_viewing_pk_hi: tx_pk_hi,
            ciphertext_hash: ct_hash,
        } = merge_public_contribution(&tx_viewing_pk, &ciphertext)?;

        // external_data_hash binds the published ciphertext blob and expiry to the
        // proof; merge_transact recomputes it identically from the instruction.
        let encrypted_utxo = merge_encrypted_utxo(&tx_viewing_pk, &ciphertext);
        let external_data_hash = MergeExternalDataHash {
            expiry_unix_ts: self.expiry_unix_ts,
            output_utxo_hash: &output_hash,
            encrypted_utxo: &encrypted_utxo,
        }
        .hash()
        .map_err(|e| ClientError::Hasher(e.to_string()))?;

        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )?;

        // Owner identity public inputs (pk_field of the signing and viewing keys).
        // SPP checks both against the owner's registry record; the owner recombines
        // the signing pk_field with their nullifier_pk to get user_owner_hash, so
        // the owner need not be carried in the ciphertext.
        let user_signing_pk_hash = self.signing_pubkey.hash()?;
        let user_viewing_pk_hash = PublicKey::from_p256(&self.user_viewing_pk).hash()?;
        let public_input = hash_chain(&[
            hash_chain(&assembled_inputs.nullifiers)?,
            output_hash,
            hash_chain(&assembled_inputs.utxo_roots)?,
            hash_chain(&assembled_inputs.nullifier_tree_roots)?,
            private_tx,
            external_data_hash,
            user_signing_pk_hash,
            user_viewing_pk_hash,
            tx_pk_lo,
            tx_pk_hi,
            ct_hash,
        ])?;

        // Owner rail select, mirroring the merge circuit: a P256 owner witnesses its
        // real point (pk_field recomputed in-circuit, solana_owner_pk_hash = 0); a
        // Solana owner witnesses a discarded dummy point and feeds its pk_field
        // through solana_owner_pk_hash.
        let eddsa_owner = self.signing_pubkey.signature_type()? == SignatureType::Ed25519;
        let (pub_x, pub_y, solana_owner_pk_hash) = if eddsa_owner {
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
            solana_owner_pk_hash,
            user_nullifier_pk: be(&user_nullifier_pk),
            user_nullifier_secret: be(&user_nullifier_secret),
            tx_viewing_sk: BigUint::from_bytes_be(&sk_bytes),
            user_viewing_pubkey,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_input_hash: be(&public_input),
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

/// Assembles the on-instruction `encrypted_utxo` blob:
/// `MERGE discriminator || tx_viewing_pk (33) || ciphertext (71)`.
pub fn merge_encrypted_utxo(tx_viewing_pk: &P256Pubkey, ciphertext: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(1 + 33 + ciphertext.len());
    blob.push(MERGE);
    blob.extend_from_slice(tx_viewing_pk.as_bytes());
    blob.extend_from_slice(ciphertext);
    blob
}

/// The merge bundle plaintext: amount (u64, 8 BE bytes) || asset field (32 BE
/// bytes) || blinding (31 BE bytes), all read from the merged output.
fn merge_plaintext(output: &OutputUtxo) -> Result<Vec<u8>, ClientError> {
    let mut pt = Vec::with_capacity(8 + 32 + 31);
    pt.extend_from_slice(&output.amount.to_be_bytes());
    pt.extend_from_slice(&asset_field(&output.asset)?);
    pt.extend_from_slice(&output.blinding);
    Ok(pt)
}

fn uncompressed(pk: &P256Pubkey) -> Result<[u8; 65], ClientError> {
    let point = pk.to_p256()?.to_encoded_point(false);
    let bytes = point.as_bytes();
    let mut out = [0u8; 65];
    if bytes.len() != 65 {
        return Err(ClientError::P256Signature(
            "uncompressed P256 point must be 65 bytes".into(),
        ));
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

fn signing_xy(pk: &P256Pubkey) -> Result<([u8; 32], [u8; 32]), ClientError> {
    let bytes = uncompressed(pk)?;
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    Ok((x, y))
}

/// The P256 generator coordinates, used as the discarded dummy `P256Pub` on the
/// Solana rail: the circuit always asserts the point is on the curve even though
/// the rail select discards its pk_field, so it must be a valid point.
fn dummy_p256_xy() -> Result<([u8; 32], [u8; 32]), ClientError> {
    let mut one = [0u8; 32];
    one[31] = 1;
    let sk = SecretKey::from_slice(&one).map_err(|e| ClientError::P256Signature(e.to_string()))?;
    let point = sk.public_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 {
        return Err(ClientError::P256Signature(
            "P256 generator point must be 65 bytes".into(),
        ));
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    Ok((x, y))
}

fn right_align(bytes: &[u8; 31]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1..].copy_from_slice(bytes);
    out
}
