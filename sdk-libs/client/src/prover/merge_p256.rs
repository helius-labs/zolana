//! High-level builder for the 8-in/1-out merge proof. It reuses the spp transfer
//! input/output assembly verbatim ([`assemble_inputs`]/[`assemble_outputs`]);
//! only the verifiable encryption and the public-input-hash element set are
//! merge-specific.

use num_bigint::BigUint;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use zolana_keypair::merge::{
    encrypt_merge, merge_public_contribution, MergeCiphertextPublicInputs,
};
use zolana_keypair::{NullifierKey, P256Pubkey, PublicKey};
use zolana_transaction::transaction::private_tx_hash;
use zolana_transaction::OutputUtxo;

use crate::error::ClientError;
use crate::private_transaction::field::{asset_field, be, hash_chain};
use crate::prover::transfer_p256::{assemble_inputs, assemble_outputs, TransferSpendInput};
use crate::prover::MergeInputs;

/// Merge consolidates up to 8 P256-owned inputs sharing one owner, asset, and
/// nullifier secret into one output, verifiably encrypted to the owner's viewing
/// key. The input slots reuse [`TransferSpendInput`] (a `None` proof is a dummy);
/// there is exactly one real output.
pub struct MergeProver {
    pub inputs: Vec<TransferSpendInput>,
    pub output: OutputUtxo,
    /// Binds the proof to the merge instruction; the circuit treats it as opaque.
    pub external_data_hash: [u8; 32],
    /// Owner identity shared by every input: the P256 signing pubkey (recomputes
    /// `user_owner_hash`) and the nullifier key (recomputes the shared
    /// `nullifier_pk` and every input nullifier).
    pub signing_pubkey: P256Pubkey,
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
    pub output_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// The published merge ciphertext and the ephemeral `tx_viewing_pk` the owner
    /// uses to decrypt it back to the merged output's `(amount, asset, blinding)`.
    pub ciphertext: Vec<u8>,
    pub tx_viewing_pk: P256Pubkey,
}

impl MergeProver {
    pub fn build(self) -> Result<MergeProofResult, ClientError> {
        let assembled_inputs = assemble_inputs(&self.inputs, true)?;
        // Merge has no Solana-owner path: every real input must be P256-owned.
        if assembled_inputs
            .solana_owner_pk_hashes
            .iter()
            .any(|h| h != &[0u8; 32])
        {
            return Err(ClientError::Prover(
                "merge inputs must all be P256-owned".to_string(),
            ));
        }

        let assembled_outputs = assemble_outputs(std::slice::from_ref(&self.output))?;
        let output_hash = *assembled_outputs
            .output_hashes
            .first()
            .ok_or(ClientError::NoInputs)?;

        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &self.external_data_hash,
        )?;

        // Verifiable encryption of the merged output to the owner's viewing key.
        let plaintext = merge_plaintext(&self.output)?;
        let (ciphertext, tx_viewing_pk) =
            encrypt_merge(&self.tx_viewing_sk, &self.user_viewing_pk, &plaintext)?;
        let MergeCiphertextPublicInputs {
            tx_viewing_pk_lo: tx_pk_lo,
            tx_viewing_pk_hi: tx_pk_hi,
            ciphertext_hash: ct_hash,
        } = merge_public_contribution(&tx_viewing_pk, &ciphertext)?;

        // Owner identity public inputs (pk_field of the signing and viewing keys).
        // SPP checks both against the owner's registry record; the owner recombines
        // the signing pk_field with their nullifier_pk to get user_owner_hash, so
        // the owner need not be carried in the ciphertext.
        let user_signing_pk_hash = PublicKey::from_p256(&self.signing_pubkey).hash()?;
        let user_viewing_pk_hash = PublicKey::from_p256(&self.user_viewing_pk).hash()?;
        let public_input = hash_chain(&[
            hash_chain(&assembled_inputs.nullifiers)?,
            output_hash,
            hash_chain(&assembled_inputs.utxo_roots)?,
            hash_chain(&assembled_inputs.nullifier_tree_roots)?,
            private_tx,
            self.external_data_hash,
            user_signing_pk_hash,
            user_viewing_pk_hash,
            tx_pk_lo,
            tx_pk_hi,
            ct_hash,
        ])?;

        let (pub_x, pub_y) = signing_xy(&self.signing_pubkey)?;
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
            user_nullifier_pk: be(&user_nullifier_pk),
            user_nullifier_secret: be(&user_nullifier_secret),
            tx_viewing_sk: BigUint::from_bytes_be(&sk_bytes),
            user_viewing_pubkey,
            external_data_hash: be(&self.external_data_hash),
            private_tx_hash: be(&private_tx),
            public_input_hash: be(&public_input),
        };

        Ok(MergeProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hash,
            private_tx_hash: private_tx,
            ciphertext,
            tx_viewing_pk,
        })
    }
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

fn right_align(bytes: &[u8; 31]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1..].copy_from_slice(bytes);
    out
}
