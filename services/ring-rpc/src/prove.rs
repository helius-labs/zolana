//! Audit proofs for clients that cannot link the Go circuit. The witness is the
//! secret the auditor key opens anyway, so the RPC learns nothing new.

use custom_ring_program::instructions::transact::{AuditProof, AuditPublicInput};
use custom_ring_prover::{AuditorKeyEncryptionProofInputs, ProofError};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_keypair::{KeypairError, P256Pubkey, ViewingKey};
use zolana_ring_client::{encrypt_tx_viewing_sk, AuditEncryptionError};

pub struct AuditWitness {
    pub private_tx_hash: [u8; 32],
    pub tx_viewing_sk: Zeroizing<[u8; 32]>,
    pub eph_sk: Zeroizing<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum AuditProveError {
    #[error("invalid scalar: {0}")]
    Scalar(#[from] KeypairError),
    #[error("auditor encryption failed: {0}")]
    Encryption(#[from] AuditEncryptionError),
    #[error("the auditor key does not encode as uncompressed SEC1")]
    UncompressedEncoding,
    #[error("public input hashing failed")]
    Hashing,
    #[error(transparent)]
    Proof(#[from] ProofError),
}

/// The ciphertext is recomputed from the scalars, so the proof binds only the
/// message the transaction publishes.
pub fn prove_auditor_key_encryption(
    witness: &AuditWitness,
    auditor_pk: &P256Pubkey,
) -> Result<AuditProof, AuditProveError> {
    let tx_viewing_pk = ViewingKey::from_bytes(&witness.tx_viewing_sk)?.pubkey();
    let ephemeral = ViewingKey::from_bytes(&witness.eph_sk)?;
    let eph_pk = ephemeral.pubkey();
    let ciphertext = encrypt_tx_viewing_sk(&witness.tx_viewing_sk, ephemeral, auditor_pk)?;
    let public_input_hash = AuditPublicInput {
        private_tx_hash: &witness.private_tx_hash,
        tx_viewing_pk: tx_viewing_pk.as_bytes(),
        auditor_pk: auditor_pk.as_bytes(),
        eph_pk: eph_pk.as_bytes(),
        ciphertext: &ciphertext,
    }
    .hash()
    .map_err(|_| AuditProveError::Hashing)?;
    let point = auditor_pk.to_p256()?.to_encoded_point(false);
    let auditor_pk_uncompressed = <[u8; 65]>::try_from(point.as_bytes())
        .map_err(|_| AuditProveError::UncompressedEncoding)?;
    let proof = AuditorKeyEncryptionProofInputs {
        public_input_hash,
        private_tx_hash: witness.private_tx_hash,
        tx_viewing_sk: *witness.tx_viewing_sk,
        eph_sk: *witness.eph_sk,
        auditor_pk: auditor_pk_uncompressed,
    }
    .prove()?;
    Ok(AuditProof {
        proof_a: proof.proof_a,
        proof_b: proof.proof_b,
        proof_c: proof.proof_c,
        commitment: proof.commitment,
        commitment_pok: proof.commitment_pok,
    })
}
