//! Proof inputs for the custom-ring transact.
//!
//! # The auditor message must be in `messages` before the SPP proof is generated
//!
//! The circuit's public input binds `private_tx_hash`, but the auditor message
//! that this module mints is folded INTO that hash: SPP folds `messages` into
//! `external_data_hash` and that into `private_tx_hash`. So the message has to
//! exist before the SPP proof, and `private_tx_hash` only exists after it.
//!
//! The two steps are therefore separate calls rather than one:
//!
//! 1. [`CustomRingProofParams::encrypt`] -> `(PendingCustomRingProof, AuditorMessage)`,
//! 2. push `message.to_message_data(&auditor_pk)` into `external_data.messages`,
//! 3. prove the SPP transfer to obtain `private_tx_hash`,
//! 4. [`PendingCustomRingProof::finish`] with that hash -> the circuit inputs.
//!
//! This is possible because the ciphertext depends only on `tx_viewing_sk`, the
//! auditor key, and a fresh ephemeral scalar -- never on `private_tx_hash`.
//! `finish` adds no new secret: it only hashes the public input over the
//! ciphertext step 2 published, which is what keeps the custom-ring proof and the
//! published message describing one encryption.
//!
//! Calling `encrypt` twice produces a different ciphertext (see
//! [`CustomRingProofParams`]) and invalidates an SPP proof taken over the first
//! message, so it is called once per transaction.

use custom_ring_interface::{CustomRingProof, CustomRingPublicInput};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_client::{ClientError, Proof, ProofCompressed};
use zolana_keypair::{KeypairError, P256Pubkey, ViewingKey};

use super::request::{CustomRingPrivateTxHash, CustomRingProofRequest, CustomRingPublicInputHash};

use zolana_ring_client::{AuditEncryptionError, AuditorEncryption, AuditorMessage};

#[derive(Debug, Error)]
pub enum CustomRingProofInputError {
    #[error(transparent)]
    Encryption(#[from] AuditEncryptionError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("public input hashing failed")]
    Hashing,
    #[error("hash is not below the BN254 scalar modulus")]
    GreaterThanB254FieldSize,
}

#[derive(Debug, Error)]
pub enum CustomRingProofError {
    #[error(transparent)]
    Compression(#[from] ClientError),
    #[error("the custom-ring proof is missing its BSB22 commitment")]
    MissingCommitment,
}

/// Everything the client knows before the auditor ciphertext exists.
///
/// The ephemeral ECDH scalar is deliberately absent: it is generated inside
/// [`Self::encrypt`]. `(ephemeral, auditor_pk)` fixes the AES-256-CTR keystream,
/// so reusing an ephemeral scalar across two plaintexts would leak their XOR --
/// and the plaintext here is the transaction viewing secret key. Accepting one
/// from the caller would make that reuse expressible.
#[must_use]
pub struct CustomRingProofParams {
    /// The transaction viewing key used as the AES plaintext.
    pub tx_viewing_key: ViewingKey,
    /// The auditor key stored in the ring's config account.
    pub auditor_pk: P256Pubkey,
}

#[must_use]
pub struct EncryptedAudit {
    pub pending: PendingCustomRingProof,
    pub message: AuditorMessage,
}

#[must_use]
pub struct PendingCustomRingProof {
    tx_viewing_key: ViewingKey,
    tx_viewing_pk: P256Pubkey,
    auditor_pk: P256Pubkey,
    ephemeral_sk: Zeroizing<[u8; 32]>,
    message: AuditorMessage,
}

impl CustomRingProofParams {
    /// Encrypts the viewing key to the auditor under a fresh ephemeral scalar.
    ///
    /// # Ordering contract
    ///
    /// The returned [`AuditorMessage`] must be pushed into
    /// `external_data.messages` (as `message.to_message_data(&auditor_pk)`)
    /// **before** the SPP transfer is proved, because SPP folds `messages` into
    /// `external_data_hash` and that into `private_tx_hash`. Feed the
    /// `private_tx_hash` the SPP proof yields to [`PendingCustomRingProof::finish`] to
    /// obtain the circuit inputs. Proving SPP first and appending the message
    /// afterwards produces two irreconcilable `private_tx_hash` values: whichever
    /// one the ring proof commits to, the other is the one SPP checks.
    ///
    /// Consuming, because the message is bound to the one ephemeral scalar this
    /// call generated; re-deriving from the same params would encrypt under a new
    /// one and publish a different ciphertext.
    pub fn encrypt(self) -> Result<EncryptedAudit, CustomRingProofInputError> {
        let Self {
            tx_viewing_key,
            auditor_pk,
        } = self;

        let tx_viewing_pk = tx_viewing_key.pubkey();
        // Chain elements 2/3 are the compressed key the circuit derives from the
        // witnessed scalar, so the host has to derive it the same way rather than
        // trust a caller-supplied public key.

        let AuditorEncryption {
            ephemeral_sk,
            message,
        } = AuditorEncryption::new(&tx_viewing_key, &auditor_pk)?;

        Ok(EncryptedAudit {
            pending: PendingCustomRingProof {
                tx_viewing_key,
                tx_viewing_pk,
                auditor_pk,
                ephemeral_sk,
                message,
            },
            message,
        })
    }
}

/// An encryption waiting for the `private_tx_hash` it will be bound to.
///
/// Holds every value the custom-ring proof is already committed to -- the plaintext,
/// the ephemeral scalar the circuit witnesses, both encodings of the auditor key,
/// and the published ciphertext -- so that [`Self::finish`] adds nothing but the
/// public-input hash.
impl PendingCustomRingProof {
    /// Binds the encryption to the `private_tx_hash` of the SPP proof that
    /// published its message, yielding the circuit inputs.
    ///
    /// `public_input_hash` is produced by the program's own
    /// [`CustomRingPublicInput::hash`], the single canonical implementation of the
    /// pinned eight-element chain: the sdk cannot drift from what the program
    /// recomputes on-chain because it calls the same code.
    ///
    /// Borrowing rather than consuming: unlike [`CustomRingProofParams::encrypt`] this
    /// derives no key material and touches no keystream, so a second call is not a
    /// reuse hazard -- it only rehashes the already published ciphertext under a
    /// different `private_tx_hash`, and only the hash of the SPP proof that
    /// actually carries this message yields a witness the program accepts.
    pub fn finish(
        self,
        private_tx_hash: CustomRingPrivateTxHash,
    ) -> Result<CustomRingProofRequest, CustomRingProofInputError> {
        let Self {
            tx_viewing_key,
            tx_viewing_pk,
            auditor_pk,
            ephemeral_sk,
            message,
        } = self;
        let public_input_hash = CustomRingPublicInput {
            private_tx_hash: private_tx_hash.as_ref(),
            tx_viewing_pk: tx_viewing_pk.as_bytes(),
            auditor_pk: auditor_pk.as_bytes(),
            eph_pk: message.ephemeral_pubkey_bytes(),
            ciphertext: message.ciphertext(),
        }
        .hash()
        .map_err(|_| CustomRingProofInputError::Hashing)?;

        Ok(CustomRingProofRequest {
            public_input_hash: CustomRingPublicInputHash::try_from(public_input_hash)?,
            private_tx_hash,
            tx_viewing_key,
            ephemeral_key: ViewingKey::from_bytes(&ephemeral_sk)?,
            auditor_key: auditor_pk,
        })
    }
}

/// Re-encodes a prover result as the proof the instruction carries.
///
/// The SDK is the only crate that owns both proof representations.
pub fn to_instruction_proof(proof: Proof) -> Result<CustomRingProof, CustomRingProofError> {
    let compressed = ProofCompressed::try_from(proof)?;
    let commitment = compressed
        .commitment
        .ok_or(CustomRingProofError::MissingCommitment)?;
    Ok(CustomRingProof {
        proof_a: compressed.a,
        proof_b: compressed.b,
        proof_c: compressed.c,
        commitment: commitment.commitment,
        commitment_pok: commitment.commitment_pok,
    })
}
