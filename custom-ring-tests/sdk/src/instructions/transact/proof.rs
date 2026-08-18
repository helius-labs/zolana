//! Proof inputs for the audited ring transact.
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
//! 1. [`AuditProofParams::encrypt`] -> `(PendingAuditProof, AuditorMessage)`,
//! 2. push `message.to_message_data(&auditor_pk)` into `external_data.messages`,
//! 3. prove the SPP transfer to obtain `private_tx_hash`,
//! 4. [`PendingAuditProof::finish`] with that hash -> the circuit inputs.
//!
//! This is possible because the ciphertext depends only on `tx_viewing_sk`, the
//! auditor key, and a fresh ephemeral scalar -- never on `private_tx_hash`.
//! `finish` adds no new secret: it only hashes the public input over the
//! ciphertext step 2 published, which is what keeps the audit proof and the
//! published message describing one encryption.
//!
//! Calling `encrypt` twice produces a different ciphertext (see
//! [`AuditProofParams`]) and invalidates an SPP proof taken over the first
//! message, so it is called once per transaction.

use custom_ring_program::instructions::transact::{AuditProof, AuditPublicInput};
use custom_ring_prover::AuditorKeyEncryptionProofInputs;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use solana_program_error::ProgramError;
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_keypair::{KeypairError, P256Pubkey, ViewingKey};

use zolana_ring_client::{AuditEncryptionError, AuditorEncryption, AuditorMessage};

/// SEC1 uncompressed public key: `0x04 || x || y`. The circuit witnesses the
/// auditor key in this form because its emulated-P256 gadgets need both
/// coordinates; the compressed form only appears in the public-input chain.
const UNCOMPRESSED_PUBKEY_LEN: usize = 65;

#[derive(Debug, Error)]
pub enum AuditProofInputError {
    #[error(transparent)]
    Encryption(#[from] AuditEncryptionError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error("the auditor key does not encode as {UNCOMPRESSED_PUBKEY_LEN}-byte uncompressed SEC1")]
    UncompressedEncoding,
    #[error("public-input hashing failed: {0:?}")]
    Hashing(ProgramError),
}

/// Everything the client knows before the auditor ciphertext exists.
///
/// The ephemeral ECDH scalar is deliberately absent: it is generated inside
/// [`Self::encrypt`]. `(ephemeral, auditor_pk)` fixes the AES-256-CTR keystream,
/// so reusing an ephemeral scalar across two plaintexts would leak their XOR --
/// and the plaintext here is the transaction viewing secret key. Accepting one
/// from the caller would make that reuse expressible.
pub struct AuditProofParams {
    /// The transaction viewing secret key, i.e. the AES plaintext. Its public key
    /// must be the `tx_viewing_pk` of the SPP payload, which is what chain
    /// elements 2/3 bind.
    pub tx_viewing_sk: Zeroizing<[u8; 32]>,
    /// The auditor key stored in the ring's config account.
    pub auditor_pk: P256Pubkey,
}

impl AuditProofParams {
    /// Encrypts the viewing key to the auditor under a fresh ephemeral scalar.
    ///
    /// # Ordering contract
    ///
    /// The returned [`AuditorMessage`] must be pushed into
    /// `external_data.messages` (as `message.to_message_data(&auditor_pk)`)
    /// **before** the SPP transfer is proved, because SPP folds `messages` into
    /// `external_data_hash` and that into `private_tx_hash`. Feed the
    /// `private_tx_hash` the SPP proof yields to [`PendingAuditProof::finish`] to
    /// obtain the circuit inputs. Proving SPP first and appending the message
    /// afterwards produces two irreconcilable `private_tx_hash` values: whichever
    /// one the ring proof commits to, the other is the one SPP checks.
    ///
    /// Consuming, because the message is bound to the one ephemeral scalar this
    /// call generated; re-deriving from the same params would encrypt under a new
    /// one and publish a different ciphertext.
    pub fn encrypt(self) -> Result<(PendingAuditProof, AuditorMessage), AuditProofInputError> {
        let Self {
            tx_viewing_sk,
            auditor_pk,
        } = self;

        // Chain elements 2/3 are the compressed key the circuit derives from the
        // witnessed scalar, so the host has to derive it the same way rather than
        // trust a caller-supplied public key.
        let tx_viewing_pk = ViewingKey::from_bytes(&tx_viewing_sk)?.pubkey();

        let AuditorEncryption {
            ephemeral_sk,
            message,
        } = AuditorEncryption::new(&tx_viewing_sk, &auditor_pk)?;

        Ok((
            PendingAuditProof {
                tx_viewing_sk,
                tx_viewing_pk,
                auditor_pk,
                auditor_pk_uncompressed: uncompressed_sec1(&auditor_pk)?,
                ephemeral_sk,
                message,
            },
            message,
        ))
    }
}

/// An encryption waiting for the `private_tx_hash` it will be bound to.
///
/// Holds every value the audit proof is already committed to -- the plaintext,
/// the ephemeral scalar the circuit witnesses, both encodings of the auditor key,
/// and the published ciphertext -- so that [`Self::finish`] adds nothing but the
/// public-input hash.
pub struct PendingAuditProof {
    tx_viewing_sk: Zeroizing<[u8; 32]>,
    tx_viewing_pk: P256Pubkey,
    auditor_pk: P256Pubkey,
    auditor_pk_uncompressed: [u8; UNCOMPRESSED_PUBKEY_LEN],
    ephemeral_sk: Zeroizing<[u8; 32]>,
    message: AuditorMessage,
}

impl PendingAuditProof {
    /// Binds the encryption to the `private_tx_hash` of the SPP proof that
    /// published its message, yielding the circuit inputs.
    ///
    /// `public_input_hash` is produced by the program's own
    /// [`AuditPublicInput::hash`], the single canonical implementation of the
    /// pinned eight-element chain: the sdk cannot drift from what the program
    /// recomputes on-chain because it calls the same code.
    ///
    /// Borrowing rather than consuming: unlike [`AuditProofParams::encrypt`] this
    /// derives no key material and touches no keystream, so a second call is not a
    /// reuse hazard -- it only rehashes the already published ciphertext under a
    /// different `private_tx_hash`, and only the hash of the SPP proof that
    /// actually carries this message yields a witness the program accepts.
    pub fn finish(
        &self,
        private_tx_hash: &[u8; 32],
    ) -> Result<AuditorKeyEncryptionProofInputs, AuditProofInputError> {
        let public_input_hash = AuditPublicInput {
            private_tx_hash,
            tx_viewing_pk: self.tx_viewing_pk.as_bytes(),
            auditor_pk: self.auditor_pk.as_bytes(),
            eph_pk: &self.message.eph_pk,
            ciphertext: &self.message.ciphertext,
        }
        .hash()
        .map_err(AuditProofInputError::Hashing)?;

        Ok(AuditorKeyEncryptionProofInputs {
            public_input_hash,
            private_tx_hash: *private_tx_hash,
            tx_viewing_sk: *self.tx_viewing_sk,
            eph_sk: *self.ephemeral_sk,
            auditor_pk: self.auditor_pk_uncompressed,
        })
    }
}

/// Re-encodes a prover result as the proof the instruction carries.
///
/// The two structs hold the same five compressed points in the same order but are
/// distinct types on purpose: the prover crate does not depend on the program
/// crate, so neither side can name the other and neither can host a `From` impl
/// (the orphan rule rules out one in this crate too, since both types are
/// foreign). The sdk is the only crate that sees both, so the conversion lives
/// here as a plain function.
pub fn to_instruction_proof(proof: &custom_ring_prover::AuditProof) -> AuditProof {
    let custom_ring_prover::AuditProof {
        proof_a,
        proof_b,
        proof_c,
        commitment,
        commitment_pok,
    } = *proof;
    AuditProof {
        proof_a,
        proof_b,
        proof_c,
        commitment,
        commitment_pok,
    }
}

/// Decompresses a compressed key into the `0x04 || x || y` form the circuit
/// witnesses. `P256Pubkey` only ever holds the compressed encoding, and
/// [`P256Pubkey::to_p256`] is what validates that the point is on the curve.
fn uncompressed_sec1(
    pubkey: &P256Pubkey,
) -> Result<[u8; UNCOMPRESSED_PUBKEY_LEN], AuditProofInputError> {
    let point = pubkey.to_p256()?.to_encoded_point(false);
    <[u8; UNCOMPRESSED_PUBKEY_LEN]>::try_from(point.as_bytes())
        .map_err(|_| AuditProofInputError::UncompressedEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The uncompressed encoding must keep the SEC1 prefix the circuit asserts
    /// (`AuditorPk[0] == 4`) and reproduce the x-coordinate of the compressed key
    /// it came from, so the two chain representations describe one point.
    #[test]
    fn uncompressed_sec1_keeps_the_prefix_and_x_coordinate() {
        let pubkey = ViewingKey::new().pubkey();
        let uncompressed = uncompressed_sec1(&pubkey).expect("valid curve point");

        assert_eq!(uncompressed.first(), Some(&4u8));
        assert_eq!(
            uncompressed.get(1..33).expect("x coordinate"),
            pubkey.x().as_slice()
        );
    }
}
