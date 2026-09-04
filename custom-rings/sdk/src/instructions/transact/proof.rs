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
//! 1. [`CustomRingProofParams::encrypt`] -> `(PendingCustomRingProof, AuditorMessage)`,
//! 2. push `message.to_message_data(&auditor_pk)` into `external_data.messages`,
//! 3. prove the SPP transfer to obtain `private_tx_hash`,
//! 4. [`PendingCustomRingProof::finish`] with that hash -> the circuit inputs.
//!
//! This is possible because the ciphertext depends only on `tx_viewing_sk`, the
//! auditor key, and a fresh ephemeral scalar -- never on `private_tx_hash`.
//! `finish` adds no new secret: it only hashes the public input over the
//! ciphertext step 2 published, which is what keeps the audit proof and the
//! published message describing one encryption.
//!
//! Calling `encrypt` twice produces a different ciphertext (see
//! [`CustomRingProofParams`]) and invalidates an SPP proof taken over the first
//! message, so it is called once per transaction.

use custom_ring_interface::{CustomRingBasePublicInput, CustomRingProof};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_client::{ClientError, Proof, ProofCompressed};
use zolana_keypair::{KeypairError, P256Pubkey, ViewingKey};

use super::request::CustomRingPrivateTxHash;

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
    #[error("the auditor key encryption proof is missing its BSB22 commitment")]
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
impl PendingCustomRingProof {
    /// The public input recomputed from `CustomRingPolicyPublicInput`, the one
    /// implementation the program calls on-chain, so a folded request cannot
    /// drift from what verification recomputes.
    /// The circuit recomputes `private_tx_hash` over the chains and the
    /// external data hash, a value the SPP proof did not fold cannot prove.
    pub fn finish(
        self,
        private_tx_hash: CustomRingPrivateTxHash,
        external_data_hash: &[u8; 32],
        witness: crate::witness::CustomRingWitness,
        policy_hash: &[u8; 32],
    ) -> Result<
        crate::instructions::transact::CustomRingPolicyProofRequest,
        CustomRingProofInputError,
    > {
        let Self {
            tx_viewing_key,
            tx_viewing_pk,
            auditor_pk,
            ephemeral_sk,
            message,
        } = self;
        let public_input_hash = custom_ring_interface::CustomRingPolicyPublicInput {
            audit: CustomRingBasePublicInput {
                private_tx_hash: private_tx_hash.as_ref(),
                tx_viewing_pk: tx_viewing_pk.as_bytes(),
                auditor_pk: auditor_pk.as_bytes(),
                eph_pk: message.ephemeral_pubkey_bytes(),
                ciphertext: message.ciphertext(),
            },
            policy_hash,
            state_root: &witness.roots.state,
            nullifier_root: &witness.roots.nullifier,
        }
        .hash()
        .map_err(|_| CustomRingProofInputError::Hashing)?;

        Ok(
            crate::instructions::transact::CustomRingPolicyProofRequest {
                public_input_hash,
                private_tx_hash: *private_tx_hash.as_ref(),
                tx_viewing_key,
                ephemeral_key: ViewingKey::from_bytes(&ephemeral_sk)?,
                auditor_key: auditor_pk,
                n_in: witness.n_in,
                n_out: witness.n_out,
                inputs: witness.inputs,
                outputs: witness.outputs,
                // SPP folds a zero address slot per input into `private_tx_hash`.
                address_chain: zolana_hasher::hash_chain::create_hash_chain_from_slice(&vec![
                [0u8; 32];
                witness.n_in
                    as usize
            ])
                .map_err(|_| CustomRingProofInputError::Hashing)?,
                external_data_hash: *external_data_hash,
                sources: witness.sources,
                policy_len: witness.policy_len,
                rules: witness.rules,
                inline_assets: witness.inline_assets,
                inline_count: witness.inline_count,
                state_root: witness.roots.state,
                nullifier_root: witness.roots.nullifier,
                answers: witness.answers,
            },
        )
    }

    /// Proves the audit statement alone over the unchanged ciphertext.
    pub fn finish_base(
        self,
        private_tx_hash: CustomRingPrivateTxHash,
    ) -> Result<crate::instructions::transact::CustomRingBaseProofRequest, CustomRingProofInputError>
    {
        let Self {
            tx_viewing_key,
            tx_viewing_pk,
            auditor_pk,
            ephemeral_sk,
            message,
        } = self;
        let public_input_hash = CustomRingBasePublicInput {
            private_tx_hash: private_tx_hash.as_ref(),
            tx_viewing_pk: tx_viewing_pk.as_bytes(),
            auditor_pk: auditor_pk.as_bytes(),
            eph_pk: message.ephemeral_pubkey_bytes(),
            ciphertext: message.ciphertext(),
        }
        .hash()
        .map_err(|_| CustomRingProofInputError::Hashing)?;

        Ok(crate::instructions::transact::CustomRingBaseProofRequest {
            public_input_hash,
            private_tx_hash: *private_tx_hash.as_ref(),
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

#[cfg(test)]
mod tests {
    use super::super::{CustomRingOpening, SourceOwnerEntry};
    use super::*;
    use crate::witness::{CustomRingWitness, TransactRoots};
    use custom_ring_interface::CustomRingPolicyPublicInput;
    use zolana_ring_policy::{
        MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES, POLICY_INPUT_SLOTS, POLICY_OUTPUT_SLOTS,
    };

    /// The `go_vectors.rs` fixture scalars, valid P-256 keys below the group order.
    const TX_SK: &str = "011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e";
    const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";

    fn key(hex_str: &str) -> ViewingKey {
        let bytes: [u8; 32] = hex::decode(hex_str)
            .expect("hex")
            .try_into()
            .expect("scalar length");
        ViewingKey::from_bytes(&bytes).expect("valid P-256 scalar")
    }

    fn witness(state: [u8; 32], nullifier: [u8; 32]) -> CustomRingWitness {
        CustomRingWitness {
            roots: TransactRoots {
                state,
                state_index: 0,
                nullifier,
                nullifier_index: 0,
            },
            sources: [SourceOwnerEntry::default(); MAX_SOURCES],
            inputs: [CustomRingOpening::default(); POLICY_INPUT_SLOTS],
            outputs: [CustomRingOpening::default(); POLICY_OUTPUT_SLOTS],
            n_in: 1,
            n_out: 1,
            rules: [[0u8; 32]; MAX_RULES],
            policy_len: 0,
            inline_assets: [[0u8; 32]; MAX_INLINE_ASSETS],
            inline_count: 0,
            answers: Vec::new(),
        }
    }

    /// finish must fold the finish-side private_tx_hash, the witness roots, the
    /// policy hash, and the published ciphertext into the one public input the
    /// program recomputes on chain.
    #[test]
    fn finish_binds_the_public_input_the_program_recomputes() {
        let tx_key = key(TX_SK);
        let tx_pk = tx_key.pubkey();
        let auditor_pk = key(AUDITOR_SK).pubkey();
        let EncryptedAudit { pending, message } = CustomRingProofParams {
            tx_viewing_key: tx_key,
            auditor_pk,
        }
        .encrypt()
        .expect("encrypt");

        let mut private_tx_hash = [0u8; 32];
        private_tx_hash[29..].copy_from_slice(&[0xab, 0xcd, 0xef]);
        let state = [7u8; 32];
        let nullifier = [9u8; 32];
        let policy_hash = [4u8; 32];
        let external_data_hash = [5u8; 32];

        let request = pending
            .finish(
                CustomRingPrivateTxHash::try_from(private_tx_hash).expect("below the modulus"),
                &external_data_hash,
                witness(state, nullifier),
                &policy_hash,
            )
            .expect("finish");

        let expected = CustomRingPolicyPublicInput {
            audit: CustomRingBasePublicInput {
                private_tx_hash: &private_tx_hash,
                tx_viewing_pk: tx_pk.as_bytes(),
                auditor_pk: auditor_pk.as_bytes(),
                eph_pk: message.ephemeral_pubkey_bytes(),
                ciphertext: message.ciphertext(),
            },
            policy_hash: &policy_hash,
            state_root: &state,
            nullifier_root: &nullifier,
        }
        .hash()
        .expect("public input hash");

        assert_eq!(request.public_input_hash, expected);
        assert_eq!(request.private_tx_hash, private_tx_hash);
        assert_eq!(request.state_root, state);
        assert_eq!(request.nullifier_root, nullifier);
    }
}
