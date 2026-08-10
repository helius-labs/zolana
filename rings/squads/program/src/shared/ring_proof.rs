//! Ring proof public-input composition and verification.
//!
//! The on-chain program recomputes the circuit's `PublicInputHash` from
//! instruction data, then verifies the Groth16 proof against it. The chain order
//! here MUST match `Circuit.Define`
//! (prover/server/circuits/squads/ring/circuit.go:90-112) byte-for-byte, or
//! proofs silently fail to verify.
//!
//! Two shapes:
//! - transfer (2 outputs): private_tx_hash, public_amount, sender_account_hash,
//!   sender_ciphertext_hash, tx_viewing_pk_lo, tx_viewing_pk_hi,
//!   recipient_account_hash, recipient_ciphertext_hash, proposal_hash.
//! - withdrawal (1 output): private_tx_hash, public_amount, sender_account_hash,
//!   sender_ciphertext_hash, proposal_hash (the four recipient/tx_viewing
//!   elements are omitted).

use pinocchio::{error::ProgramError, ProgramResult};
use zolana_squads_interface::{
    error::SquadsRingError, instruction::instruction_data::EncryptedUtxos,
    state::viewing_key_account::ViewingKeyAccount,
};

use super::{
    proof::{
        pack33_to_2fe, pack_bytes_be, poseidon_hash, verify_groth16, Chain, MAX_POSEIDON_INPUTS,
    },
    shapes::{select_ring_fold_vk, select_ring_vk, RING_FOLD_MAX_LEGS},
};

const HASH_ERR: SquadsRingError = SquadsRingError::ProofHashingFailed;

/// The recipient-side inputs present only on the transfer shape.
pub struct RingRecipient<'a> {
    /// `Pack33To2FE` of the compressed tx_viewing_pk: the ephemeral public key
    /// the recipient uses to derive the ECDH shared secret.
    /// `circuit.go:103` (`pkLo, pkHi`).
    pub tx_viewing_pk: &'a [u8; 33],
    /// Recipient public account identity. `recipient.go:32` (`Recipient.Hash`):
    /// `Poseidon(owner, viewing_pk_lo, viewing_pk_hi, nullifier_pubkey)` where
    /// `viewing_pk_{lo,hi} = Pack33To2FE(compressed_viewing_pk)`.
    pub owner: [u8; 32],
    pub viewing_pk: &'a [u8; 33],
    pub nullifier_pubkey: [u8; 32],
    /// Recipient ciphertext (71 bytes: amount 8 || asset 32 || blinding 31).
    /// `recipient.go:66`: `Poseidon(PackBytesBE(ciphertext, 16))`.
    pub ciphertext: &'a [u8],
}

/// A transfer has a recipient account and exactly one recipient ciphertext. A
/// withdrawal has neither.
pub fn ring_recipient<'a>(
    encrypted_utxos: &'a EncryptedUtxos,
    recipient_vka: Option<&'a ViewingKeyAccount>,
) -> Result<Option<RingRecipient<'a>>, ProgramError> {
    match recipient_vka {
        None => {
            if !encrypted_utxos.recipient_ciphertexts.is_empty() {
                return Err(SquadsRingError::InvalidInstructionData.into());
            }
            Ok(None)
        }
        Some(recipient) => {
            let [recipient_ciphertext] = encrypted_utxos.recipient_ciphertexts.as_slice() else {
                return Err(SquadsRingError::InvalidInstructionData.into());
            };
            Ok(Some(RingRecipient {
                tx_viewing_pk: &encrypted_utxos.tx_viewing_pk,
                owner: recipient.owner.to_bytes(),
                viewing_pk: &recipient.shared_viewing_key,
                nullifier_pubkey: recipient.nullifier_pubkey,
                ciphertext: recipient_ciphertext.as_slice(),
            }))
        }
    }
}

/// Inputs required to recompute the ring circuit's public-input hash, plus the
/// proof and shape.
pub struct RingProof<'a> {
    /// `c.Transaction.Hash(api)`. `circuit.go:91`.
    pub private_tx_hash: [u8; 32],
    /// `c.PublicAmount`. `circuit.go:92`.
    pub public_amount: [u8; 32],

    /// Sender public account identity. `view_key.go:22` (`PublicViewingKeyAccount.Hash`):
    /// `Poseidon(owner, shared_viewing_secret_key_commitment, nullifier_pubkey)`.
    pub sender_owner: [u8; 32],
    pub sender_commitment: [u8; 32],
    pub sender_nullifier_pubkey: [u8; 32],
    /// Sender ciphertext (40 bytes: amount 8 || asset 32). `sender.go:103`:
    /// `Poseidon(PackBytesBE(ciphertext, 16))`.
    pub sender_ciphertext: &'a [u8],

    /// Present iff this is a transfer (2 outputs). `None` for a withdrawal.
    pub recipient: Option<RingRecipient<'a>>,

    /// `c.Proposal.Constrain(..)` -- the proposal hash (0 when no proposal).
    /// `circuit.go:109-110`, `proposal.go:17`.
    pub proposal_hash: [u8; 32],

    /// The 192-byte compressed Groth16 proof.
    pub proof: &'a [u8; 192],

    /// Circuit shape `(n_inputs, n_outputs)`. Selects the verifying key.
    pub n_inputs: u8,
    pub n_outputs: u8,
}

/// The circuit reads `public_amount` as a big-endian field element, zero for a
/// transfer. Every caller shares this encoding, or the recomputed chain no
/// longer matches the one the proof bound.
pub fn public_amount_fe(amount: Option<u64>) -> [u8; 32] {
    let mut fe = [0u8; 32];
    if let Some(amount) = amount {
        fe[24..].copy_from_slice(&amount.to_be_bytes());
    }
    fe
}

/// `Poseidon(PackBytesBE(ciphertext, 16))`. This is the ciphertext hash folded
/// into the public input chain (sender.go:103 / recipient.go:66).
fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], ProgramError> {
    let mut fes = [[0u8; 32]; MAX_POSEIDON_INPUTS];
    let n = pack_bytes_be(ciphertext, &mut fes, HASH_ERR)?;
    let used = fes.get(..n).ok_or(HASH_ERR)?;
    poseidon_hash(used, HASH_ERR)
}

impl RingProof<'_> {
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        // view_key.go:22.
        let sender_account_hash = poseidon_hash(
            &[
                self.sender_owner,
                self.sender_commitment,
                self.sender_nullifier_pubkey,
            ],
            HASH_ERR,
        )?;
        let sender_ciphertext_hash = ciphertext_hash(self.sender_ciphertext)?;

        // Chain order: circuit.go:90-95 then (transfer) :106 then :110.
        // Max chain length is the transfer shape: 9 elements.
        let mut chain = Chain::<9>::default();

        chain.push(self.private_tx_hash)?;
        chain.push(self.public_amount)?;
        chain.push(sender_account_hash)?;
        chain.push(sender_ciphertext_hash)?;

        if let Some(recipient) = &self.recipient {
            // tx_viewing_pk_lo, tx_viewing_pk_hi. circuit.go:103,106.
            let (tx_pk_lo, tx_pk_hi) = pack33_to_2fe(recipient.tx_viewing_pk);
            chain.push(tx_pk_lo)?;
            chain.push(tx_pk_hi)?;

            // recipient.go:32.
            let (vpk_lo, vpk_hi) = pack33_to_2fe(recipient.viewing_pk);
            let recipient_account_hash = poseidon_hash(
                &[recipient.owner, vpk_lo, vpk_hi, recipient.nullifier_pubkey],
                HASH_ERR,
            )?;
            chain.push(recipient_account_hash)?;

            chain.push(ciphertext_hash(recipient.ciphertext)?)?;
        }

        // proposal_hash. circuit.go:109-110.
        chain.push(self.proposal_hash)?;

        chain.hash()
    }

    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let vk = select_ring_vk(self.n_inputs, self.n_outputs)?;
        verify_groth16(
            self.proof,
            public_input_hash,
            vk,
            SquadsRingError::InvalidProofEncoding,
            SquadsRingError::RingProofVerificationFailed,
        )
    }
}

/// One leg of a folded spend, as the program reads it back from instruction
/// data. Only the fields the fold chains per leg. The sender and recipient
/// identities are shared and read from the accounts once.
pub struct RingFoldLeg<'a> {
    /// `c.Transaction.Hash(api)` for this leg.
    pub private_tx_hash: [u8; 32],
    /// Sender ciphertext (40 bytes: amount 8 || asset 32).
    pub sender_ciphertext: &'a [u8],
    /// `Pack33To2FE` of this leg's compressed `tx_viewing_pk`.
    pub tx_viewing_pk: &'a [u8; 33],
    /// Recipient ciphertext (71 bytes: amount 8 || asset 32 || blinding 31).
    pub recipient_ciphertext: &'a [u8],
}

/// Inputs to recompute the ring fold circuit's public-input hash, plus the
/// proof and shape.
///
/// The chain carries the sender and recipient identities once and every leg's
/// own fields after them, mirroring `Circuit.Define`
/// (prover/server/circuits/squads/ring_fold/fold.go). Reading the identities
/// once is sound because the circuit asserts every leg agrees on them. Without
/// that a leg could spend another account and this hash would still match.
///
/// A leg carries no proposal and no public amount. The circuit asserts the
/// proposal hash is zero on every leg, and a transfer's public amount is zero.
pub struct RingFoldProof<'a> {
    /// Sender public account identity, as `RingProof` composes it.
    pub sender_owner: [u8; 32],
    pub sender_commitment: [u8; 32],
    pub sender_nullifier_pubkey: [u8; 32],

    /// Recipient public account identity, as `RingRecipient` composes it.
    pub recipient_owner: [u8; 32],
    pub recipient_viewing_pk: &'a [u8; 33],
    pub recipient_nullifier_pubkey: [u8; 32],

    /// Legs in the order the fold chained them.
    pub legs: &'a [RingFoldLeg<'a>],

    /// The 192-byte compressed Groth16 proof of the fold.
    pub proof: &'a [u8; 192],

    /// Leg shape `(n_inputs, n_outputs)`. With the leg count it selects the
    /// verifying key.
    pub n_inputs: u8,
    pub n_outputs: u8,
}

/// Fields per leg in the fold chain: private_tx_hash, public_amount,
/// sender ciphertext hash, tx_viewing_pk low and high, recipient ciphertext
/// hash.
const FOLD_FIELDS_PER_LEG: usize = 6;

/// Largest chain the buffer must hold: the two shared identities plus the
/// widest supported leg count.
const MAX_FOLD_CHAIN: usize = 2 + FOLD_FIELDS_PER_LEG * RING_FOLD_MAX_LEGS as usize;

impl RingFoldProof<'_> {
    /// The leg count the verifying-key selector reads. A run wider than the
    /// chain buffer has no key and no recomputable public input, so it fails
    /// here rather than hashing a truncated chain.
    fn leg_count(&self) -> Result<u8, ProgramError> {
        let legs =
            u8::try_from(self.legs.len()).map_err(|_| SquadsRingError::FoldLegCountOverflow)?;
        if legs == 0 || legs > RING_FOLD_MAX_LEGS {
            return Err(SquadsRingError::FoldLegCountOverflow.into());
        }
        Ok(legs)
    }

    /// Recompute the fold circuit's `FoldInputHash` over the exact ordered
    /// chain.
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        self.leg_count()?;

        let sender_account_hash = poseidon_hash(
            &[
                self.sender_owner,
                self.sender_commitment,
                self.sender_nullifier_pubkey,
            ],
            HASH_ERR,
        )?;
        let (vpk_lo, vpk_hi) = pack33_to_2fe(self.recipient_viewing_pk);
        let recipient_account_hash = poseidon_hash(
            &[
                self.recipient_owner,
                vpk_lo,
                vpk_hi,
                self.recipient_nullifier_pubkey,
            ],
            HASH_ERR,
        )?;

        let mut chain = Chain::<MAX_FOLD_CHAIN>::default();

        chain.push(sender_account_hash)?;
        chain.push(recipient_account_hash)?;

        for leg in self.legs {
            chain.push(leg.private_tx_hash)?;
            chain.push([0u8; 32])?;
            chain.push(ciphertext_hash(leg.sender_ciphertext)?)?;
            let (tx_pk_lo, tx_pk_hi) = pack33_to_2fe(leg.tx_viewing_pk);
            chain.push(tx_pk_lo)?;
            chain.push(tx_pk_hi)?;
            chain.push(ciphertext_hash(leg.recipient_ciphertext)?)?;
        }

        chain.hash()
    }

    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let vk = select_ring_fold_vk(self.n_inputs, self.n_outputs, self.leg_count()?)?;
        verify_groth16(
            self.proof,
            public_input_hash,
            vk,
            SquadsRingError::InvalidProofEncoding,
            SquadsRingError::RingProofVerificationFailed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROOF: [u8; 192] = [0u8; 192];
    const VIEWING_PK: [u8; 33] = [2u8; 33];
    const SENDER_CIPHERTEXT: [u8; 40] = [0u8; 40];
    const RECIPIENT_CIPHERTEXT: [u8; 71] = [0u8; 71];

    fn legs(count: usize) -> Vec<RingFoldLeg<'static>> {
        (0..count)
            .map(|_| RingFoldLeg {
                private_tx_hash: [0u8; 32],
                sender_ciphertext: &SENDER_CIPHERTEXT,
                tx_viewing_pk: &VIEWING_PK,
                recipient_ciphertext: &RECIPIENT_CIPHERTEXT,
            })
            .collect()
    }

    fn fold<'a>(legs: &'a [RingFoldLeg<'a>]) -> RingFoldProof<'a> {
        RingFoldProof {
            sender_owner: [0u8; 32],
            sender_commitment: [0u8; 32],
            sender_nullifier_pubkey: [0u8; 32],
            recipient_owner: [0u8; 32],
            recipient_viewing_pk: &VIEWING_PK,
            recipient_nullifier_pubkey: [0u8; 32],
            legs,
            proof: &PROOF,
            n_inputs: 2,
            n_outputs: 2,
        }
    }

    /// The chain buffer holds the widest supported run. A wider one would hash a
    /// truncated chain, which no verifying key ever constrained.
    #[test]
    fn a_run_wider_than_the_chain_is_rejected() {
        let wide = legs(RING_FOLD_MAX_LEGS as usize + 1);
        assert_eq!(
            fold(&wide).public_input_hash().unwrap_err(),
            ProgramError::Custom(SquadsRingError::FoldLegCountOverflow as u32)
        );
        assert_eq!(
            fold(&[]).public_input_hash().unwrap_err(),
            ProgramError::Custom(SquadsRingError::FoldLegCountOverflow as u32)
        );
    }
}
