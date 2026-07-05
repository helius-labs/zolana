//! Zone proof public-input composition and verification.
//!
//! The on-chain program recomputes the circuit's `PublicInputHash` from
//! instruction data, then verifies the Groth16 proof against it. The chain order
//! here MUST match `Circuit.Define`
//! (prover/server/circuits/squads/zone/circuit.go:90-112) byte-for-byte, or
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
    error::SquadsZoneError, instruction::instruction_data::EncryptedUtxos,
    state::viewing_key_account::ViewingKeyAccount,
};

use super::{
    proof::{
        hash_chain, pack33_to_2fe, pack_bytes_be, poseidon_hash, verify_groth16,
        MAX_POSEIDON_INPUTS,
    },
    shapes::select_zone_vk,
};

/// Hashing failures during public-input composition map to this error.
const HASH_ERR: SquadsZoneError = SquadsZoneError::ProofHashingFailed;

/// The recipient-side inputs present only on the transfer shape.
pub struct ZoneRecipient<'a> {
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

/// Build the recipient half of the zone proof from the typed `EncryptedUtxos`
/// and the recipient viewing key account. A transfer has a recipient account and
/// exactly one recipient ciphertext; a withdrawal has neither. Any mismatch
/// between the account's presence and the ciphertext count is rejected. The
/// recipient's `tx_viewing_pk` and ciphertext come from `encrypted_utxos`; its
/// public identity comes from the account. Shared by `transact` and
/// `execute_proposal`.
pub fn zone_recipient<'a>(
    encrypted_utxos: &'a EncryptedUtxos,
    recipient_vka: Option<&'a ViewingKeyAccount>,
) -> Result<Option<ZoneRecipient<'a>>, ProgramError> {
    match recipient_vka {
        None => {
            if !encrypted_utxos.recipient_ciphertexts.is_empty() {
                return Err(SquadsZoneError::InvalidInstructionData.into());
            }
            Ok(None)
        }
        Some(recipient) => {
            let [recipient_ciphertext] = encrypted_utxos.recipient_ciphertexts.as_slice() else {
                return Err(SquadsZoneError::InvalidInstructionData.into());
            };
            Ok(Some(ZoneRecipient {
                tx_viewing_pk: &encrypted_utxos.tx_viewing_pk,
                owner: recipient.owner.to_bytes(),
                viewing_pk: &recipient.shared_viewing_key,
                nullifier_pubkey: recipient.nullifier_pubkey,
                ciphertext: recipient_ciphertext.as_slice(),
            }))
        }
    }
}

/// Inputs required to recompute the zone circuit's public-input hash, plus the
/// proof and shape.
pub struct ZoneProof<'a> {
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

    /// Present iff this is a transfer (2 outputs); `None` for a withdrawal.
    pub recipient: Option<ZoneRecipient<'a>>,

    /// `c.Proposal.Constrain(..)` -- the proposal hash (0 when no proposal).
    /// `circuit.go:109-110`, `proposal.go:17`.
    pub proposal_hash: [u8; 32],

    /// The 192-byte compressed Groth16 proof.
    pub proof: &'a [u8; 192],

    /// Circuit shape `(n_inputs, n_outputs)`; selects the verifying key.
    pub n_inputs: u8,
    pub n_outputs: u8,
}

/// `Poseidon(PackBytesBE(ciphertext, 16))`; the ciphertext hash folded into the
/// public input chain (sender.go:103 / recipient.go:66).
fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], ProgramError> {
    let mut fes = [[0u8; 32]; MAX_POSEIDON_INPUTS];
    let n = pack_bytes_be(ciphertext, &mut fes, HASH_ERR)?;
    let used = fes.get(..n).ok_or(HASH_ERR)?;
    poseidon_hash(used, HASH_ERR)
}

impl ZoneProof<'_> {
    /// Recompute the circuit's `PublicInputHash` over the exact ordered chain.
    /// Mirrors `Circuit.Define` (circuit.go:90-112).
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        // sender_account_hash = Poseidon(owner, commitment, nullifier_pubkey).
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
        let mut chain = [[0u8; 32]; 9];
        let mut len = 0usize;
        let push = |v: [u8; 32], chain: &mut [[u8; 32]; 9], len: &mut usize| {
            if let Some(slot) = chain.get_mut(*len) {
                *slot = v;
                *len += 1;
            }
        };

        push(self.private_tx_hash, &mut chain, &mut len);
        push(self.public_amount, &mut chain, &mut len);
        push(sender_account_hash, &mut chain, &mut len);
        push(sender_ciphertext_hash, &mut chain, &mut len);

        if let Some(recipient) = &self.recipient {
            // tx_viewing_pk_lo, tx_viewing_pk_hi. circuit.go:103,106.
            let (tx_pk_lo, tx_pk_hi) = pack33_to_2fe(recipient.tx_viewing_pk);
            push(tx_pk_lo, &mut chain, &mut len);
            push(tx_pk_hi, &mut chain, &mut len);

            // recipient_account_hash = Poseidon(owner, vpk_lo, vpk_hi, nullifier_pubkey).
            // recipient.go:32.
            let (vpk_lo, vpk_hi) = pack33_to_2fe(recipient.viewing_pk);
            let recipient_account_hash = poseidon_hash(
                &[recipient.owner, vpk_lo, vpk_hi, recipient.nullifier_pubkey],
                HASH_ERR,
            )?;
            push(recipient_account_hash, &mut chain, &mut len);

            let recipient_ciphertext_hash = ciphertext_hash(recipient.ciphertext)?;
            push(recipient_ciphertext_hash, &mut chain, &mut len);
        }

        // proposal_hash. circuit.go:109-110.
        push(self.proposal_hash, &mut chain, &mut len);

        let used = chain.get(..len).ok_or(HASH_ERR)?;
        hash_chain(used, HASH_ERR)
    }

    /// Select the verifying key for the shape and verify the proof against the
    /// recomputed public-input hash.
    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let vk = select_zone_vk(self.n_inputs, self.n_outputs)?;
        verify_groth16(
            self.proof,
            public_input_hash,
            vk,
            SquadsZoneError::InvalidProofEncoding,
            SquadsZoneError::ZoneProofVerificationFailed,
        )
    }
}
