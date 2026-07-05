//! `getProposals`: the pending async proposals for a viewing key account,
//! decrypted with the auditor-recovered shared viewing key, plus the shared
//! [`SquadsBackend::reconstruct_zone_proposal`] helper the crank uses to rebuild
//! and verify a proposal from on-chain data alone.
//!
//! A `Proposal` carries no op discriminant. It is classified by the 2-way rule:
//! `recipient == 0` is a withdrawal (the amount leaves the pool, `public_amount ==
//! amount`), otherwise a transfer (`public_amount == 0`, `recipient` holds the
//! recipient's `owner_pk_field`). The transfer ciphertext is encrypted to the
//! recipient's viewing key, the withdrawal ciphertext to the sender's, so the
//! correct viewing key account is resolved before decrypting. The reconstructed
//! `ZoneProposal` is verified by recomputing `proposal_hash` against the on-chain
//! `Proposal.proposal_hash`.

use zolana_client::Rpc;
use zolana_keypair::hash::poseidon;
use zolana_squads_interface::{state::Proposal, SQUADS_ZONE_PROGRAM_ID};
use zolana_squads_sdk::{
    proposal::{decrypt_proposal_ciphertext, proposal_hash},
    prover::ZoneProposal,
};
use zolana_transaction::Address;

use crate::{
    backend::{right_align_31, SquadsBackend},
    error::{Result, SquadsBackendError},
    types::{DecryptedProposal, GetProposalsRequest, GetProposalsResponse, ReconstructedProposal},
};

/// `DecryptedProposal.op`: a withdrawal (public exit) proposal (spec sync table).
pub const OP_WITHDRAW: u8 = 2;
/// `DecryptedProposal.op`: an in-pool transfer proposal (spec sync table).
pub const OP_TRANSFER: u8 = 3;

/// A `u64` right-aligned big-endian into a 32-byte field element.
fn fe_u64(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&x.to_be_bytes());
    out
}

impl<I: Rpc, R: Rpc> SquadsBackend<I, R> {
    /// Reconstruct and verify a pending proposal from on-chain data plus the
    /// auditor key: classify it, resolve the viewing key account it is encrypted
    /// to, decrypt `(amount, blinding)`, rebuild the [`ZoneProposal`], and confirm
    /// the recomputed `proposal_hash` matches the stored one.
    pub fn reconstruct_zone_proposal(
        &self,
        pda: Address,
        proposal: &Proposal,
    ) -> Result<ReconstructedProposal> {
        let is_withdrawal = proposal.recipient == Address::default();
        let asset_id = self.asset_id_for_mint(&proposal.asset).unwrap_or_default();

        if is_withdrawal {
            // Encrypted to the sender (Proposal.owner's viewing key account).
            let (_, sender_vka) = self
                .find_viewing_key_account_by_owner(proposal.owner)?
                .ok_or_else(|| {
                    SquadsBackendError::AccountNotFound(format!(
                        "sender viewing key account for owner {}",
                        proposal.owner
                    ))
                })?;
            let resolved = self.resolve_shared_key_from_vka(sender_vka)?;
            let (amount, blinding) =
                decrypt_proposal_ciphertext(&proposal.cipher_text, &resolved.shared_viewing_sk)
                    .map_err(|e| SquadsBackendError::Crypto(format!("proposal decrypt: {e}")))?;

            let zone_proposal = ZoneProposal {
                amount: [0u8; 32],
                recipient: [0u8; 32],
                blinding: right_align_31(&blinding),
                public_amount: fe_u64(amount),
            };
            let expected = proposal_hash(0, &[0u8; 32], &blinding, amount)
                .map_err(|e| SquadsBackendError::Crypto(format!("proposal hash: {e}")))?;
            if expected != proposal.proposal_hash {
                return Err(SquadsBackendError::Unsupported(format!(
                    "withdrawal proposal {pda} hash mismatch"
                )));
            }

            Ok(ReconstructedProposal {
                pda,
                op: OP_WITHDRAW,
                owner: proposal.owner,
                sender_vault: proposal.rent_payer,
                recipient: Address::default(),
                asset: proposal.asset,
                asset_id,
                amount,
                public_amount: amount,
                blinding,
                expiry: proposal.expiry,
                proposal_hash: proposal.proposal_hash,
                zone_proposal,
            })
        } else {
            // Encrypted to the recipient (Proposal.recipient's viewing key account).
            let (_, recipient_vka) = self
                .find_viewing_key_account_by_owner(proposal.recipient)?
                .ok_or_else(|| {
                    SquadsBackendError::AccountNotFound(format!(
                        "recipient viewing key account for owner {}",
                        proposal.recipient
                    ))
                })?;
            let recipient_nullifier_pubkey = recipient_vka.nullifier_pubkey;
            let resolved = self.resolve_shared_key_from_vka(recipient_vka)?;
            let (amount, blinding) =
                decrypt_proposal_ciphertext(&proposal.cipher_text, &resolved.shared_viewing_sk)
                    .map_err(|e| SquadsBackendError::Crypto(format!("proposal decrypt: {e}")))?;

            // The zone proposal binds the recipient by owner_hash =
            // Poseidon(owner_pk_field, nullifier_pubkey), not the raw owner_pk_field.
            let owner_hash = poseidon(&[
                proposal.recipient.to_bytes().as_ref(),
                recipient_nullifier_pubkey.as_ref(),
            ])
            .map_err(|e| SquadsBackendError::Crypto(format!("recipient owner hash: {e:?}")))?;

            let zone_proposal = ZoneProposal {
                amount: fe_u64(amount),
                recipient: owner_hash,
                blinding: right_align_31(&blinding),
                public_amount: [0u8; 32],
            };
            let expected = proposal_hash(amount, &owner_hash, &blinding, 0)
                .map_err(|e| SquadsBackendError::Crypto(format!("proposal hash: {e}")))?;
            if expected != proposal.proposal_hash {
                return Err(SquadsBackendError::Unsupported(format!(
                    "transfer proposal {pda} hash mismatch"
                )));
            }

            Ok(ReconstructedProposal {
                pda,
                op: OP_TRANSFER,
                owner: proposal.owner,
                sender_vault: proposal.rent_payer,
                recipient: proposal.recipient,
                asset: proposal.asset,
                asset_id,
                amount,
                public_amount: 0,
                blinding,
                expiry: proposal.expiry,
                proposal_hash: proposal.proposal_hash,
                zone_proposal,
            })
        }
    }

    /// The pending proposals a viewing key account participates in (as sender or
    /// recipient), each decrypted with the correct viewing key and verified.
    pub fn get_proposals(&self, request: GetProposalsRequest) -> Result<GetProposalsResponse> {
        let queried = self.resolve_shared_key(request.viewing_key_account)?;
        let owner = queried.account.owner;

        let program_id = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);
        let accounts = self.rpc().get_program_accounts(program_id)?;

        let mut proposals = Vec::new();
        for (pda, account) in accounts {
            let Ok(proposal) = Proposal::deserialize(&account.data) else {
                continue;
            };
            if proposal.discriminator != Proposal::DISCRIMINATOR {
                continue;
            }
            // Only proposals the queried account is a party to.
            if proposal.owner != owner && proposal.recipient != owner {
                continue;
            }
            let Ok(reconstructed) = self.reconstruct_zone_proposal(pda, &proposal) else {
                continue;
            };
            proposals.push(DecryptedProposal {
                pda: reconstructed.pda,
                op: reconstructed.op,
                asset_id: reconstructed.asset_id,
                amount: reconstructed.amount,
                recipient: reconstructed.recipient,
                expiry: reconstructed.expiry,
                proposal_hash: reconstructed.proposal_hash,
            });
        }

        Ok(GetProposalsResponse { proposals })
    }
}
