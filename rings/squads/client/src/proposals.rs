//! `getProposals` lists the pending proposals a viewing key account is a party
//! to, decrypted with the auditor-recovered shared viewing key. The crank uses
//! the shared [`SquadsBackend::reconstruct_ring_proposal`] helper to rebuild and
//! verify a proposal from on-chain data alone.
//!
//! A `Proposal` carries no op discriminant. Classification is authenticated.
//! Try the sender key with the withdrawal core, then the recipient key with the
//! transfer core. AES-GCM and the operation-bound private core make exactly the
//! approved form match. `Proposal.recipient` therefore stores the actual public
//! withdrawal destination.

use zolana_client::Rpc;
use zolana_keypair::hash::poseidon;
use zolana_squads_interface::{state::Proposal, SQUADS_RING_PROGRAM_ID};
use zolana_squads_sdk::{
    crypto::{fe_from_u64, right_align_31},
    proposal::{
        decrypt_proposal_ciphertext, proposal_asset_commitment, proposal_destination_commitment,
        proposal_hash, ProposalOperation,
    },
    prover::RingProposal,
};
use zolana_transaction::Address;

use crate::{
    authorization::ReadAuthorization,
    backend::SquadsBackend,
    error::{Result, SquadsBackendError},
    types::{DecryptedProposal, GetProposalsRequest, GetProposalsResponse, ReconstructedProposal},
};

/// The withdrawal (public exit) `DecryptedProposal.op` value (spec sync table).
pub const OP_WITHDRAW: u8 = 2;
/// The in-pool transfer `DecryptedProposal.op` value (spec sync table).
pub const OP_TRANSFER: u8 = 3;

impl<I: Rpc, R: Rpc, A: ReadAuthorization> SquadsBackend<I, R, A> {
    /// Reconstruct and verify a pending proposal from on-chain data plus the
    /// auditor key. Classify it, resolve the viewing key account it is encrypted
    /// to, decrypt `(amount, blinding)`, rebuild the [`RingProposal`], and
    /// confirm the recomputed `proposal_hash` matches the stored one.
    pub fn reconstruct_ring_proposal(
        &self,
        pda: Address,
        proposal: &Proposal,
    ) -> Result<ReconstructedProposal> {
        let asset_id = self.asset_id_for_mint(&proposal.asset).ok_or_else(|| {
            SquadsBackendError::Unsupported(format!(
                "proposal {pda} spends unregistered mint {}",
                proposal.asset
            ))
        })?;

        // Withdrawal ciphertexts are encrypted to the sender. Treat this as a
        // withdrawal only when both GCM authentication and the operation-bound
        // private core match.
        if let Some((_, sender_vka)) = self.find_viewing_key_account_by_owner(proposal.owner)? {
            let resolved = self.resolve_shared_key_from_vka(sender_vka)?;
            if let Ok((amount, blinding)) =
                decrypt_proposal_ciphertext(&proposal.cipher_text, &resolved.shared_viewing_sk)
            {
                let expected = proposal_hash(
                    ProposalOperation::Withdrawal,
                    0,
                    &[0u8; 32],
                    &blinding,
                    amount,
                )?;
                if expected == proposal.proposal_hash {
                    let asset = proposal_asset_commitment(&proposal.asset)?;
                    let destination = proposal_destination_commitment(
                        ProposalOperation::Withdrawal,
                        &proposal.recipient,
                    )?;
                    return Ok(ReconstructedProposal {
                        pda,
                        op: OP_WITHDRAW,
                        owner: proposal.owner,
                        sender_vault: proposal.rent_payer,
                        recipient: proposal.recipient,
                        asset: proposal.asset,
                        asset_id,
                        amount,
                        public_amount: amount,
                        blinding,
                        expiry: proposal.expiry,
                        proposal_hash: proposal.proposal_hash,
                        ring_proposal: RingProposal {
                            amount: [0u8; 32],
                            recipient: [0u8; 32],
                            asset,
                            destination,
                            blinding: right_align_31(&blinding),
                            public_amount: fe_from_u64(amount),
                        },
                    });
                }
            }
        }

        let unclassified = || {
            SquadsBackendError::Unsupported(format!(
                "proposal {pda} matches neither an authenticated withdrawal nor a transfer"
            ))
        };

        // Transfer ciphertexts are encrypted to the recipient VKA recorded by
        // owner field. A public withdrawal destination need not resolve to a VKA.
        let (_, recipient_vka) = self
            .find_viewing_key_account_by_owner(proposal.recipient)?
            .ok_or_else(unclassified)?;
        let recipient_nullifier_pubkey = recipient_vka.nullifier_pubkey;
        let resolved = self.resolve_shared_key_from_vka(recipient_vka)?;
        let (amount, blinding) =
            decrypt_proposal_ciphertext(&proposal.cipher_text, &resolved.shared_viewing_sk)
                .map_err(|_| unclassified())?;
        let owner_hash = poseidon(&[
            proposal.recipient.to_bytes().as_ref(),
            recipient_nullifier_pubkey.as_ref(),
        ])?;
        let expected = proposal_hash(
            ProposalOperation::Transfer,
            amount,
            &owner_hash,
            &blinding,
            0,
        )?;
        if expected != proposal.proposal_hash {
            return Err(unclassified());
        }
        let asset = proposal_asset_commitment(&proposal.asset)?;
        let destination =
            proposal_destination_commitment(ProposalOperation::Transfer, &proposal.recipient)?;

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
            ring_proposal: RingProposal {
                amount: fe_from_u64(amount),
                recipient: owner_hash,
                asset,
                destination,
                blinding: right_align_31(&blinding),
                public_amount: [0u8; 32],
            },
        })
    }

    /// The pending proposals a viewing key account participates in (as sender or
    /// recipient), each decrypted with the correct viewing key and verified.
    pub fn get_proposals(&self, request: GetProposalsRequest) -> Result<GetProposalsResponse> {
        self.authorize_read(request.viewing_key_account, &request.signature)?;

        let queried = self.resolve_shared_key(request.viewing_key_account)?;
        let owner = queried.account.owner;

        let program_id = Address::new_from_array(SQUADS_RING_PROGRAM_ID);
        let accounts = self.rpc().get_program_accounts(program_id)?;

        let mut proposals = Vec::new();
        for (pda, account) in accounts {
            let Ok(proposal) = Proposal::deserialize(&account.data) else {
                continue;
            };
            if proposal.discriminator != Proposal::DISCRIMINATOR {
                continue;
            }
            if proposal.owner != owner && proposal.recipient != owner {
                continue;
            }
            let Ok(reconstructed) = self.reconstruct_ring_proposal(pda, &proposal) else {
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
