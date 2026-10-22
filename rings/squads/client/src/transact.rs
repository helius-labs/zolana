//! `requestTransact`: build the paired ring + SPP proofs and the `transact`
//! instruction for a transfer or withdrawal.
//!
//! The backend proves on the account's behalf using the shared viewing key and
//! nullifier secret it recovered with the auditor key. A smart-account owner
//! settles on the signatureless ring-authority rail. A Ed25519 keypair owner signs
//! `transact_message_hash(private_tx_hash, external_data_hash)`, which [`SquadsBackend::request_transact_probe`]
//! returns; the probe is deterministic in the request, so the signed hash is the
//! one the finalize step rebuilds. The relayer (`ring_authority`) is the fee
//! payer and co-signer.

use solana_pubkey::Pubkey;
use zolana_client::{Rpc, SpendProof};
use zolana_keypair::{hash::sha256, NullifierKey, X25519Pubkey};
use zolana_squads_interface::{
    instruction::{builders::Transact, instruction_data::TransactIxData},
    state::ViewingKeyAccount,
};
use zolana_squads_sdk::prover::{
    dummy_input, probe_squads_spend, ProbedSpend, RingProposal, SquadsDummyInput, SquadsOwner,
    SquadsRecipient, SquadsSender, SquadsSpendInput, SquadsSpendOperation, SquadsSpendProof,
    SquadsSpendRequest, WithdrawalSettlement,
};
use zolana_transaction::Address;

use crate::{
    backend::{ResolvedAccount, SquadsBackend, SOL_ASSET_ID},
    error::{Result, SquadsBackendError},
    tags::{account_view_tag, view_tag_from_shared_viewing_key},
    types::{DecryptedUtxo, RequestTransactRequest, RequestTransactResponse, TransactionType},
};

fn to_pubkey(address: Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

/// What a spend pays out.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SpendKind {
    Transfer {
        recipient_viewing_key_account: Address,
        amount: u64,
    },
    Withdrawal {
        amount: u64,
        recipient_account: Address,
    },
}

/// Everything the backend needs to probe one spend.
pub(crate) struct SpendParams<'a> {
    pub sender: &'a ResolvedAccount,
    pub owner: SquadsOwner,
    pub inputs: &'a [DecryptedUtxo],
    pub kind: SpendKind,
    pub expiry: i64,
    pub proposal: Option<RingProposal>,
}

/// A padding blinding derived from the spent inputs, so re-probing the same
/// request rebuilds the same transaction. It is a 248-bit field element.
fn padding_blinding(inputs: &[DecryptedUtxo], expiry: i64) -> [u8; 32] {
    let mut preimage = b"squads-ring/padding".to_vec();
    for input in inputs {
        preimage.extend_from_slice(&input.utxo_hash);
    }
    preimage.extend_from_slice(&expiry.to_be_bytes());
    let mut blinding = sha256(&preimage);
    blinding[0] = 0;
    blinding
}

impl<I: Rpc, R: Rpc> SquadsBackend<I, R> {
    /// Build the proof and `transact` instruction.
    ///
    /// `sender_owner_pubkey == None` selects the smart-account (signatureless)
    /// rail. `Some` selects the Ed25519 keypair rail, which requires the client's
    /// `owner_signature` over `transact_message_hash(private_tx_hash, external_data_hash)` (see
    /// [`Self::request_transact_probe`]).
    pub fn request_transact(
        &self,
        request: RequestTransactRequest,
    ) -> Result<RequestTransactResponse> {
        let sender = self.resolve_shared_key(request.intent.sender_viewing_key_account)?;
        let (owner, authorization) = match request.sender_owner_pubkey {
            None => (SquadsOwner::SmartAccount, None),
            Some(bytes) => {
                let signature = request.owner_signature.ok_or_else(|| {
                    SquadsBackendError::Unsupported(
                        "Ed25519 keypair rail requires owner_signature over transact_message_hash(private_tx_hash, external_data_hash); obtain it via request_transact_probe".into(),
                    )
                })?;
                (SquadsOwner::Ed25519(bytes), Some(signature))
            }
        };
        let probe = self.probe_request(&request, &sender, owner)?;
        let proof = probe.finalize(authorization)?;
        let recipient = match request.transaction_type {
            TransactionType::Transfer {
                recipient_viewing_key_account,
            } => Some(recipient_viewing_key_account),
            TransactionType::Withdraw { .. } => None,
        };
        Ok(RequestTransactResponse::Instruction(
            self.transact_instruction(request.intent.sender_viewing_key_account, recipient, proof),
        ))
    }

    /// The Ed25519 keypair rail: the `private_tx_hash` the owner signs (as
    /// `transact_message_hash(private_tx_hash, external_data_hash)`) before calling [`Self::request_transact`].
    pub fn request_transact_probe(&self, request: &RequestTransactRequest) -> Result<[u8; 32]> {
        let bytes = request.sender_owner_pubkey.ok_or_else(|| {
            SquadsBackendError::Unsupported(
                "the Ed25519 keypair rail requires sender_owner_pubkey".into(),
            )
        })?;
        let sender = self.resolve_shared_key(request.intent.sender_viewing_key_account)?;
        Ok(self
            .probe_request(request, &sender, SquadsOwner::Ed25519(bytes))?
            .message_hash)
    }

    fn probe_request(
        &self,
        request: &RequestTransactRequest,
        sender: &ResolvedAccount,
        owner: SquadsOwner,
    ) -> Result<ProbedSpend> {
        let kind = match request.transaction_type {
            TransactionType::Transfer {
                recipient_viewing_key_account,
            } => {
                let recipient = self.load_viewing_key_account(recipient_viewing_key_account)?;
                let amount = request
                    .intent
                    .outputs
                    .iter()
                    .find(|output| output.owner == recipient.owner)
                    .map(|output| output.amount)
                    .ok_or_else(|| {
                        SquadsBackendError::Unsupported("intent has no recipient output".into())
                    })?;
                SpendKind::Transfer {
                    recipient_viewing_key_account,
                    amount,
                }
            }
            TransactionType::Withdraw {
                public_amount,
                recipient_account,
            } => SpendKind::Withdrawal {
                amount: public_amount,
                recipient_account,
            },
        };
        self.probe_spend(SpendParams {
            sender,
            owner,
            inputs: &request.intent.inputs,
            kind,
            expiry: request.intent.expiry,
            proposal: None,
        })
    }

    /// Probe a spend of `params.inputs`. A transfer of a single input is padded
    /// with a dummy slot whose nullifier non-inclusion proof is fetched here.
    pub(crate) fn probe_spend(&self, params: SpendParams<'_>) -> Result<ProbedSpend> {
        let SpendParams {
            sender,
            owner,
            inputs,
            kind,
            expiry,
            proposal,
        } = params;
        let nullifier_key = NullifierKey::from_secret(sender.nullifier_secret);
        let first = inputs.first().ok_or_else(|| {
            SquadsBackendError::Unsupported("a spend needs at least one input".into())
        })?;
        let asset = self.mint_for_asset_id(first.asset_id).ok_or_else(|| {
            SquadsBackendError::Unsupported(format!("unknown asset_id {}", first.asset_id))
        })?;

        let (operation, max_inputs) = match kind {
            SpendKind::Transfer {
                recipient_viewing_key_account,
                amount,
            } => {
                let recipient = self.load_viewing_key_account(recipient_viewing_key_account)?;
                (
                    SquadsSpendOperation::Transfer {
                        recipient: self.transfer_recipient(&recipient)?,
                        amount,
                    },
                    2,
                )
            }
            SpendKind::Withdrawal {
                amount,
                recipient_account,
            } => {
                let settlement = if first.asset_id == SOL_ASSET_ID {
                    WithdrawalSettlement::Sol {
                        recipient: recipient_account,
                    }
                } else {
                    WithdrawalSettlement::Spl {
                        mint: asset,
                        user_token_account: recipient_account,
                    }
                };
                (SquadsSpendOperation::Withdrawal { amount, settlement }, 1)
            }
        };
        if inputs.len() > max_inputs {
            return Err(SquadsBackendError::Unsupported(format!(
                "a spend takes at most {max_inputs} inputs"
            )));
        }

        let mut spend_inputs = Vec::with_capacity(inputs.len());
        for input in inputs {
            let input_asset = self.mint_for_asset_id(input.asset_id).ok_or_else(|| {
                SquadsBackendError::Unsupported(format!("unknown asset_id {}", input.asset_id))
            })?;
            spend_inputs.push(SquadsSpendInput {
                asset: input_asset,
                amount: input.amount,
                blinding: input.blinding,
                tree_id: input.tree_id,
                leaf_index: input.leaf_index,
                spend_proof: self.spend_proof(input, &nullifier_key)?,
            });
        }
        let needs_dummy = match kind {
            SpendKind::Transfer { .. } => inputs.len() == 1,
            SpendKind::Withdrawal { .. } => matches!(owner, SquadsOwner::SmartAccount),
        };
        let dummy = if needs_dummy {
            let blinding = padding_blinding(inputs, expiry);
            let nullifier = dummy_input(blinding, first.tree_id)?.nullifier;
            let nullifier_proof = self
                .indexer()
                .get_non_inclusion_proofs(self.tree_for(first.tree_id), vec![nullifier], None)?
                .proofs
                .into_iter()
                .next()
                .ok_or_else(|| {
                    SquadsBackendError::Unsupported("missing padding non-inclusion proof".into())
                })?;
            Some(SquadsDummyInput {
                blinding,
                nullifier_proof,
            })
        } else {
            None
        };

        Ok(probe_squads_spend(SquadsSpendRequest {
            sender: SquadsSender {
                owner,
                owner_identity: sender.account.owner.to_bytes(),
                nullifier_key,
                viewing_secret: sender.shared_viewing_sk.clone(),
                view_tag: account_view_tag(&sender.account),
            },
            inputs: spend_inputs,
            dummy,
            operation,
            payer: Address::new_from_array(self.relayer_pubkey().to_bytes()),
            output_tree_id: self.tree_id(),
            expiry_unix_ts: u64::try_from(expiry)
                .map_err(|_| SquadsBackendError::Unsupported("negative expiry".into()))?,
            proposal,
            prover_url: self.prover_url().to_string(),
        })?)
    }

    /// The relayer that pays and co-signs ring transactions (the backend's
    /// `ring_authority`).
    pub(crate) fn relayer_pubkey(&self) -> Pubkey {
        self.ring_authority_pubkey()
    }

    /// State-inclusion + nullifier-non-inclusion proofs for one input.
    pub(crate) fn spend_proof(
        &self,
        input: &DecryptedUtxo,
        nullifier_key: &NullifierKey,
    ) -> Result<SpendProof> {
        let nullifier = nullifier_key
            .nullifier(&input.utxo_hash, &input.blinding)
            .map_err(|e| SquadsBackendError::Crypto(format!("nullifier: {e:?}")))?;
        let tree = self.tree_for(input.tree_id);
        let state = self
            .indexer()
            .get_merkle_proofs(tree, vec![input.utxo_hash], None)?
            .proofs
            .into_iter()
            .next()
            .ok_or_else(|| {
                SquadsBackendError::Unsupported("missing state inclusion proof".into())
            })?;
        let non_inclusion = self
            .indexer()
            .get_non_inclusion_proofs(tree, vec![nullifier], None)?
            .proofs
            .into_iter()
            .next()
            .ok_or_else(|| {
                SquadsBackendError::Unsupported("missing nullifier non-inclusion proof".into())
            })?;
        Ok(SpendProof {
            state,
            nullifier: non_inclusion,
        })
    }

    /// The transfer recipient from its viewing key account: the account's owner
    /// identity, nullifier pubkey and shared viewing key are all the recipient
    /// output needs.
    pub(crate) fn transfer_recipient(
        &self,
        account: &ViewingKeyAccount,
    ) -> Result<SquadsRecipient> {
        let viewing_pubkey = X25519Pubkey::from_bytes(account.shared_viewing_key)
            .map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))?;
        Ok(SquadsRecipient {
            owner_identity: account.owner.to_bytes(),
            nullifier_pubkey: account.nullifier_pubkey,
            viewing_pubkey,
            view_tag: view_tag_from_shared_viewing_key(&account.shared_viewing_key),
        })
    }

    /// Assemble the `transact` instruction with the backend's relayer as payer and
    /// co-signer.
    fn transact_instruction(
        &self,
        sender_viewing_key_account: Address,
        recipient_viewing_key_account: Option<Address>,
        proof: SquadsSpendProof,
    ) -> solana_instruction::Instruction {
        let relayer = self.relayer_pubkey();
        Transact {
            payer: relayer,
            co_signer: relayer,
            ring_config: to_pubkey(self.ring_config()),
            sender_viewing_key_account: to_pubkey(sender_viewing_key_account),
            recipient_viewing_key_account: recipient_viewing_key_account.map(to_pubkey),
            spp_accounts: proof.spp_accounts,
            data: TransactIxData {
                ring_proof: proof.ring_proof,
                spp: proof.spp,
            },
        }
        .instruction()
    }
}
