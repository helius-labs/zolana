use std::sync::Arc;

use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use spl_token_2022_interface::{extension::StateWithExtensions, state::Account as TokenAccount};
use spr_instruction::instruction::{
    Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    TransactSplDepositAccounts, TransactSplWithdrawalAccounts,
};
use spr_interface::{
    instruction::TransactIxData, pda, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use spr_transaction::instructions::transact::{SettlementTransfer, SppProofInputs};

use super::{
    prove_on_blocking_pool, AsyncIndexer, AsyncSprClient, BlockingIndexer, BlockingRpc, SprClient,
};
use crate::{
    authority::{complete_with_authorities, ProofAuthority},
    error::ClientError,
    prover::{
        indexed::PreparedIndexedTransfer,
        indexed::{IndexedTransferPreparation, IndexedTransferRail},
        transact::witness::{build_confidential_eddsa_transfer, build_transfer},
        witness::InputWitnesses,
        OwnerAuthorization, Proof, Prover, TransferProofResult,
    },
    rpc::{
        compile_message, sign_transaction, AsyncRpc, ComputeBudgetConfig,
        SettlementAccountValidation,
    },
};

/// A message awaiting signatures and its corresponding blockhash expiry.
#[derive(Clone, Debug, PartialEq)]
pub struct UnsignedMessage {
    pub message: VersionedMessage,
    pub last_valid_block_height: u64,
}

/// Encrypted inputs and explicit proof authorities. Settlement accounts stay
/// paired with the public transfers from which they are derived.
pub struct TransactionProofRequest<'a> {
    transaction: SppProofInputs,
    authorities: Vec<&'a dyn ProofAuthority>,
    settlement_transfers: Vec<Option<TransactInterfaceTransferAccounts>>,
    prover: Option<Arc<dyn Prover>>,
    confidential_eddsa_owner: Option<OwnerAuthorization<'a>>,
}

/// A transaction with an attached proof, reusable with a fresh Solana blockhash.
/// Proof verification is performed on chain.
#[derive(Clone, Debug)]
pub struct ProvedTransaction {
    payer: Address,
    input_tree_ids: Vec<u16>,
    output_tree_id: u16,
    read_cache: Option<Address>,
    write_cache: Option<Address>,
    owner_signers: Vec<Address>,
    settlement_transfers: Vec<SettlementTransfer>,
    instruction_data: TransactIxData,
}

impl ProvedTransaction {
    pub fn instruction_data(&self) -> &TransactIxData {
        &self.instruction_data
    }

    /// Build `transact` after checking the supplied accounts against its transfers.
    pub fn instruction(
        &self,
        settlement_accounts: &[TransactInterfaceTransferAccounts],
    ) -> Result<Instruction, ClientError> {
        if self.write_cache.is_some() {
            return Err(ClientError::CacheWriteNeedsWriter);
        }
        SettlementAccountValidation {
            transfers: &self.instruction_data.interface_transfers,
            accounts: settlement_accounts,
        }
        .validate()?;
        for (index, (transfer, accounts)) in self
            .settlement_transfers
            .iter()
            .zip(settlement_accounts)
            .enumerate()
        {
            let matches = match (transfer, accounts) {
                (
                    SettlementTransfer::Sol {
                        user_sol_account, ..
                    },
                    TransactInterfaceTransferAccounts::Sol(accounts),
                ) => accounts.recipient == *user_sol_account,
                (
                    SettlementTransfer::Spl {
                        mint,
                        user_spl_token,
                        ..
                    },
                    TransactInterfaceTransferAccounts::SplDeposit(accounts),
                ) => {
                    accounts.mint == *mint
                        && accounts.user_token_account == *user_spl_token
                        && accounts.spl_interface == pda::spl_interface(mint)
                        && matches!(
                            accounts.token_program.to_bytes(),
                            SPL_TOKEN_PROGRAM_ID | SPL_TOKEN_2022_PROGRAM_ID
                        )
                }
                (
                    SettlementTransfer::Spl {
                        mint,
                        user_spl_token,
                        ..
                    },
                    TransactInterfaceTransferAccounts::SplWithdrawal(accounts),
                ) => {
                    accounts.mint == *mint
                        && accounts.user_token_account == *user_spl_token
                        && accounts.spl_interface == pda::spl_interface(mint)
                        && matches!(
                            accounts.token_program.to_bytes(),
                            SPL_TOKEN_PROGRAM_ID | SPL_TOKEN_2022_PROGRAM_ID
                        )
                }
                _ => false,
            };
            if !matches {
                return Err(ClientError::SettlementTransferAccountMismatch { index });
            }
        }
        let transact = Transact {
            payer: self.payer,
            input_trees: self.input_tree_ids.iter().copied().map(pda::tree).collect(),
            output_tree: pda::tree(self.output_tree_id),
            owner_signers: self.owner_signers.clone(),
            interface_transfer_accounts: settlement_accounts.to_vec(),
            data: self.instruction_data.clone(),
        };
        Ok(match self.read_cache {
            Some(cache) => transact.instruction_with_cache_read(cache),
            None => transact.instruction(),
        })
    }

    /// Pure message construction. The blockhash and height must come from
    /// the same RPC response.
    pub fn build_solana_message(
        &self,
        settlement_accounts: &[TransactInterfaceTransferAccounts],
        blockhash: Hash,
        last_valid_block_height: u64,
        compute_budget: ComputeBudgetConfig,
    ) -> Result<UnsignedMessage, ClientError> {
        Ok(UnsignedMessage {
            message: compile_message(
                &self.payer,
                &[self.instruction(settlement_accounts)?],
                blockhash,
                compute_budget,
            )?,
            last_valid_block_height,
        })
    }
}

impl<'a> TransactionProofRequest<'a> {
    pub fn new(
        transaction: SppProofInputs,
        authorities: &[&'a dyn ProofAuthority],
    ) -> Result<Self, ClientError> {
        transaction.check_shape()?;
        transaction.public_transfers()?;
        transaction.owner_signer_pubkeys()?;
        let settlement_transfers = transaction
            .external_data
            .interface_transfers
            .iter()
            .map(|transfer| match transfer {
                SettlementTransfer::Sol {
                    user_sol_account, ..
                } => Some(TransactInterfaceTransferAccounts::Sol(
                    TransactSolTransferAccounts {
                        recipient: *user_sol_account,
                    },
                )),
                SettlementTransfer::Spl { .. } => None,
            })
            .collect();
        Ok(Self {
            transaction,
            authorities: authorities.to_vec(),
            settlement_transfers,
            prover: None,
            confidential_eddsa_owner: None,
        })
    }

    #[must_use]
    pub fn with_prover(mut self, prover: Arc<dyn Prover>) -> Self {
        self.prover = Some(prover);
        self
    }

    /// Authorize this owner inside the proof and omit its owner-signer account.
    /// Select the EdDSA shape with `with_transaction_signers` before encryption.
    #[must_use]
    pub fn with_confidential_eddsa_owner(
        mut self,
        owner: impl Into<OwnerAuthorization<'a>>,
    ) -> Self {
        self.confidential_eddsa_owner = Some(owner.into());
        self
    }

    /// Build completed prover inputs and matching instruction data without I/O.
    pub fn build(&self, proofs: InputWitnesses) -> Result<TransferProofResult, ClientError> {
        let mut transfer = match self.confidential_eddsa_owner {
            Some(owner) => build_confidential_eddsa_transfer(
                self.transaction.clone(),
                &proofs.spend_proofs,
                &proofs.dummy_nullifier_proofs,
                owner,
            )?,
            None => build_transfer(
                self.transaction.clone(),
                &proofs.spend_proofs,
                &proofs.dummy_nullifier_proofs,
            )?,
        };
        complete_with_authorities(
            &mut transfer.inputs.inputs,
            &self.transaction.input_utxos,
            &self.authorities,
        )?;
        Ok(transfer)
    }

    /// Build an indexed request synchronously; the server fetches the chain proofs.
    pub fn build_indexed(&self) -> Result<PreparedIndexedTransfer, ClientError> {
        IndexedTransferPreparation {
            transaction: self.transaction.clone(),
            rail: match self.confidential_eddsa_owner {
                Some(owner) => IndexedTransferRail::ConfidentialEddsa { owner },
                None => IndexedTransferRail::Confidential,
            },
        }
        .prepare_with_authorities(&self.authorities, true)
    }

    /// Invoke the selected prover with already completed inputs. No chain reads.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
        transfer: &TransferProofResult,
    ) -> Result<Proof, ClientError> {
        let keys = match &self.prover {
            Some(prover) => prover.key_set(),
            None => client.key_set(),
        };
        transfer.check_key_set(keys)?;
        match &self.prover {
            Some(prover) => match prover.server_client() {
                Some(server) => server.prove(&transfer.request()?).await,
                None => prove_on_blocking_pool(Arc::clone(prover), transfer.request()?).await,
            },
            None => client.prove(transfer).await,
        }
    }

    pub fn prove_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
        transfer: &TransferProofResult,
    ) -> Result<Proof, ClientError> {
        client.block_on(self.prove(&client.client, transfer))
    }

    /// Attach a returned proof without performing local Groth16 verification.
    pub fn with_proof(
        &self,
        mut transfer: TransferProofResult,
        proof: Proof,
    ) -> Result<ProvedTransaction, ClientError> {
        let proof = transfer.accept_proof(proof)?;
        let tree_ids = transfer.tree_ids.clone();
        self.proved_transaction(tree_ids, transfer.with_proof(proof))
    }

    fn proved_transaction(
        &self,
        input_tree_ids: Vec<u16>,
        instruction_data: TransactIxData,
    ) -> Result<ProvedTransaction, ClientError> {
        let external = &self.transaction.external_data;
        if instruction_data.private_tx_hash
            != self.transaction.padding_independent_private_tx_hash()?
            || instruction_data.expiry_unix_ts != external.expiry_unix_ts
            || instruction_data.data_hash != external.data_hash
            || instruction_data.ring_data_hash != external.ring_data_hash
            || instruction_data.tx_viewing_pk != external.tx_viewing_pk
            || instruction_data.salt != external.salt
            || instruction_data.outputs != external.outputs
            || instruction_data.messages != external.messages
            || instruction_data
                .interface_transfers
                .iter()
                .copied()
                .ne(external
                    .interface_transfers
                    .iter()
                    .copied()
                    .map(SettlementTransfer::interface_transfer))
        {
            return Err(ClientError::TransactionProofRequestMismatch);
        }
        let mut owner_signers = self.transaction.owner_signer_pubkeys()?;
        if let Some(owner) = self.confidential_eddsa_owner {
            let owner = Address::new_from_array(owner.public_key().as_ed25519()?);
            owner_signers.retain(|signer| *signer != owner);
        }
        Ok(ProvedTransaction {
            payer: self.transaction.payer,
            input_tree_ids,
            output_tree_id: self.transaction.output_tree_id,
            read_cache: self.transaction.cache_accounts.read,
            write_cache: self.transaction.cache_accounts.write,
            owner_signers,
            settlement_transfers: self.transaction.external_data.interface_transfers.clone(),
            instruction_data,
        })
    }

    /// Fetch proof data, prove, and fetch settlement accounts and a blockhash in
    /// parallel, then return the unsigned Solana message. Does not sign or send.
    pub async fn fetch_and_prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
    ) -> Result<UnsignedMessage, ClientError> {
        if self.transaction.cache_accounts.write.is_some() {
            return Err(ClientError::CacheWriteNeedsWriter);
        }
        let proving = async {
            if self.prover.is_none() && client.indexed_prover().is_some() {
                let mut prepared = self.build_indexed()?;
                if let Some(slot) = client.indexer_config.require_slot {
                    prepared = prepared.with_min_context_slot(slot);
                }
                let proved = client.prove_indexed(&prepared).await?;
                self.proved_transaction(proved.input_tree_ids, proved.data)
            } else {
                let input_proofs = client.fetch_input_proofs(self).await?;
                let transfer = self.build(input_proofs)?;
                let proof = self.prove(client, &transfer).await?;
                self.with_proof(transfer, proof)
            }
        };
        let (proved, accounts, (blockhash, height)) = tokio::try_join!(
            proving,
            client.fetch_settlement_accounts(self),
            client.get_latest_blockhash(),
        )?;
        proved.build_solana_message(&accounts, blockhash, height, client.compute_budget())
    }

    pub fn fetch_and_prove_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
    ) -> Result<UnsignedMessage, ClientError> {
        client.block_on(self.fetch_and_prove(&client.client))
    }

    /// Fetch and prove, sign, submit, and wait for confirmation and indexing.
    pub async fn prove_and_send<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        let unsigned = self.fetch_and_prove(client).await?;
        let signature = client
            .process_transaction(sign_transaction(unsigned.message, signers)?)
            .await?;
        client.confirm_private_transaction(signature).await?;
        Ok(signature)
    }

    pub fn prove_and_send_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        client.block_on(self.prove_and_send(&client.client, signers))
    }

    async fn resolve_settlement_accounts<R: AsyncRpc>(
        &self,
        rpc: &R,
    ) -> Result<Vec<TransactInterfaceTransferAccounts>, ClientError> {
        let mut accounts = Vec::with_capacity(self.settlement_transfers.len());
        for (transfer, sol_accounts) in self
            .transaction
            .external_data
            .interface_transfers
            .iter()
            .zip(&self.settlement_transfers)
        {
            if let Some(sol_accounts) = sol_accounts {
                accounts.push(*sol_accounts);
                continue;
            }
            let SettlementTransfer::Spl {
                mint,
                is_deposit,
                user_spl_token,
                ..
            } = transfer
            else {
                return Err(ClientError::SettlementTransferTypeMismatch {
                    index: accounts.len(),
                });
            };
            let mint_account =
                rpc.get_account(*mint)
                    .await?
                    .ok_or(ClientError::AccountNotFound {
                        address: mint.to_bytes(),
                    })?;
            let token_program = mint_account.owner;
            if token_program.to_bytes() != SPL_TOKEN_PROGRAM_ID
                && token_program.to_bytes() != SPL_TOKEN_2022_PROGRAM_ID
            {
                return Err(ClientError::UnsupportedSplTokenProgram {
                    mint: *mint,
                    owner: token_program,
                });
            }
            let token_account = rpc
                .get_account(*user_spl_token)
                .await?
                .ok_or(ClientError::MissingSplTokenAccount { mint: *mint })?;
            let invalid = || ClientError::InvalidSplTokenAccount {
                address: *user_spl_token,
                mint: *mint,
            };
            if token_account.owner != token_program {
                return Err(invalid());
            }
            let token = StateWithExtensions::<TokenAccount>::unpack(&token_account.data)
                .map_err(|_| invalid())?;
            if token.base.mint != *mint {
                return Err(invalid());
            }
            accounts.push(if *is_deposit {
                TransactInterfaceTransferAccounts::SplDeposit(TransactSplDepositAccounts {
                    mint: *mint,
                    spl_interface: pda::spl_interface(mint),
                    token_authority: token.base.owner,
                    user_token_account: *user_spl_token,
                    token_program,
                })
            } else {
                TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
                    mint: *mint,
                    spl_interface: pda::spl_interface(mint),
                    user_token_account: *user_spl_token,
                    token_program,
                })
            });
        }
        Ok(accounts)
    }
}

#[cfg(test)]
#[path = "transaction_test.rs"]
mod tests;

impl<R: AsyncRpc, I: AsyncIndexer> AsyncSprClient<R, I> {
    pub async fn fetch_input_proofs(
        &self,
        request: &TransactionProofRequest<'_>,
    ) -> Result<InputWitnesses, ClientError> {
        self.indexer
            .transaction_proofs(&request.transaction.input_utxos, Some(self.indexer_config))
            .await
    }

    pub async fn fetch_settlement_accounts(
        &self,
        request: &TransactionProofRequest<'_>,
    ) -> Result<Vec<TransactInterfaceTransferAccounts>, ClientError> {
        request.resolve_settlement_accounts(self.rpc()).await
    }

    /// Invoke the configured backend without fetching proof data or verifying the proof locally.
    pub async fn prove(&self, transfer: &TransferProofResult) -> Result<Proof, ClientError> {
        transfer.check_key_set(self.key_set())?;
        self.prove_request(transfer.request()?).await
    }

    /// Invoke the indexed backend. Resolution and response validation stay with that backend.
    pub async fn prove_indexed(
        &self,
        prepared: &PreparedIndexedTransfer,
    ) -> Result<crate::prover::indexed::ProvenIndexedTransfer, ClientError> {
        self.server_prover()
            .ok_or(ClientError::IndexedProverUnavailable)?
            .prove_indexed(prepared)
            .await
    }
}

impl<R: BlockingRpc, I: BlockingIndexer> SprClient<R, I> {
    pub fn fetch_input_proofs(
        &self,
        request: &TransactionProofRequest<'_>,
    ) -> Result<InputWitnesses, ClientError> {
        self.block_on(self.client.fetch_input_proofs(request))
    }

    pub fn fetch_settlement_accounts(
        &self,
        request: &TransactionProofRequest<'_>,
    ) -> Result<Vec<TransactInterfaceTransferAccounts>, ClientError> {
        self.block_on(self.client.fetch_settlement_accounts(request))
    }

    pub fn prove(&self, transfer: &TransferProofResult) -> Result<Proof, ClientError> {
        self.block_on(self.client.prove(transfer))
    }

    pub fn prove_indexed(
        &self,
        prepared: &PreparedIndexedTransfer,
    ) -> Result<crate::prover::indexed::ProvenIndexedTransfer, ClientError> {
        self.block_on(self.client.prove_indexed(prepared))
    }
}

#[cfg(all(test, feature = "reqwest"))]
#[path = "transaction_runtime_keys_test.rs"]
mod runtime_keys_tests;
