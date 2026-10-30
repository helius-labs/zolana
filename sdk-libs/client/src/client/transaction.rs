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
use spr_keypair::SigningKey;
use spr_transaction::instructions::transact::{SettlementTransfer, SppProofInputs};

use super::{
    prove_on_blocking_pool, AsyncIndexer, AsyncZolanaClient, BlockingIndexer, BlockingRpc,
    ZolanaClient,
};
use crate::{
    authority::{complete_with_authorities, ProofAuthority},
    error::ClientError,
    prover::{
        indexed::{IndexedTransferPreparation, IndexedTransferRail},
        transact::witness::{assemble, assemble_confidential_eddsa},
        Prover,
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
    confidential_eddsa_owner: Option<&'a SigningKey>,
}

/// A verified transaction proof, reusable with a fresh Solana blockhash.
#[derive(Clone, Debug)]
pub struct ProvedTransaction {
    payer: Address,
    input_tree_ids: Vec<u16>,
    output_tree_id: u16,
    read_cache: Option<Address>,
    write_cache: Option<Address>,
    owner_signers: Vec<Address>,
    settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
    instruction_data: TransactIxData,
}

impl ProvedTransaction {
    pub fn instruction_data(&self) -> &TransactIxData {
        &self.instruction_data
    }

    /// The verified `transact` instruction for custom message composition.
    pub fn instruction(&self) -> Result<Instruction, ClientError> {
        if self.write_cache.is_some() {
            return Err(ClientError::CacheWriteNeedsWriter);
        }
        let transact = Transact {
            payer: self.payer,
            input_trees: self.input_tree_ids.iter().copied().map(pda::tree).collect(),
            output_tree: pda::tree(self.output_tree_id),
            owner_signers: self.owner_signers.clone(),
            interface_transfer_accounts: self.settlement_transfers.clone(),
            data: self.instruction_data.clone(),
        };
        Ok(match self.read_cache {
            Some(cache) => transact.instruction_with_cache_read(cache),
            None => transact.instruction(),
        })
    }

    /// Pure message construction. The blockhash and height must come from
    /// the same RPC response, fetched after proving.
    pub fn build_solana_message(
        &self,
        blockhash: Hash,
        last_valid_block_height: u64,
        compute_budget: ComputeBudgetConfig,
    ) -> Result<UnsignedMessage, ClientError> {
        Ok(UnsignedMessage {
            message: compile_message(
                &self.payer,
                &[self.instruction()?],
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
    pub fn with_confidential_eddsa_owner(mut self, owner: &'a SigningKey) -> Self {
        self.confidential_eddsa_owner = Some(owner);
        self
    }

    /// Fetch proof data, complete every real input, and verify the generated proof.
    /// SPL metadata is resolved from the mint and token account on the Solana RPC.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvedTransaction, ClientError> {
        let settlement_transfers = self.resolve_settlement_accounts(client.rpc()).await?;
        let (input_tree_ids, instruction_data) = match (&self.prover, client.indexed_prover()) {
            (None, Some(server)) => {
                let mut prepared = IndexedTransferPreparation {
                    transaction: self.transaction.clone(),
                    rail: match self.confidential_eddsa_owner {
                        Some(owner) => IndexedTransferRail::ConfidentialEddsa { owner },
                        None => IndexedTransferRail::Confidential,
                    },
                }
                .prepare_with_authorities(&self.authorities, true)?;
                if let Some(slot) = client.indexer_config.require_slot {
                    prepared = prepared.with_min_context_slot(slot);
                }
                let proved = server.prove_indexed(&prepared).await?;
                (proved.input_tree_ids, proved.data)
            }
            (prover, _) => {
                let proofs = client
                    .indexer
                    .transaction_proofs(&self.transaction.input_utxos, Some(client.indexer_config))
                    .await?;
                let mut assembled = match self.confidential_eddsa_owner {
                    Some(owner) => assemble_confidential_eddsa(
                        self.transaction.clone(),
                        &proofs.spend_proofs,
                        &proofs.dummy_nullifier_proofs,
                        owner,
                    )?,
                    None => assemble(
                        self.transaction.clone(),
                        &proofs.spend_proofs,
                        &proofs.dummy_nullifier_proofs,
                    )?,
                };
                complete_with_authorities(
                    &mut assembled.prover_inputs.inputs,
                    &self.transaction.input_utxos,
                    &self.authorities,
                )?;
                let proof = match prover {
                    Some(prover) => {
                        prove_on_blocking_pool(Arc::clone(prover), assembled.request()?).await?
                    }
                    None => client.prove_request(assembled.request()?).await?,
                };
                let proof = assembled.accept_proof(proof)?;
                let input_tree_ids = assembled.input_tree_ids.clone();
                (input_tree_ids, assembled.with_proof(proof))
            }
        };
        SettlementAccountValidation {
            transfers: &instruction_data.interface_transfers,
            accounts: &settlement_transfers,
        }
        .validate()?;
        let mut owner_signers = self.transaction.owner_signer_pubkeys()?;
        if let Some(owner) = self.confidential_eddsa_owner {
            let owner = Address::new_from_array(owner.pubkey().as_ed25519()?);
            owner_signers.retain(|signer| *signer != owner);
        }
        Ok(ProvedTransaction {
            payer: self.transaction.payer,
            input_tree_ids,
            output_tree_id: self.transaction.output_tree_id,
            read_cache: self.transaction.cache_accounts.read,
            write_cache: self.transaction.cache_accounts.write,
            owner_signers,
            settlement_transfers,
            instruction_data,
        })
    }

    pub fn prove_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
    ) -> Result<ProvedTransaction, ClientError> {
        client.block_on(self.prove(&client.client))
    }

    /// Prove and verify, then fetch a fresh blockhash, sign, submit, confirm and index.
    pub async fn prove_and_send<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        if self.transaction.cache_accounts.write.is_some() {
            return Err(ClientError::CacheWriteNeedsWriter);
        }
        let proved = self.prove(client).await?;
        let (blockhash, last_valid_block_height) = client.get_latest_blockhash().await?;
        let unsigned = proved.build_solana_message(
            blockhash,
            last_valid_block_height,
            client.compute_budget(),
        )?;
        let signature = client
            .process_transaction(sign_transaction(unsigned.message, signers)?)
            .await?;
        client.confirm_private_transaction(signature).await?;
        Ok(signature)
    }

    pub fn prove_and_send_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
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
