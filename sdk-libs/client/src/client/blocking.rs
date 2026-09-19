use crate::{prover::witness::WitnessReader, rpc::Rpc};

use solana_account::Account;
use solana_address::Address;
use solana_hash::Hash;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::TransactionStatus;
use zolana_transaction::{instructions::transact::SppProofInputs, utxo::SppProofInputUtxo};

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        transact::witness::{assemble, SpendProof},
        verify_confidential_transfer_inputs, ProofCompressed,
    },
    rpc::{
        GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse, GetNonInclusionProofsResponse,
        GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsBySignatureResponse,
        GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, ProveResult,
        ShieldedTransactionStream,
    },
};

use super::ZolanaClient;

impl<R: Rpc> Rpc for ZolanaClient<R> {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.rpc.get_account(address)
    }

    fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        self.rpc.get_multiple_accounts(addresses)
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        self.rpc.get_program_accounts(program_id)
    }

    fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        self.rpc.get_balance(address)
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        self.rpc.get_latest_blockhash()
    }

    fn get_block_height(&self) -> Result<u64, ClientError> {
        self.rpc.get_block_height()
    }

    fn get_slot(&self) -> Result<u64, ClientError> {
        self.rpc.get_slot()
    }

    fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        self.rpc.get_transaction_slot(signature)
    }

    fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.rpc.get_signature_statuses(signatures)
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        self.rpc.get_minimum_balance_for_rent_exemption(data_len)
    }

    fn health(&self) -> Result<(), ClientError> {
        self.rpc.health()
    }

    fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.rpc.send_transaction_with_config(transaction, config)
    }

    fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        self.rpc.process_transaction(transaction)
    }

    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        self.rpc.confirm_transaction(signature)
    }

    fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        self.rpc.transact_output_view_tags_from_signature(signature)
    }

    fn should_retry(&self, error: &ClientError) -> bool {
        self.rpc.should_retry(error) || self.blocking_indexer().should_retry(error)
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.blocking_indexer().get_encrypted_utxos_by_tags(
            tags,
            cursor,
            limit,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.blocking_indexer().get_shielded_transactions_by_tags(
            tags,
            cursor,
            limit,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.blocking_indexer()
            .get_shielded_transactions_by_signature(
                signature,
                Some(config.unwrap_or(self.indexer_config)),
            )
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.blocking_indexer()
            .get_shielded_transactions_by_nullifiers(
                nullifiers,
                cursor,
                limit,
                Some(config.unwrap_or(self.indexer_config)),
            )
    }

    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        self.blocking_indexer()
            .subscribe_to_shielded_transactions_by_tags(tags)
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.blocking_indexer().get_merkle_proofs(
            tree_account,
            leaves,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.blocking_indexer().get_non_inclusion_proofs(
            tree_account,
            leaves,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn get_input_merkle_proofs(
        &self,
        input_utxos: &[&SppProofInputUtxo],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        Ok(self
            .blocking_indexer()
            .input_witnesses(
                input_utxos,
                &[],
                Some(config.unwrap_or(self.indexer_config)),
            )?
            .spend_proofs)
    }

    fn prove(
        &self,
        transaction: SppProofInputs,
        authority: &dyn ProofAuthority,
    ) -> Result<ProveResult, ClientError> {
        let commitments = transaction.input_utxo_hashes()?;
        let witnesses = self.blocking_indexer().input_witnesses(
            &commitments,
            &transaction.dummy_nullifiers(),
            None,
        )?;
        let mut assembled = assemble(
            transaction,
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
        )?;
        let inputs = &mut assembled.prover_inputs;
        let proof = authority.prove_transfer(self.blocking_prover(), inputs)?;
        verify_confidential_transfer_inputs(inputs, assembled.public_input_hash, &proof)?;
        let circuit_id = 0;
        Ok(ProveResult {
            proof: ProofCompressed::try_from(proof)?,
            public_inputs: vec![assembled.public_input_hash],
            circuit_id,
        })
    }
}
