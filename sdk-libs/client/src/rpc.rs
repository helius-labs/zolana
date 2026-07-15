use std::pin::Pin;

use async_trait::async_trait;
use futures::Stream;
use solana_account::Account;
use solana_address::Address;
use solana_clock::Slot;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{AddressLookupTableAccount, Message};
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use solana_transaction_status_client_types::TransactionStatus;
use zolana_keypair::P256Pubkey;
use zolana_transaction::instructions::{transact::SignedTransaction, types::InputCommitment};
pub use zolana_transaction::{OutputContext, OutputSlot, ShieldedTransaction};

use crate::{
    error::ClientError,
    prover::{transact::witness::SpendProof, ProofCompressed},
};

pub const STATE_TREE_HEIGHT: usize = 32;
pub const NULLIFIER_TREE_HEIGHT: usize = 40;

/// Slot the indexer assembled a response at. Every indexer response carries one
/// so the client knows the chain state the answer reflects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub slot: u64,
}

/// Identifies the tree a proof was produced against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleContext {
    pub tree_type: u16,
    pub tree: Address,
}

/// A single ciphertext whose view tag matched a query tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedUtxoMatch {
    pub slot: u64,
    pub tx_signature: Signature,
    pub output_slot: OutputSlot,
    /// `None` when the payload is plaintext (nothing to decrypt).
    pub tx_viewing_pk: Option<P256Pubkey>,
    /// Transaction-level AES salt shared by every output ciphertext; `None` for
    /// plaintext/proofless payloads.
    pub salt: Option<[u8; 16]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetEncryptedUtxosByTagsResponse {
    pub context: Context,
    pub matches: Vec<EncryptedUtxoMatch>,
    pub next_cursor: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetShieldedTransactionsByTagsResponse {
    pub context: Context,
    pub transactions: Vec<ShieldedTransaction>,
    pub next_cursor: Option<Vec<u8>>,
}

/// Stream of shielded transactions pushed as they land, one per matching transaction.
pub type ShieldedTransactionStream =
    Pin<Box<dyn Stream<Item = Result<ShieldedTransaction, ClientError>> + Send>>;

/// Inclusion proof for a leaf, plus the root metadata the consuming instruction needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub merkle_context: MerkleContext,
    /// Sibling hashes; length matches the tree height.
    pub path: Vec<[u8; 32]>,
    pub leaf_index: u64,
    pub root: [u8; 32],
    pub root_seq: u64,
    pub root_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetMerkleProofsResponse {
    pub context: Context,
    pub proofs: Vec<MerkleProof>,
}

/// Non-inclusion proof for a leaf against an indexed Merkle tree, with the low/high
/// adjacency witness bounding the exclusion range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonInclusionProof {
    pub leaf: [u8; 32],
    pub merkle_context: MerkleContext,
    pub path: Vec<[u8; 32]>,
    pub low_element: [u8; 32],
    pub low_element_index: u64,
    pub high_element: [u8; 32],
    pub high_element_index: u64,
    pub root: [u8; 32],
    pub root_seq: u64,
    pub root_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetNonInclusionProofsResponse {
    pub context: Context,
    pub proofs: Vec<NonInclusionProof>,
}

/// Result of a server-side proving request.
#[derive(Clone, Debug)]
pub struct ProveResult {
    pub proof: ProofCompressed,
    pub public_inputs: Vec<[u8; 32]>,
    pub circuit_id: u16,
}

/// Combined Solana RPC, SPP indexer, and proving surface used by clients.
#[allow(unused_variables)]
pub trait Rpc {
    // ===== Accounts =====

    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Err(unsupported("get_account"))
    }

    fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        Err(unsupported("get_multiple_accounts"))
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        Err(unsupported("get_program_accounts"))
    }

    // ===== Chain state =====

    fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        Err(unsupported("get_balance"))
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Err(unsupported("get_latest_blockhash"))
    }

    fn get_block_height(&self) -> Result<u64, ClientError> {
        Err(unsupported("get_block_height"))
    }

    fn get_slot(&self) -> Result<u64, ClientError> {
        Err(unsupported("get_slot"))
    }

    fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        Err(unsupported("get_transaction_slot"))
    }

    fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        Err(unsupported("get_signature_statuses"))
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        Err(unsupported("get_minimum_balance_for_rent_exemption"))
    }

    fn health(&self) -> Result<(), ClientError> {
        Err(unsupported("health"))
    }

    // ===== Transactions =====

    fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
        Err(unsupported("send_transaction"))
    }

    fn send_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("send_transaction_with_config"))
    }

    fn send_versioned_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("send_versioned_transaction_with_config"))
    }

    fn process_transaction(&self, transaction: Transaction) -> Result<Signature, ClientError> {
        Err(unsupported("process_transaction"))
    }

    fn process_transaction_with_context(
        &self,
        transaction: Transaction,
    ) -> Result<(Signature, Slot), ClientError> {
        Err(unsupported("process_transaction_with_context"))
    }

    fn process_versioned_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("process_versioned_transaction"))
    }

    fn create_and_send_transaction(
        &self,
        instructions: &[Instruction],
        payer: Address,
        signers: &[&Keypair],
    ) -> Result<Signature, ClientError> {
        let (blockhash, _) = self.get_latest_blockhash()?;
        let payer = Pubkey::new_from_array(payer.to_bytes());
        let message = Message::new(instructions, Some(&payer));
        let transaction = Transaction::new(signers, message, blockhash);
        self.send_transaction(&transaction)
    }

    fn create_and_send_versioned_transaction(
        &self,
        instructions: &[Instruction],
        payer: Address,
        signers: &[&Keypair],
        address_lookup_tables: &[AddressLookupTableAccount],
    ) -> Result<Signature, ClientError> {
        Err(unsupported("create_and_send_versioned_transaction"))
    }

    // ===== Misc =====

    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        Err(unsupported("confirm_transaction"))
    }

    fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        Err(unsupported("transact_output_view_tags_from_signature"))
    }

    fn should_retry(&self, error: &ClientError) -> bool {
        false
    }

    // ===== Indexer (SPP) =====

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Err(unsupported("get_encrypted_utxos_by_tags"))
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_tags"))
    }

    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        Err(unsupported("subscribe_to_shielded_transactions_by_tags"))
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        Err(unsupported("get_merkle_proofs"))
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        Err(unsupported("get_non_inclusion_proofs"))
    }

    /// Resolve the state-inclusion and nullifier-non-inclusion proofs for each
    /// input UTXO commitment, returned in the same order as the commitments.
    fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputCommitment],
    ) -> Result<Vec<SpendProof>, ClientError> {
        Err(unsupported("get_input_merkle_proofs"))
    }

    // ===== Proving =====

    /// Build the SPP proof for a signed transaction (server-side proving).
    fn prove(&self, transaction: SignedTransaction) -> Result<ProveResult, ClientError> {
        Err(unsupported("prove"))
    }
}

/// Async combined Solana RPC, SPP indexer, and proving surface for production clients.
#[async_trait]
#[allow(unused_variables)]
pub trait AsyncRpc: Send + Sync {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Err(unsupported("get_account"))
    }

    async fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        Err(unsupported("get_multiple_accounts"))
    }

    async fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        Err(unsupported("get_program_accounts"))
    }

    async fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        Err(unsupported("get_balance"))
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Err(unsupported("get_latest_blockhash"))
    }

    async fn get_block_height(&self) -> Result<u64, ClientError> {
        Err(unsupported("get_block_height"))
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        Err(unsupported("get_slot"))
    }

    async fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        Err(unsupported("get_transaction_slot"))
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        Err(unsupported("get_signature_statuses"))
    }

    async fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
    ) -> Result<u64, ClientError> {
        Err(unsupported("get_minimum_balance_for_rent_exemption"))
    }

    async fn health(&self) -> Result<(), ClientError> {
        Err(unsupported("health"))
    }

    async fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
        Err(unsupported("send_transaction"))
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("send_transaction_with_config"))
    }

    async fn send_versioned_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("send_versioned_transaction_with_config"))
    }

    async fn process_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("process_transaction"))
    }

    async fn process_transaction_with_context(
        &self,
        transaction: Transaction,
    ) -> Result<(Signature, Slot), ClientError> {
        Err(unsupported("process_transaction_with_context"))
    }

    async fn process_versioned_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("process_versioned_transaction"))
    }

    async fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        Err(unsupported("confirm_transaction"))
    }

    async fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        Err(unsupported("transact_output_view_tags_from_signature"))
    }

    fn should_retry(&self, error: &ClientError) -> bool {
        false
    }

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Err(unsupported("get_encrypted_utxos_by_tags"))
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_tags"))
    }

    async fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        Err(unsupported("subscribe_to_shielded_transactions_by_tags"))
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        Err(unsupported("get_merkle_proofs"))
    }

    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        Err(unsupported("get_non_inclusion_proofs"))
    }

    async fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputCommitment],
    ) -> Result<Vec<SpendProof>, ClientError> {
        Err(unsupported("get_input_merkle_proofs"))
    }

    async fn prove(&self, transaction: SignedTransaction) -> Result<ProveResult, ClientError> {
        Err(unsupported("prove"))
    }
}

fn unsupported(method: &'static str) -> ClientError {
    ClientError::UnsupportedRpcMethod(method)
}
