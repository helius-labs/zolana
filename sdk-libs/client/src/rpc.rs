use std::pin::Pin;

use async_trait::async_trait;
use futures::Stream;
use solana_account::Account;
use solana_address::Address;
use solana_clock::Slot;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_message::{v1, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use solana_transaction_status_client_types::TransactionStatus;
use zolana_keypair::P256Pubkey;
use zolana_transaction::instructions::{transact::SppProofInputs, types::InputUtxoContext};
pub use zolana_transaction::{OutputContext, OutputSlot, ShieldedTransaction};

use crate::{
    error::ClientError,
    prover::{transact::witness::SpendProof, ProofCompressed},
    retry::IndexerRpcConfig,
};

pub const STATE_TREE_HEIGHT: usize = 32;
pub const NULLIFIER_TREE_HEIGHT: usize = 40;

/// The runtime's ceiling on the account data one transaction may load, and what
/// a transaction carrying no `set_loaded_accounts_data_size_limit` instruction
/// received by default
/// (`solana_program_runtime::execution_budget::MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES`).
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

const MICRO_LAMPORTS_PER_LAMPORT: u128 = 1_000_000;

/// Compute ceilings for a v1 transaction.
///
/// v1 carries them in the message header rather than in compute-budget
/// instructions, and reads an absent header field as zero rather than as a
/// default, so every ceiling is written explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComputeBudgetConfig {
    pub cu_limit: u32,
    /// Priority bid in micro-lamports per compute unit, the unit
    /// `ComputeBudgetInstruction::set_compute_unit_price` took.
    pub cu_price_micro_lamports: Option<u64>,
}

impl ComputeBudgetConfig {
    pub const fn new(cu_limit: u32) -> Self {
        Self {
            cu_limit,
            cu_price_micro_lamports: None,
        }
    }

    #[must_use]
    pub const fn with_compute_unit_price(mut self, micro_lamports: u64) -> Self {
        self.cu_price_micro_lamports = Some(micro_lamports);
        self
    }

    pub fn transaction_config(&self) -> v1::TransactionConfig {
        let config = v1::TransactionConfig::empty()
            .with_compute_unit_limit(self.cu_limit)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE);
        match self.cu_price_micro_lamports {
            Some(price) => config.with_priority_fee(priority_fee_lamports(price, self.cu_limit)),
            None => config,
        }
    }
}

/// The lamport priority fee a compute-unit price buys.
///
/// Both formats charge the same thing in different units: the runtime turned a
/// legacy `set_compute_unit_price` bid into `ceil(price * cu_limit / 1_000_000)`
/// lamports (`solana_compute_budget::compute_budget_limits::get_prioritization_fee`)
/// and charges a v1 header's `priority_fee` as lamports directly, so converting
/// with that same formula bills a caller exactly what the instruction did.
fn priority_fee_lamports(cu_price_micro_lamports: u64, cu_limit: u32) -> u64 {
    u128::from(cu_price_micro_lamports)
        .saturating_mul(u128::from(cu_limit))
        .saturating_add(MICRO_LAMPORTS_PER_LAMPORT.saturating_sub(1))
        .checked_div(MICRO_LAMPORTS_PER_LAMPORT)
        .and_then(|fee| u64::try_from(fee).ok())
        .unwrap_or(u64::MAX)
}

/// Compile `instructions` into an unsigned v1 message.
///
/// v1 takes no compute-budget instructions, which is where the ceilings in
/// `compute_budget` would otherwise go, and it has no address lookup tables.
pub fn compile_v1_message(
    payer: &Address,
    instructions: &[Instruction],
    recent_blockhash: Hash,
    compute_budget: ComputeBudgetConfig,
) -> Result<VersionedMessage, ClientError> {
    v1::Message::try_compile_with_config(
        payer,
        instructions,
        recent_blockhash,
        compute_budget.transaction_config(),
    )
    .map(VersionedMessage::V1)
    .map_err(|error| ClientError::TransactionCompile(error.to_string()))
}

/// Sign a compiled message, passing each signer once.
///
/// `VersionedTransaction::try_new` refuses a signer list longer than the
/// message's required signatures, and a fee payer that also owns a shielded
/// input is one account key but two entries in the caller's list.
pub fn sign_versioned_transaction(
    message: VersionedMessage,
    signers: &[&dyn Signer],
) -> Result<VersionedTransaction, ClientError> {
    let mut unique: Vec<(Pubkey, &dyn Signer)> = Vec::with_capacity(signers.len());
    for signer in signers {
        let pubkey = signer
            .try_pubkey()
            .map_err(|error| ClientError::SolanaTransactionSigning(error.to_string()))?;
        if unique.iter().any(|(kept, _)| *kept == pubkey) {
            continue;
        }
        unique.push((pubkey, *signer));
    }
    let unique = unique
        .into_iter()
        .map(|(_, signer)| signer)
        .collect::<Vec<_>>();
    VersionedTransaction::try_new(message, &unique)
        .map_err(|error| ClientError::SolanaTransactionSigning(error.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub block_time: i64,
    /// Highest slot the indexer has persisted.
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
    pub scanned_through: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetShieldedTransactionsByTagsResponse {
    pub context: Context,
    pub transactions: Vec<ShieldedTransaction>,
    pub next_cursor: Option<Vec<u8>>,
    pub scanned_through: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedShieldedTransaction {
    pub event_index: u16,
    pub transaction: ShieldedTransaction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetShieldedTransactionsBySignatureResponse {
    pub context: Context,
    pub transactions: Vec<IndexedShieldedTransaction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetShieldedTransactionsByNullifiersResponse {
    pub context: Context,
    pub transactions: Vec<ShieldedTransaction>,
    pub next_cursor: Option<Vec<u8>>,
    /// Where the indexer's scan reached. Set only on a page the limit did not
    /// truncate. Unspent nullifiers match nothing, so `next_cursor` is `None`
    /// for them and this is the only resume point.
    pub scanned_through: Option<Vec<u8>>,
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
    /// Completed Solana slot for ordering and freshness of a state-tree proof.
    pub root_seq: u64,
    /// Actual on-chain cyclic-history position for `root`; it is not derived
    /// from `root_seq` because slots without a tree update consume no entry.
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
    /// On-chain indexed-tree update sequence.
    pub root_seq: u64,
    /// On-chain root-history position for `root`.
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
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        let (blockhash, _) = self.get_latest_blockhash()?;
        let payer = Pubkey::new_from_array(payer.to_bytes());
        let message = Message::new(instructions, Some(&payer));
        let transaction = Transaction::new(signers, message, blockhash);
        self.send_transaction(&transaction)
    }

    /// Build, sign, and send a v1 transaction: the format every proof-carrying
    /// shielded-pool transaction uses, because it lifts the 1,232-byte legacy
    /// packet ceiling to 4,096 bytes.
    fn create_and_send_v1_transaction(
        &self,
        instructions: &[Instruction],
        payer: Address,
        signers: &[&dyn Signer],
        compute_budget: ComputeBudgetConfig,
    ) -> Result<Signature, ClientError> {
        let (blockhash, _) = self.get_latest_blockhash()?;
        let message = compile_v1_message(&payer, instructions, blockhash, compute_budget)?;
        self.process_versioned_transaction(sign_versioned_transaction(message, signers)?)
    }

    fn create_and_send_versioned_transaction(
        &self,
        instructions: &[Instruction],
        payer: Address,
        signers: &[&dyn Signer],
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

    /// Whether `error` is transient for the post-submission confirmation poll
    /// (`wait_for_indexed_transaction`). Indexer data-plane polling
    /// (`IndexerPollConfig::poll_until`, the merkle-proof retry loop) deliberately
    /// retries every error and does not consult this.
    fn should_retry(&self, error: &ClientError) -> bool {
        false
    }

    // ===== Indexer (SPP) =====

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Err(unsupported("get_encrypted_utxos_by_tags"))
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_tags"))
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_signature"))
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_nullifiers"))
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
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        Err(unsupported("get_merkle_proofs"))
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        Err(unsupported("get_non_inclusion_proofs"))
    }

    /// Resolve the state-inclusion and nullifier-non-inclusion proofs for each
    /// input UTXO commitment, returned in the same order as the commitments. The
    /// commitments determine the tree; each returned proof names it in its merkle
    /// context.
    fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputUtxoContext],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        Err(unsupported("get_input_merkle_proofs"))
    }

    /// Resolve input proofs against an explicitly selected tree. Implementations
    /// that resolve the tree from their own indexed commitment context may use
    /// the default; tree-configured clients override this for cross-tree spends.
    fn get_input_merkle_proofs_for_tree(
        &self,
        input_tree: Address,
        input_utxo_commitments: &[InputUtxoContext],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        let _ = input_tree;
        self.get_input_merkle_proofs(input_utxo_commitments, config)
    }

    // ===== Proving =====

    /// Build the SPP proof for a signed transaction (server-side proving).
    fn prove(&self, proof_inputs: SppProofInputs) -> Result<ProveResult, ClientError> {
        Err(unsupported("prove"))
    }

    fn send_and_prove(&self, proof_inputs: SppProofInputs) -> Result<Signature, ClientError> {
        Err(unsupported("send_and_prove"))
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

    /// Whether `error` is transient for the post-submission confirmation poll
    /// (`wait_for_indexed_transaction_async`). Indexer data-plane polling
    /// (`IndexerPollConfig::poll_until`) deliberately retries every error and does
    /// not consult this.
    fn should_retry(&self, error: &ClientError) -> bool {
        false
    }

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Err(unsupported("get_encrypted_utxos_by_tags"))
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_tags"))
    }

    async fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_signature"))
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_nullifiers"))
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
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        Err(unsupported("get_merkle_proofs"))
    }

    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        Err(unsupported("get_non_inclusion_proofs"))
    }

    async fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputUtxoContext],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        Err(unsupported("get_input_merkle_proofs"))
    }

    async fn get_input_merkle_proofs_for_tree(
        &self,
        input_tree: Address,
        input_utxo_commitments: &[InputUtxoContext],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        let _ = input_tree;
        self.get_input_merkle_proofs(input_utxo_commitments, config)
            .await
    }

    async fn prove(&self, proof_inputs: SppProofInputs) -> Result<ProveResult, ClientError> {
        Err(unsupported("prove"))
    }
}

fn unsupported(method: &'static str) -> ClientError {
    ClientError::UnsupportedRpcMethod(method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compute_unit_price_converts_to_the_lamport_fee_the_runtime_charged() {
        // The three cases `get_prioritization_fee` pins: a sub-lamport fee
        // rounds up to one, an exact lamport stays one, and a hair over one
        // lamport rounds up to two.
        assert_eq!(priority_fee_lamports(999_999, 1), 1);
        assert_eq!(priority_fee_lamports(1_000_000, 1), 1);
        assert_eq!(priority_fee_lamports(1_000_001, 1), 2);
        assert_eq!(priority_fee_lamports(25_000, 450_000), 11_250);
        assert_eq!(priority_fee_lamports(u64::MAX, u32::MAX), u64::MAX);
    }

    #[test]
    fn a_transaction_config_always_states_both_ceilings() {
        let without_priority = ComputeBudgetConfig::new(450_000).transaction_config();
        assert_eq!(
            without_priority,
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(450_000)
                .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE)
        );

        let with_priority = ComputeBudgetConfig::new(450_000)
            .with_compute_unit_price(25_000)
            .transaction_config();
        assert_eq!(
            with_priority,
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(450_000)
                .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE)
                .with_priority_fee(11_250)
        );
    }
}
