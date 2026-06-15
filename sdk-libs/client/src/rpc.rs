use std::pin::Pin;

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

use crate::error::ClientError;
use crate::private_transaction::{InputCommitment, SignedTransaction, SpendProof};
use crate::prover::ProofCompressed;

pub const STATE_TREE_HEIGHT: usize = 26;
pub const NULLIFIER_TREE_HEIGHT: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateInclusionProof {
    pub path_elements: [[u8; 32]; STATE_TREE_HEIGHT],
    pub leaf_index: u64,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierNonInclusionProof {
    pub low_value: [u8; 32],
    pub next_value: [u8; 32],
    pub low_path_elements: [[u8; 32]; NULLIFIER_TREE_HEIGHT],
    pub low_leaf_index: u64,
    pub root: [u8; 32],
}

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
    pub view_tag: [u8; 32],
    /// `None` when the payload is plaintext (nothing to decrypt).
    pub tx_viewing_pk: Option<P256Pubkey>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetEncryptedUtxosByTagsResponse {
    pub context: Context,
    pub matches: Vec<EncryptedUtxoMatch>,
    pub next_cursor: Option<Vec<u8>>,
}

/// One output of a shielded transaction: its view tag and encrypted/plaintext payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSlot {
    pub view_tag: [u8; 32],
    pub payload: Vec<u8>,
}

/// A shielded transaction with every output slot in UTXO-tree-append order and the
/// nullifiers it consumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedTransaction {
    pub slot: u64,
    pub tx_signature: Signature,
    /// `None` when there is nothing to decrypt (proofless or plaintext transfer).
    pub tx_viewing_pk: Option<P256Pubkey>,
    pub output_slots: Vec<OutputSlot>,
    pub nullifiers: Vec<[u8; 32]>,
    pub proofless: bool,
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
///
/// Every method defaults to `unimplemented!()`; implementors override the subset
/// they support.
#[allow(unused_variables)]
pub trait Rpc {
    // ===== Accounts =====

    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        unimplemented!()
    }

    fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        unimplemented!()
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        unimplemented!()
    }

    // ===== Chain state =====

    fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        unimplemented!()
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        unimplemented!()
    }

    fn get_block_height(&self) -> Result<u64, ClientError> {
        unimplemented!()
    }

    fn get_slot(&self) -> Result<u64, ClientError> {
        unimplemented!()
    }

    fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        unimplemented!()
    }

    fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        unimplemented!()
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        unimplemented!()
    }

    fn health(&self) -> Result<(), ClientError> {
        unimplemented!()
    }

    // ===== Transactions =====

    fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
        unimplemented!()
    }

    fn send_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        unimplemented!()
    }

    fn send_versioned_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        unimplemented!()
    }

    fn process_transaction(&self, transaction: Transaction) -> Result<Signature, ClientError> {
        unimplemented!()
    }

    fn process_transaction_with_context(
        &self,
        transaction: Transaction,
    ) -> Result<(Signature, Slot), ClientError> {
        unimplemented!()
    }

    fn process_versioned_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        unimplemented!()
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
        unimplemented!()
    }

    // ===== Misc =====

    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        unimplemented!()
    }

    fn should_retry(&self, error: &ClientError) -> bool {
        unimplemented!()
    }

    // ===== Indexer (SPP) =====

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        unimplemented!()
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        unimplemented!()
    }

    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        unimplemented!()
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        unimplemented!()
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        unimplemented!()
    }

    /// Resolve the state-inclusion and nullifier-non-inclusion proofs for each
    /// input UTXO commitment, returned in the same order as the commitments.
    fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputCommitment],
    ) -> Result<Vec<SpendProof>, ClientError> {
        unimplemented!()
    }

    // ===== Proving =====

    /// Build the SPP proof for a signed transaction (server-side proving).
    fn prove(&self, transaction: SignedTransaction) -> Result<ProveResult, ClientError> {
        unimplemented!()
    }

    /// Build the SPP proof and submit the resulting transaction in one call.
    fn send_and_prove(&self, transaction: SignedTransaction) -> Result<Signature, ClientError> {
        unimplemented!()
    }
}
