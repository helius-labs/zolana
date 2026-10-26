//! A [`ZolanaClient`] over the litesvm harness.
//!
//! The harness is both halves of that client: transactions run in litesvm
//! through its [`Rpc`], and the proofs and transactions the client reads come
//! from the [`TestIndexer`](crate::TestIndexer) the harness feeds with every
//! event it sends. Nothing is served over HTTP, so a client's whole flow, from
//! proving to confirmation, runs in one process.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_hash::Hash;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use zolana_client::{
    rpc::{
        Context, GetMerkleProofsResponse, GetNonInclusionProofsResponse,
        GetShieldedTransactionsBySignatureResponse, IndexedShieldedTransaction, IndexerRpcConfig,
        MerkleContext, MerkleProof, NonInclusionProof,
    },
    ClientError, ProverClient, Rpc, RpcSendTransactionConfig, WitnessReader, ZolanaClient,
};
use zolana_tree::TreeAccount;

use crate::{indexer::LeafProof, transaction_trace::TransactionOutcome, ZolanaProgramTest};

/// `tree_type` of a state-tree proof, as Photon reports it.
const STATE_TREE_TYPE: u16 = 1;
/// `tree_type` of a nullifier-tree proof, as Photon reports it.
const NULLIFIER_TREE_TYPE: u16 = 2;

/// The harness, shared by a client's RPC and indexer halves. Clones share one
/// harness; [`Self::lock`] reaches it for anything the client does not do.
#[derive(Clone)]
pub struct ProgramTestHandle(Arc<Mutex<ZolanaProgramTest>>);

impl ZolanaProgramTest {
    pub fn into_handle(self) -> ProgramTestHandle {
        ProgramTestHandle(Arc::new(Mutex::new(self)))
    }

    /// A client whose RPC and indexer are this harness, proving through
    /// `prover`. [`ZolanaClient::with_prover`] over two clones of
    /// [`Self::into_handle`] gives one with a custom prover.
    pub fn into_client(
        self,
        prover: ProverClient,
    ) -> ZolanaClient<ProgramTestHandle, ProgramTestHandle> {
        let handle = self.into_handle();
        ZolanaClient::new(handle.clone(), handle, prover)
    }
}

impl ProgramTestHandle {
    pub fn lock(&self) -> MutexGuard<'_, ZolanaProgramTest> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn send(&self, transaction: VersionedTransaction) -> Result<Signature, ClientError> {
        self.lock()
            .send_indexed(transaction)
            .map(|indexed| indexed.signature)
            .map_err(|error| ClientError::Rpc(error.to_string()))
    }
}

impl WitnessReader for ProgramTestHandle {}

impl Rpc for ProgramTestHandle {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Rpc::get_account(&*self.lock(), address)
    }

    fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        let harness = self.lock();
        addresses
            .into_iter()
            .map(|address| Rpc::get_account(&*harness, address))
            .collect()
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        Rpc::get_program_accounts(&*self.lock(), program_id)
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        Rpc::get_minimum_balance_for_rent_exemption(&*self.lock(), data_len)
    }

    fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        Ok(self.lock().svm.get_balance(&address).unwrap_or(0))
    }

    /// A fresh blockhash each time: a client fetches one per message it
    /// builds, and litesvm would otherwise deduplicate a second transaction
    /// signed over the blockhash of the first.
    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        let mut harness = self.lock();
        harness.svm.expire_blockhash();
        let slot = harness.svm.get_sysvar::<Clock>().slot;
        Ok((harness.svm.latest_blockhash(), slot))
    }

    fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        _config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.send(transaction.clone())
    }

    fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        self.send(transaction)
    }

    /// litesvm runs a transaction as it is sent, so one the harness accepted
    /// is confirmed.
    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        Ok(self.lock().transaction_traces().iter().any(|trace| {
            trace.signature == signature && trace.outcome == TransactionOutcome::Succeeded
        }))
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        let harness = self.lock();
        let transactions = harness
            .indexer()
            .transactions()
            .iter()
            .filter(|transaction| transaction.tx_signature == signature)
            .cloned()
            .enumerate()
            .map(|(event_index, transaction)| IndexedShieldedTransaction {
                event_index: event_index as u16,
                transaction,
            })
            .collect();
        Ok(GetShieldedTransactionsBySignatureResponse {
            context: context(&harness),
            output_tree_id: None,
            transactions,
        })
    }

    /// Each proof is bound to the root the tree account holds now, at its
    /// current history index. A reference root the chain does not hold is
    /// an error here, not a proof the program would reject.
    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        let harness = self.lock();
        let mut tree = tree_account_of(&harness, tree_account)?;
        let root_index = tree.utxo_tree().current_root_index();
        let chain_root = tree
            .get_utxo_tree_root(root_index)
            .map_err(|error| ClientError::Rpc(format!("tree {tree_account}: {error:?}")))?;
        let proofs = leaves
            .iter()
            .map(|leaf| -> Result<MerkleProof, ClientError> {
                let LeafProof {
                    leaf_index,
                    path,
                    root,
                } = harness
                    .indexer()
                    .merkle_proof(&tree_account, leaf)
                    .map_err(|error| ClientError::Rpc(error.to_string()))?;
                if root != chain_root {
                    return Err(ClientError::Rpc(format!(
                        "test indexer root of tree {tree_account} is not the chain's"
                    )));
                }
                Ok(MerkleProof {
                    leaf: *leaf,
                    merkle_context: MerkleContext {
                        tree_type: STATE_TREE_TYPE,
                        tree: tree_account,
                    },
                    path,
                    leaf_index,
                    root,
                    root_seq: u64::from(root_index),
                    root_index,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GetMerkleProofsResponse {
            context: context(&harness),
            proofs,
        })
    }

    /// The root index is the history position of the reference root, found
    /// by reading the account's root history: the nullifier tree keeps no
    /// current index, and a reference root the history does not hold means a
    /// forester batch the test indexer did not see.
    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        let harness = self.lock();
        let tree = tree_account_of(&harness, tree_account)?;
        let proofs = leaves
            .iter()
            .map(|nullifier| -> Result<NonInclusionProof, ClientError> {
                let proof = harness
                    .indexer()
                    .non_inclusion_proof(nullifier)
                    .map_err(|error| ClientError::Rpc(error.to_string()))?;
                let root_index = (0..=u16::MAX)
                    .map_while(|index| {
                        tree.get_nullifier_tree_root(index)
                            .ok()
                            .map(|root| (index, root))
                    })
                    .find_map(|(index, root)| (root == proof.root).then_some(index))
                    .ok_or_else(|| {
                        ClientError::Rpc(format!(
                            "test indexer nullifier root is not in tree {tree_account}'s history"
                        ))
                    })?;
                Ok(NonInclusionProof {
                    leaf: *nullifier,
                    merkle_context: MerkleContext {
                        tree_type: NULLIFIER_TREE_TYPE,
                        tree: tree_account,
                    },
                    path: proof.merkle_proof,
                    low_element: proof.leaf_lower_range_value,
                    low_element_index: proof.leaf_index as u64,
                    high_element: proof.leaf_higher_range_value,
                    high_element_index: proof.next_index as u64,
                    root: proof.root,
                    root_seq: u64::from(root_index),
                    root_index,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GetNonInclusionProofsResponse {
            context: context(&harness),
            proofs,
        })
    }
}

fn context(harness: &ZolanaProgramTest) -> Context {
    let clock = harness.svm.get_sysvar::<Clock>();
    Context {
        block_time: clock.unix_timestamp,
        slot: clock.slot,
    }
}

/// The tree account's bytes, loaded as a tree. A copy: the account is read,
/// never written through this.
fn tree_account_of(
    harness: &ZolanaProgramTest,
    tree: Address,
) -> Result<TreeAccount<'static>, ClientError> {
    let data = harness
        .account_data(&tree)
        .ok_or_else(|| ClientError::Rpc(format!("tree account {tree} not found")))?;
    TreeAccount::from_bytes(Box::leak(data.into_boxed_slice()), tree.to_bytes())
        .map_err(|error| ClientError::Rpc(format!("tree {tree}: {error:?}")))
}
