//! Combined client bundling the Solana RPC, indexer, and prover connections a
//! wallet needs. Requires both the `indexer-api` and `solana-rpc` features.
//!
//! The client is the *where* (connections and the state tree), not the *who*:
//! the fee payer stays a caller-owned [`Signer`] passed to each action.

use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_pubkey::{pubkey, Pubkey};
use solana_signature::Signature;
use solana_transaction::Transaction;
use zolana_transaction::instructions::{transact::SignedTransaction, types::InputCommitment};

use solana_signer::Signer;

use crate::{
    actions::{
        submit::{fetch_spend_proofs, prove_transact},
        Submit,
    },
    error::ClientError,
    indexer::{indexer_url, ZolanaIndexer, DEVNET_INDEXER_URL},
    prover::{server_address, transact::witness::SpendProof, ProverClient, DEVNET_SERVER_ADDRESS},
    rpc::{
        GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse, GetNonInclusionProofsResponse,
        GetShieldedTransactionsByTagsResponse, ProveResult, Rpc, ShieldedTransactionStream,
    },
    solana_rpc::{rpc_url, SolanaRpc, HELIUS_DEVNET_RPC_URL},
};

/// The protocol's state-tree account. One fixed address, created from the same
/// keypair on localnet and devnet, so the presets fill it in. Verified for
/// localnet and devnet only; on other networks set [`ZolanaClientConfig::tree`]
/// to the deployed tree.
pub const DEFAULT_TREE: Pubkey = pubkey!("treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8");

/// Endpoints for [`ZolanaClient`]. To use an API key, embed it in the URL:
/// `https://...?api-key=YOUR_KEY`.
pub struct ZolanaClientConfig {
    pub rpc_url: String,
    pub indexer_url: String,
    pub prover_url: String,
    /// State tree private transactions write to; the presets fill
    /// [`DEFAULT_TREE`].
    pub tree: Pubkey,
    /// Commitment level for every read and send; `None` means `confirmed`.
    pub commitment: Option<CommitmentConfig>,
}

impl ZolanaClientConfig {
    /// Local defaults, honoring the per-clone `ZOLANA_LOCALNET_URL` /
    /// `ZOLANA_INDEXER_URL` / `ZOLANA_PROVER_URL` overrides.
    pub fn local() -> Self {
        Self {
            rpc_url: rpc_url(),
            indexer_url: indexer_url(),
            prover_url: server_address(),
            tree: DEFAULT_TREE,
            commitment: None,
        }
    }

    /// Shared devnet endpoints, with the Helius RPC keyed by the caller's API
    /// key. The key is embedded in the RPC URL and never read from env or
    /// stored elsewhere. No env overrides: those exist for local port
    /// contention only; set custom URLs on the struct fields instead.
    pub fn devnet(api_key: &str) -> Self {
        Self {
            rpc_url: format!("{HELIUS_DEVNET_RPC_URL}/?api-key={api_key}"),
            indexer_url: DEVNET_INDEXER_URL.to_string(),
            prover_url: DEVNET_SERVER_ADDRESS.to_string(),
            tree: DEFAULT_TREE,
            commitment: None,
        }
    }
}

/// One handle for every connection a wallet needs. The fee payer is not part
/// of the client; every action takes it as an explicit [`Signer`] argument.
///
/// Implements [`Rpc`] end to end: account and transaction methods answer from
/// the Solana RPC, the indexer queries answer from the indexer, and
/// [`Rpc::prove`] runs the client-side proving pipeline against the prover
/// server.
///
/// [`Signer`]: solana_signer::Signer
///
/// # Examples
///
/// ```no_run
/// use zolana_client::{Rpc, ZolanaClient};
///
/// let client = ZolanaClient::devnet("YOUR_API_KEY");
/// client.rpc().assert_executable(&solana_pubkey::Pubkey::new_unique())?;
/// # Ok::<(), zolana_client::ClientError>(())
/// ```
pub struct ZolanaClient {
    rpc: SolanaRpc,
    indexer: ZolanaIndexer,
    prover: ProverClient,
    tree: Pubkey,
}

impl ZolanaClient {
    pub fn new(config: ZolanaClientConfig) -> Self {
        let commitment = config
            .commitment
            .unwrap_or_else(CommitmentConfig::confirmed);
        Self {
            rpc: SolanaRpc::new_with_commitment(config.rpc_url, commitment),
            indexer: ZolanaIndexer::new(config.indexer_url),
            prover: ProverClient::new(config.prover_url),
            tree: config.tree,
        }
    }

    pub fn local() -> Self {
        Self::new(ZolanaClientConfig::local())
    }

    pub fn devnet(api_key: &str) -> Self {
        Self::new(ZolanaClientConfig::devnet(api_key))
    }

    pub fn rpc(&self) -> &SolanaRpc {
        &self.rpc
    }

    /// Some RPC operations mutate client state (e.g. [`SolanaRpc::airdrop`]).
    pub fn rpc_mut(&mut self) -> &mut SolanaRpc {
        &mut self.rpc
    }

    pub fn indexer(&self) -> &ZolanaIndexer {
        &self.indexer
    }

    pub fn prover(&self) -> &ProverClient {
        &self.prover
    }

    /// State tree private transactions write to.
    pub fn tree(&self) -> Pubkey {
        self.tree
    }

    /// A [`Submit`] wired to this client's connections and tree; only the fee
    /// payer stays caller-owned. Call [`Submit::execute`] on the result, or
    /// override `cu_limit` first.
    pub fn submit<'a>(&'a self, payer: &'a dyn Signer) -> Submit<'a, Self, Self> {
        Submit {
            indexer: self,
            rpc: self,
            prover: &self.prover,
            payer,
            tree: self.tree,
            cu_limit: None,
        }
    }
}

impl Rpc for ZolanaClient {
    // ===== Accounts and transactions (Solana RPC) =====

    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.rpc.get_account(address)
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        self.rpc.get_program_accounts(program_id)
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        self.rpc.get_minimum_balance_for_rent_exemption(data_len)
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        self.rpc.get_latest_blockhash()
    }

    fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
        self.rpc.send_transaction(transaction)
    }

    // ===== Indexer (SPP) =====

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.indexer
            .get_encrypted_utxos_by_tags(tags, cursor, limit)
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.indexer
            .get_shielded_transactions_by_tags(tags, cursor, limit)
    }

    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        self.indexer
            .subscribe_to_shielded_transactions_by_tags(tags)
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.indexer.get_merkle_proofs(tree_account, leaves)
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.indexer.get_non_inclusion_proofs(tree_account, leaves)
    }

    fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputCommitment],
    ) -> Result<Vec<SpendProof>, ClientError> {
        let tree = Address::new_from_array(self.tree.to_bytes());
        fetch_spend_proofs(&self.indexer, tree, input_utxo_commitments)
    }

    // ===== Proving (client-side) =====

    /// Prove a signed transaction client-side: fetch the input proofs from the
    /// indexer, assemble the witness, and prove on the matching rail via the
    /// prover server.
    fn prove(&self, transaction: SignedTransaction) -> Result<ProveResult, ClientError> {
        let commitments = transaction.input_commitments()?;
        let spend_proofs = self.get_input_merkle_proofs(&commitments)?;
        let proven = prove_transact(&self.prover, transaction, &spend_proofs)?;
        Ok(ProveResult {
            proof: proven.proof,
            public_inputs: vec![proven.public_input_hash],
            circuit_id: proven.circuit_id,
        })
    }

    /// Not available client-side: sending needs a fee-payer signature and the
    /// client holds no signer. Call [`Rpc::prove`], build the `Transact`
    /// instruction, and send it with the caller's payer — or use
    /// [`crate::Submit`].
    fn send_and_prove(&self, _transaction: SignedTransaction) -> Result<Signature, ClientError> {
        Err(ClientError::Rpc(
            "send_and_prove needs a fee payer and the client holds no signer; \
             use prove() and send the Transact instruction with your own payer, or use Submit"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The env-reading `local()` path is deliberately untested: env is
    // process-inherited (the justfile exports ZOLANA_PROVER_URL into test
    // runs), so asserting resolved local URLs would be environment-dependent.
    const KEYED_DEVNET_RPC_URL: &str = "https://devnet.helius-rpc.com/?api-key=test-key";

    #[test]
    fn devnet_config_uses_devnet_endpoints() {
        let config = ZolanaClientConfig::devnet("test-key");
        assert_eq!(config.rpc_url, KEYED_DEVNET_RPC_URL);
        assert_eq!(config.indexer_url, DEVNET_INDEXER_URL);
        assert_eq!(config.prover_url, DEVNET_SERVER_ADDRESS);
    }

    #[test]
    fn devnet_preset_wires_devnet_endpoints() {
        let client = ZolanaClient::devnet("test-key");
        assert_eq!(client.rpc().client().url(), KEYED_DEVNET_RPC_URL);
        assert_eq!(client.indexer().api().base_path(), DEVNET_INDEXER_URL);
        assert_eq!(client.prover().server_address(), DEVNET_SERVER_ADDRESS);
    }

    #[test]
    fn new_wires_all_connections() {
        let tree = Pubkey::new_unique();
        let client = ZolanaClient::new(ZolanaClientConfig {
            rpc_url: "http://127.0.0.1:9899".to_string(),
            indexer_url: "http://127.0.0.1:9784".to_string(),
            prover_url: "http://127.0.0.1:9001".to_string(),
            tree,
            commitment: Some(CommitmentConfig::processed()),
        });
        assert_eq!(client.rpc().client().url(), "http://127.0.0.1:9899");
        assert_eq!(client.indexer().api().base_path(), "http://127.0.0.1:9784");
        assert_eq!(client.prover().server_address(), "http://127.0.0.1:9001");
        assert_eq!(client.tree(), tree);
        assert_eq!(
            client.rpc().client().commitment(),
            CommitmentConfig::processed()
        );
    }

    #[test]
    fn submit_carries_client_tree_and_default_cu_limit() {
        let tree = Pubkey::new_unique();
        let client = ZolanaClient::new(ZolanaClientConfig {
            rpc_url: "http://127.0.0.1:9899".to_string(),
            indexer_url: "http://127.0.0.1:9784".to_string(),
            prover_url: "http://127.0.0.1:9001".to_string(),
            tree,
            commitment: None,
        });
        let payer = solana_keypair::Keypair::new();
        let submit = client.submit(&payer);
        assert_eq!(submit.tree, tree);
        assert_eq!(submit.cu_limit, None);
        assert_eq!(
            submit.prover.server_address(),
            client.prover().server_address()
        );
    }

    #[test]
    fn presets_fill_default_tree_and_confirmed_commitment() {
        let client = ZolanaClient::devnet("test-key");
        assert_eq!(client.tree(), DEFAULT_TREE);
        assert_eq!(
            client.rpc().client().commitment(),
            CommitmentConfig::confirmed()
        );
    }
}
