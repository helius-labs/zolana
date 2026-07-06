//! Combined client bundling the Solana RPC, indexer, and prover connections a
//! wallet needs, plus the fee payer. Requires both the `indexer-api` and
//! `solana-rpc` features.

use solana_keypair::Keypair;

use crate::{
    indexer::{indexer_url, ZolanaIndexer, DEVNET_INDEXER_URL},
    prover::{server_address, ProverClient, DEVNET_SERVER_ADDRESS},
    solana_rpc::{rpc_url, SolanaRpc, HELIUS_DEVNET_RPC_URL},
};

/// Endpoints and fee payer for [`ZolanaClient`]. The payer is always supplied
/// by the caller: the SDK never generates keypairs or loads them from disk
/// (devnet has no faucet). To use an API key, embed it in the URL:
/// `https://...?api-key=YOUR_KEY`.
pub struct ZolanaClientConfig {
    pub rpc_url: String,
    pub indexer_url: String,
    pub prover_url: String,
    pub payer: Keypair,
}

impl ZolanaClientConfig {
    /// Local defaults, honoring the per-clone `ZOLANA_LOCALNET_URL` /
    /// `ZOLANA_INDEXER_URL` / `ZOLANA_PROVER_URL` overrides.
    pub fn local(payer: Keypair) -> Self {
        Self {
            rpc_url: rpc_url(),
            indexer_url: indexer_url(),
            prover_url: server_address(),
            payer,
        }
    }

    /// Shared devnet endpoints, with the Helius RPC keyed by the caller's API
    /// key. The key is embedded in the RPC URL and never read from env or
    /// stored elsewhere. No env overrides: those exist for local port
    /// contention only; set custom URLs on the struct fields instead.
    pub fn devnet(payer: Keypair, api_key: &str) -> Self {
        Self {
            rpc_url: format!("{HELIUS_DEVNET_RPC_URL}/?api-key={api_key}"),
            indexer_url: DEVNET_INDEXER_URL.to_string(),
            prover_url: DEVNET_SERVER_ADDRESS.to_string(),
            payer,
        }
    }
}

/// One handle for every connection a wallet needs.
///
/// # Examples
///
/// ```no_run
/// use solana_keypair::Keypair;
/// use zolana_client::ZolanaClient;
///
/// let payer: Keypair = /* your funded keypair */
/// # Keypair::new();
/// let mut client = ZolanaClient::devnet(payer, "YOUR_API_KEY");
/// let (rpc, indexer, prover, payer) = client.parts();
/// rpc.assert_executable(&solana_pubkey::Pubkey::new_unique())?;
/// # Ok::<(), zolana_client::ClientError>(())
/// ```
pub struct ZolanaClient {
    rpc: SolanaRpc,
    indexer: ZolanaIndexer,
    prover: ProverClient,
    payer: Keypair,
}

impl ZolanaClient {
    pub fn new(config: ZolanaClientConfig) -> Self {
        Self {
            rpc: SolanaRpc::new(config.rpc_url),
            indexer: ZolanaIndexer::new(config.indexer_url),
            prover: ProverClient::new(config.prover_url),
            payer: config.payer,
        }
    }

    pub fn local(payer: Keypair) -> Self {
        Self::new(ZolanaClientConfig::local(payer))
    }

    pub fn devnet(payer: Keypair, api_key: &str) -> Self {
        Self::new(ZolanaClientConfig::devnet(payer, api_key))
    }

    /// Borrow every connection and the payer at once, as disjoint fields, so
    /// a `&mut` RPC call can take the payer in the same expression.
    pub fn parts(&mut self) -> (&mut SolanaRpc, &ZolanaIndexer, &ProverClient, &Keypair) {
        (&mut self.rpc, &self.indexer, &self.prover, &self.payer)
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

    pub fn payer(&self) -> &Keypair {
        &self.payer
    }
}

#[cfg(test)]
mod tests {
    use solana_signer::Signer;

    use super::*;

    // The env-reading `local()` path is deliberately untested: env is
    // process-inherited (the justfile exports ZOLANA_PROVER_URL into test
    // runs), so asserting resolved local URLs would be environment-dependent.
    const KEYED_DEVNET_RPC_URL: &str = "https://devnet.helius-rpc.com/?api-key=test-key";

    #[test]
    fn devnet_config_uses_devnet_endpoints() {
        let config = ZolanaClientConfig::devnet(Keypair::new(), "test-key");
        assert_eq!(config.rpc_url, KEYED_DEVNET_RPC_URL);
        assert_eq!(config.indexer_url, DEVNET_INDEXER_URL);
        assert_eq!(config.prover_url, DEVNET_SERVER_ADDRESS);
    }

    #[test]
    fn devnet_preset_wires_devnet_endpoints() {
        let client = ZolanaClient::devnet(Keypair::new(), "test-key");
        assert_eq!(client.rpc().client().url(), KEYED_DEVNET_RPC_URL);
        assert_eq!(client.indexer().api().base_path(), DEVNET_INDEXER_URL);
        assert_eq!(client.prover().server_address(), DEVNET_SERVER_ADDRESS);
    }

    // Compiling is the point: `&mut rpc` and `&payer` from one call must not
    // conflict, which the single accessors (rpc_mut + payer) cannot express.
    #[test]
    fn parts_returns_disjoint_borrows() {
        let payer = Keypair::new();
        let payer_pubkey = payer.pubkey();
        let mut client = ZolanaClient::devnet(payer, "test-key");
        let (rpc, indexer, prover, payer) = client.parts();
        assert_eq!(payer.pubkey(), payer_pubkey);
        assert_eq!(rpc.client().url(), KEYED_DEVNET_RPC_URL);
        assert_eq!(indexer.api().base_path(), DEVNET_INDEXER_URL);
        assert_eq!(prover.server_address(), DEVNET_SERVER_ADDRESS);
    }

    #[test]
    fn new_wires_all_connections_and_payer() {
        let payer = Keypair::new();
        let payer_pubkey = payer.pubkey();
        let client = ZolanaClient::new(ZolanaClientConfig {
            rpc_url: "http://127.0.0.1:9899".to_string(),
            indexer_url: "http://127.0.0.1:9784".to_string(),
            prover_url: "http://127.0.0.1:9001".to_string(),
            payer,
        });
        assert_eq!(client.rpc().client().url(), "http://127.0.0.1:9899");
        assert_eq!(client.indexer().api().base_path(), "http://127.0.0.1:9784");
        assert_eq!(client.prover().server_address(), "http://127.0.0.1:9001");
        assert_eq!(client.payer().pubkey(), payer_pubkey);
    }
}
