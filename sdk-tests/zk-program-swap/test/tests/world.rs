use std::collections::BTreeMap;

use anyhow::Result;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::{
    instruction::CreateProtocolConfig, pda, state::tree_account_size, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_test_utils::smart_account::{self, execute_sync_ix, StandardSigners};
use zolana_transaction::AssetRegistry;

use crate::{
    actor::Actor,
    localnet::{
        restart_localnet, send_transaction, start_prover, DEFAULT_INDEXER_URL, DEFAULT_RPC_URL,
    },
};

#[derive(cucumber::World)]
#[world(init = Self::new)]
pub struct SwapWorld {
    pub(crate) rpc: SolanaRpc,
    pub(crate) indexer: ZolanaIndexer,
    pub(crate) assets: AssetRegistry,
    pub(crate) payer: Keypair,
    pub(crate) tree: Pubkey,
    pub(crate) tree_address: Address,
    pub(crate) actors: BTreeMap<String, Actor>,
    pub(crate) open_orders: Vec<crate::steps::create::OpenOrder>,
}

impl std::fmt::Debug for SwapWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SwapWorld")
    }
}

impl SwapWorld {
    async fn new() -> Result<Self> {
        let prover = std::thread::spawn(start_prover);
        restart_localnet();
        prover.join().expect("prover startup thread panicked")?;

        let rpc_url =
            std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
        let indexer_url =
            std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
        let mut rpc = SolanaRpc::new(rpc_url);
        let indexer = ZolanaIndexer::new(indexer_url);

        let spp_program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        rpc.assert_executable(&spp_program_id)?;
        let swap_program_id = Pubkey::new_from_array(*swap_program::SWAP_PROGRAM_ID.as_array());
        rpc.assert_executable(&swap_program_id)?;

        let payer = Keypair::new();
        let authority = Keypair::new();
        let forester_authority = Keypair::new();
        let merge_authority = Keypair::new();
        let tree_creation_authority = Keypair::new();
        let zone_creation_authority = Keypair::new();
        rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
        rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;
        rpc.airdrop(&forester_authority.pubkey(), 1_000_000_000)?;
        rpc.airdrop(&merge_authority.pubkey(), 1_000_000_000)?;
        rpc.airdrop(&tree_creation_authority.pubkey(), 1_000_000_000)?;
        rpc.airdrop(&zone_creation_authority.pubkey(), 1_000_000_000)?;

        let accounts = smart_account::standard_accounts();
        for ix in accounts.create_ixs(
            &payer.pubkey(),
            StandardSigners {
                protocol: authority.pubkey(),
                forester: forester_authority.pubkey(),
                merge: merge_authority.pubkey(),
                tree: tree_creation_authority.pubkey(),
                zone: zone_creation_authority.pubkey(),
            },
        ) {
            send_transaction(&mut rpc, &[ix], &payer.pubkey(), &[&payer])?;
        }

        rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?;

        let create_config_ix = CreateProtocolConfig {
            authority: accounts.protocol_vault,
            protocol_authority: accounts.protocol_vault.to_bytes().into(),
            tree_creation_authority: accounts.tree_vault.to_bytes().into(),
            tree_creation_is_permissionless: false,
            forester_authority: accounts.forester_vault.to_bytes().into(),
            zone_creation_authority: accounts.zone_vault.to_bytes().into(),
            zone_creation_is_permissionless: false,
            spl_interface_creation_is_permissionless: false,
        }
        .instruction();
        let create_config_sync = execute_sync_ix(
            &accounts.protocol_settings,
            0,
            &[authority.pubkey()],
            &[create_config_ix],
        );
        send_transaction(
            &mut rpc,
            &[create_config_sync],
            &payer.pubkey(),
            &[&payer, &authority],
        )?;

        let tree = Keypair::new();
        let rent = rpc
            .get_minimum_balance_for_rent_exemption(tree_account_size())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let alloc_ix = zolana_program_test::system_create_account_ix(
            &payer.pubkey(),
            &tree.pubkey(),
            rent,
            tree_account_size() as u64,
            &pda::shielded_pool_program_id(),
        );
        let create_tree_ix = zolana_interface::instruction::CreateTree {
            authority: accounts.tree_vault,
            tree: tree.pubkey(),
            owner: accounts.tree_vault,
        }
        .instruction();
        let create_tree_sync = execute_sync_ix(
            &accounts.tree_settings,
            0,
            &[tree_creation_authority.pubkey()],
            &[create_tree_ix],
        );
        send_transaction(
            &mut rpc,
            &[alloc_ix, create_tree_sync],
            &payer.pubkey(),
            &[&payer, &tree, &tree_creation_authority],
        )?;

        let tree_address = Address::new_from_array(tree.pubkey().to_bytes());
        Ok(Self {
            rpc,
            indexer,
            assets: AssetRegistry::default(),
            payer,
            tree: tree.pubkey(),
            tree_address,
            actors: BTreeMap::new(),
            open_orders: Vec::new(),
        })
    }

    pub(crate) fn ensure_actor(&mut self, name: &str) -> Result<()> {
        if !self.actors.contains_key(name) {
            self.actors.insert(name.to_string(), Actor::new()?);
        }
        Ok(())
    }

    pub(crate) fn actor(&self, name: &str) -> &Actor {
        self.actors.get(name).expect("actor exists")
    }

    pub(crate) fn actor_mut(&mut self, name: &str) -> &mut Actor {
        self.actors.get_mut(name).expect("actor exists")
    }

    pub(crate) fn wait_for_merkle_proof(
        &self,
        leaf: [u8; 32],
    ) -> Result<zolana_client::MerkleProof> {
        self.wait_for("indexed merkle proof", || {
            let response = self
                .indexer
                .get_merkle_proofs(self.tree_address, vec![leaf])?;
            Ok(response.proofs.into_iter().next())
        })
    }

    pub(crate) fn wait_for_non_inclusion_proof(
        &self,
        leaf: [u8; 32],
    ) -> Result<zolana_client::NonInclusionProof> {
        self.wait_for("indexed non-inclusion proof", || {
            let response = self
                .indexer
                .get_non_inclusion_proofs(self.tree_address, vec![leaf])?;
            Ok(response.proofs.into_iter().next())
        })
    }

    fn wait_for<T>(
        &self,
        label: &str,
        mut poll: impl FnMut() -> Result<Option<T>, zolana_client::ClientError>,
    ) -> Result<T> {
        let started = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(60);
        let mut last_error = None;
        while started.elapsed() < timeout {
            match poll() {
                Ok(Some(value)) => return Ok(value),
                Ok(None) => {}
                Err(error) => last_error = Some(error.to_string()),
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Err(anyhow::anyhow!(
            "timed out waiting for {label}; last indexer error: {}",
            last_error.unwrap_or_else(|| "none".to_string())
        ))
    }
}
