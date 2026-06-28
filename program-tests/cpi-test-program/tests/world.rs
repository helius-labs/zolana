//! The cucumber `World`: localnet/indexer handles, per-actor state, and setup.
//!
//! The lifecycle operations live next to their cucumber steps in `steps/*`, each
//! adding an `impl CpiLifecycleWorld` block; the fields and actor accessors here are
//! `pub(crate)` so those step modules can drive the World.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::{
    instruction::CreateProtocolConfig, pda, state::tree_account_size, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::PublicKey;
use zolana_test_utils::smart_account::{self, execute_sync_ix, StandardSigners};
use zolana_transaction::{
    AssetRegistry, Data, ShieldedTransaction, Utxo, WalletUtxo, DEFAULT_TAG_WINDOW,
};

use crate::{
    actor::Actor,
    localnet::{
        restart_localnet, send_transaction, start_prover, DEFAULT_INDEXER_URL, DEFAULT_RPC_URL,
        ZERO,
    },
};

#[derive(cucumber::World)]
#[world(init = Self::new)]
pub struct CpiLifecycleWorld {
    pub(crate) rpc: SolanaRpc,
    pub(crate) indexer: ZolanaIndexer,
    pub(crate) assets: AssetRegistry,
    pub(crate) payer: Keypair,
    pub(crate) tree: Pubkey,
    pub(crate) tree_address: Address,
    pub(crate) actors: BTreeMap<String, Actor>,
    pub(crate) indexed: Vec<ShieldedTransaction>,
}

impl std::fmt::Debug for CpiLifecycleWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CpiLifecycleWorld")
    }
}

impl CpiLifecycleWorld {
    async fn new() -> Result<Self> {
        // The prover is independent of the validator and indexer, so start it
        // concurrently with the validator + Photon restart and join before use.
        let prover = std::thread::spawn(start_prover);
        restart_localnet();
        prover.join().expect("prover startup thread panicked")?;

        let rpc_url =
            std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
        let indexer_url =
            std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
        let mut rpc = SolanaRpc::new(rpc_url);
        let indexer = ZolanaIndexer::new(indexer_url);
        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        rpc.assert_executable(&program_id)?;

        let payer = Keypair::new();
        let authority = Keypair::new();
        let forester_key = Keypair::new();
        let merge_key = Keypair::new();
        let tree_key = Keypair::new();
        let zone_key = Keypair::new();
        rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
        rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;
        rpc.airdrop(&forester_key.pubkey(), 1_000_000_000)?;
        rpc.airdrop(&merge_key.pubkey(), 1_000_000_000)?;
        rpc.airdrop(&tree_key.pubkey(), 1_000_000_000)?;
        rpc.airdrop(&zone_key.pubkey(), 1_000_000_000)?;

        let accounts = smart_account::standard_accounts();
        for ix in accounts.create_ixs(
            &payer.pubkey(),
            StandardSigners {
                protocol: authority.pubkey(),
                forester: forester_key.pubkey(),
                merge: merge_key.pubkey(),
                tree: tree_key.pubkey(),
                zone: zone_key.pubkey(),
            },
        ) {
            send_transaction(&mut rpc, &[ix], &payer.pubkey(), &[&payer])?;
        }

        // The shielded pool program requires the fee payer == protocol_authority,
        // so we CPI via execute_sync_ix with the protocol vault as the inner fee payer.
        rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?;

        let create_config_ix = CreateProtocolConfig {
            authority: accounts.protocol_vault,
            protocol_authority: accounts.protocol_vault.to_bytes().into(),
            tree_creation_authority: accounts.tree_vault.to_bytes().into(),
            tree_creation_is_permissionless: false,
            forester_authority: accounts.forester_vault.to_bytes().into(),
            zone_creation_authority: accounts.zone_vault.to_bytes().into(),
            zone_creation_is_permissionless: false,
            merge_authority: accounts.merge_vault.to_bytes().into(),
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
            .map_err(|e| anyhow!("{e}"))?;
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
            &[tree_key.pubkey()],
            &[create_tree_ix],
        );
        send_transaction(
            &mut rpc,
            &[alloc_ix, create_tree_sync],
            &payer.pubkey(),
            &[&payer, &tree, &tree_key],
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
            indexed: Vec::new(),
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

    /// Sync an actor's wallet from every indexed transaction (decryption), and make
    /// newly decrypted, unspent UTXOs spendable. No assertions.
    pub(crate) fn sync(&mut self, name: &str) -> Result<()> {
        self.ensure_actor(name)?;
        let indexed = self.indexed.clone();
        let assets = self.assets.clone();
        let actor = self.actor_mut(name);
        actor
            .wallet
            .sync(&indexed, &assets, 0, DEFAULT_TAG_WINDOW)?;
        Ok(())
    }

    /// Full-struct assert that the actor's synced wallet holds exactly the UTXOs it
    /// is expected to have decrypted (with `spent` flags). Run `sync` first.
    pub(crate) fn assert_utxos(&self, name: &str) -> Result<()> {
        let actor = self.actor(name);
        let mut actual = actor.wallet.utxos.clone();
        let mut expected = actor.expected.clone();
        actual.sort_by_key(|u| u.output_context.hash);
        expected.sort_by_key(|u| u.output_context.hash);
        assert_eq!(
            actual, expected,
            "synced UTXOs for {name} do not match expected"
        );
        Ok(())
    }

    /// Build the `WalletUtxo` the scenario expects an actor to hold for a known
    /// `(owner, asset, amount, blinding, program_id)`, locating its on-chain output
    /// context in the indexed transaction so `assert_utxos` cross-checks the synced
    /// wallet. A program-governed output carries `program_id: Some(..)`, so its hash
    /// folds the program hash (with a zero `program_data_hash`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_expected(
        &self,
        name: &str,
        owner: PublicKey,
        asset: Address,
        amount: u64,
        blinding: [u8; 31],
        program_id: Option<Address>,
        tx: &ShieldedTransaction,
    ) -> Result<WalletUtxo> {
        let keypair = &self.actor(name).keypair;
        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let utxo = Utxo {
            owner,
            asset,
            amount,
            blinding,
            program_id,
            zone_program_id: None,
            data: Data::default(),
        };
        let hash = utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
        let output_context = tx
            .output_slots
            .iter()
            .find(|slot| slot.output_context.hash == hash)
            .map(|slot| slot.output_context.clone())
            .ok_or_else(|| anyhow!("expected output not found in indexed tx"))?;
        let nullifier = utxo.nullifier(&output_context.hash, &keypair.nullifier_key)?;
        Ok(WalletUtxo {
            utxo,
            output_context,
            nullifier,
            spent: false,
        })
    }
}
