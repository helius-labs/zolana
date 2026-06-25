//! The cucumber `World`: localnet/indexer handles, per-actor state, and setup.
//!
//! The lifecycle operations live next to their cucumber steps in `steps/*`, each
//! adding an `impl LifecycleWorld` block; the fields and actor accessors here are
//! `pub(crate)` so those step modules can drive the World.

use std::collections::BTreeMap;

use anyhow::Result;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::{
    instruction::CreateProtocolConfig, pda, state::tree_account_size, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_test_utils::smart_account::{
    create_smart_account_ix, execute_sync_ix, settings_pda, smart_account_pda, treasury_pda,
    Permissions, SmartAccountSigner,
};
use zolana_transaction::{AssetRegistry, ShieldedTransaction};

use crate::{
    actor::Actor,
    localnet::{
        restart_localnet, send_transaction, start_prover, DEFAULT_INDEXER_URL, DEFAULT_RPC_URL,
    },
};

/// An SPL asset a scenario registers: its mint, the vault the deposit credits,
/// and the shared funding token account (owned by the payer).
#[derive(Clone, Copy)]
pub(crate) struct SplAsset {
    pub(crate) mint: Pubkey,
    pub(crate) vault: Pubkey,
    pub(crate) user_token: Pubkey,
}

/// Which ownership rail the last transfer took. P256 proves ownership inside the
/// proof; Eddsa proves it with an ed25519 signature on the transaction, checked by
/// the program against the eddsa signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rail {
    P256,
    Eddsa,
}

#[derive(cucumber::World)]
#[world(init = Self::new)]
pub struct LifecycleWorld {
    pub(crate) rpc: SolanaRpc,
    pub(crate) indexer: ZolanaIndexer,
    pub(crate) assets: AssetRegistry,
    pub(crate) payer: Keypair,
    pub(crate) authority: Keypair,
    pub(crate) tree: Pubkey,
    pub(crate) tree_address: Address,
    pub(crate) actors: BTreeMap<String, Actor>,
    /// The Solana keypair each actor registered on the user-registry under, kept so
    /// the merge step can derive the `user_record` PDA the program reads.
    pub(crate) merge_owners: BTreeMap<String, Keypair>,
    pub(crate) indexed: Vec<ShieldedTransaction>,
    pub(crate) spls: Vec<SplAsset>,
    pub(crate) last_rail: Option<Rail>,
    /// The most recent `transact` instruction and its transaction signature, kept
    /// so the decode step can re-parse the exact bytes and accounts that were sent.
    pub(crate) last_transact: Option<(Signature, Instruction)>,
    /// The most recent merge, kept so the consolidated-output assert can reconstruct
    /// and verify the merged UTXO.
    pub(crate) last_merge: Option<crate::steps::merge::MergeRecord>,
    pub(crate) protocol_settings: Pubkey,
    pub(crate) protocol_vault: Pubkey,
    pub(crate) merge_settings: Pubkey,
    pub(crate) merge_vault: Pubkey,
    pub(crate) merge_key: Keypair,
}

impl std::fmt::Debug for LifecycleWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LifecycleWorld")
    }
}

impl LifecycleWorld {
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

        // Seeds are deterministic: the injected ProgramConfig starts with
        // smart_account_index = 0; the program uses index + 1 as each seed.
        let (protocol_settings, _) = settings_pda(1);
        let (protocol_vault, _) = smart_account_pda(&protocol_settings, 0);
        let (forester_settings, _) = settings_pda(2);
        let (forester_vault, _) = smart_account_pda(&forester_settings, 0);
        let (merge_settings, _) = settings_pda(3);
        let (merge_vault, _) = smart_account_pda(&merge_settings, 0);
        let (tree_settings, _) = settings_pda(4);
        let (tree_vault, _) = smart_account_pda(&tree_settings, 0);
        let (zone_settings, _) = settings_pda(5);
        let (zone_vault, _) = smart_account_pda(&zone_settings, 0);

        let signer_all = |key: Pubkey| {
            vec![SmartAccountSigner {
                key,
                permissions: Permissions::all(),
            }]
        };

        let treasury = treasury_pda();

        send_transaction(
            &mut rpc,
            &[create_smart_account_ix(
                &payer.pubkey(),
                &treasury,
                1,
                None,
                &signer_all(authority.pubkey()),
                1,
                0,
            )],
            &payer.pubkey(),
            &[&payer],
        )?;
        send_transaction(
            &mut rpc,
            &[create_smart_account_ix(
                &payer.pubkey(),
                &treasury,
                2,
                Some(protocol_vault),
                &signer_all(forester_key.pubkey()),
                1,
                0,
            )],
            &payer.pubkey(),
            &[&payer],
        )?;
        send_transaction(
            &mut rpc,
            &[create_smart_account_ix(
                &payer.pubkey(),
                &treasury,
                3,
                Some(protocol_vault),
                &signer_all(merge_key.pubkey()),
                1,
                0,
            )],
            &payer.pubkey(),
            &[&payer],
        )?;
        send_transaction(
            &mut rpc,
            &[create_smart_account_ix(
                &payer.pubkey(),
                &treasury,
                4,
                Some(protocol_vault),
                &signer_all(tree_key.pubkey()),
                1,
                0,
            )],
            &payer.pubkey(),
            &[&payer],
        )?;
        send_transaction(
            &mut rpc,
            &[create_smart_account_ix(
                &payer.pubkey(),
                &treasury,
                5,
                Some(protocol_vault),
                &signer_all(zone_key.pubkey()),
                1,
                0,
            )],
            &payer.pubkey(),
            &[&payer],
        )?;

        // The shielded pool program requires the fee payer == protocol_authority,
        // so we CPI via execute_sync_ix with the protocol vault as the inner fee payer.
        rpc.airdrop(&protocol_vault, 5_000_000_000)?;

        let create_config_ix = CreateProtocolConfig {
            authority: protocol_vault,
            protocol_authority: protocol_vault.to_bytes().into(),
            tree_creation_authority: tree_vault.to_bytes().into(),
            tree_creation_is_permissionless: false,
            forester_authority: forester_vault.to_bytes().into(),
            zone_creation_authority: zone_vault.to_bytes().into(),
            zone_creation_is_permissionless: false,
            merge_authority: merge_vault.to_bytes().into(),
        }
        .instruction();
        let create_config_sync = execute_sync_ix(
            &protocol_settings,
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
            authority: tree_vault,
            tree: tree.pubkey(),
            owner: tree_vault,
        }
        .instruction();
        let create_tree_sync =
            execute_sync_ix(&tree_settings, 0, &[tree_key.pubkey()], &[create_tree_ix]);
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
            authority,
            tree: tree.pubkey(),
            tree_address,
            actors: BTreeMap::new(),
            merge_owners: BTreeMap::new(),
            indexed: Vec::new(),
            spls: Vec::new(),
            last_rail: None,
            last_transact: None,
            last_merge: None,
            protocol_settings,
            protocol_vault,
            merge_settings,
            merge_vault,
            merge_key,
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
}
