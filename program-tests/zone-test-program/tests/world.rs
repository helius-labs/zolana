//! The cucumber `World`: localnet/indexer handles, per-actor state, and setup.
//!
//! The lifecycle operations live next to their cucumber steps in `steps/*`, each
//! adding an `impl ZoneLifecycleWorld` block; the fields and actor accessors here
//! are `pub(crate)` so those step modules can drive the World.

#![allow(dead_code)]

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CreateAssetCounter, CreateSplInterface, CreateZoneConfigData,
    },
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::PublicKey;
use zolana_program_test::ZONE_TEST_PROGRAM_ID;
use zolana_test_utils::{
    smart_account::{self, execute_sync_ix, StandardSigners},
    spl::{create_mint, create_token_account},
    test_validator_asserts::assert_create_spl_interface,
};
use zolana_transaction::{
    serialization::{confidential::ConfidentialSenderBundle, DecodeCx, UtxoSerialization},
    AssetRegistry, Data, ShieldedTransaction, Utxo, WalletUtxo, DEFAULT_TAG_WINDOW,
};

use crate::{
    actor::Actor,
    localnet::{
        restart_localnet, send_transaction, start_prover, DEFAULT_INDEXER_URL, DEFAULT_RPC_URL,
        ZERO,
    },
    support::{MergeZoneRecord, Rail, SplAsset},
};

// SOL occupies asset id 1; the first registered SPL mint gets id 2.
const FIRST_SPL_ASSET_ID: u64 = 2;

#[derive(cucumber::World)]
#[world(init = Self::new)]
pub struct ZoneLifecycleWorld {
    pub(crate) rpc: SolanaRpc,
    pub(crate) indexer: ZolanaIndexer,
    pub(crate) assets: AssetRegistry,
    pub(crate) payer: Keypair,
    pub(crate) authority: Keypair,
    pub(crate) tree: Pubkey,
    pub(crate) tree_address: Address,
    pub(crate) actors: BTreeMap<String, Actor>,
    pub(crate) zone_program_id: Pubkey,
    /// The zone's `zone_auth` PDA (which IS the zone-config account), set when the
    /// zone config is created.
    pub(crate) zone_config: Option<Pubkey>,
    pub(crate) zone_authority: Option<Keypair>,
    pub(crate) previous_zone_authority: Option<Keypair>,
    pub(crate) indexed: Vec<ShieldedTransaction>,
    pub(crate) spls: Vec<SplAsset>,
    /// The Solana keypair each actor registered on the user-registry under, kept so
    /// the `merge_zone` step can derive the `user_record` PDA the program reads.
    pub(crate) merge_owners: BTreeMap<String, Keypair>,
    /// Which rail the last zone transact / merge took.
    pub(crate) last_rail: Option<Rail>,
    /// The most recent `zone_transact` instruction and its transaction signature,
    /// kept so a decode step can re-parse the exact bytes and accounts that were sent.
    pub(crate) last_transact: Option<(Signature, Instruction)>,
    /// The most recent `merge_zone`, kept so the consolidated-output assert can
    /// reconstruct and verify the merged UTXO.
    pub(crate) last_merge: Option<MergeZoneRecord>,
    pub(crate) protocol_settings: Pubkey,
    pub(crate) protocol_vault: Pubkey,
}

impl std::fmt::Debug for ZoneLifecycleWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZoneLifecycleWorld")
    }
}

impl ZoneLifecycleWorld {
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

        // Permissionless zone creation lets the fixture's payer create the zone
        // config without the zone smart-account signing.
        let create_config_ix = zolana_interface::instruction::CreateProtocolConfig {
            authority: accounts.protocol_vault,
            protocol_authority: accounts.protocol_vault.to_bytes().into(),
            tree_creation_authority: accounts.tree_vault.to_bytes().into(),
            tree_creation_is_permissionless: false,
            forester_authority: accounts.forester_vault.to_bytes().into(),
            zone_creation_authority: accounts.zone_vault.to_bytes().into(),
            zone_creation_is_permissionless: true,
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
            authority,
            tree: tree.pubkey(),
            tree_address,
            actors: BTreeMap::new(),
            zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
            zone_config: None,
            zone_authority: None,
            previous_zone_authority: None,
            indexed: Vec::new(),
            spls: Vec::new(),
            merge_owners: BTreeMap::new(),
            last_rail: None,
            last_transact: None,
            last_merge: None,
            protocol_settings: accounts.protocol_settings,
            protocol_vault: accounts.protocol_vault,
        })
    }

    /// Create the zone config through the fixture's `CREATE_ZONE_CONFIG` instruction.
    /// The fixture signs the `zone_auth` PDA (which IS the config account) on the CPI
    /// into SPP. Stores the resulting `zone_auth` PDA in `self.zone_config`. The
    /// caller owns the authority keypair and is responsible for setting
    /// `self.zone_authority` if it wants to track it.
    pub(crate) fn create_zone_config(&mut self, authority: &Address, enabled: bool) -> Result<()> {
        let payer = self.payer.insecure_clone();
        let (zone_auth, _) = pda::zone_auth(&self.zone_program_id);
        let data = CreateZoneConfigData {
            program_id: ZONE_TEST_PROGRAM_ID.into(),
            authority: *authority,
            zone_authority_transact_is_enabled: enabled,
        };
        let ix = Instruction {
            program_id: self.zone_program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(zone_auth, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            ],
            data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
        };
        send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer])?;
        self.zone_config = Some(zone_auth);
        Ok(())
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
        let actor = self.actor_mut(name);
        actor.wallet.sync(&indexed, 0, DEFAULT_TAG_WINDOW)?;

        let nullifier_pk = actor.keypair.nullifier_key.pubkey()?;
        let mut spendable_hashes: Vec<[u8; 32]> = Vec::new();
        for utxo in &actor.spendable {
            spendable_hashes.push(utxo.hash(&nullifier_pk, &ZERO, &ZERO)?);
        }
        let newly_spendable: Vec<Utxo> = actor
            .wallet
            .utxos
            .iter()
            .filter(|w| !w.spent && !spendable_hashes.contains(&w.output_context.hash))
            .map(|w| w.utxo.clone())
            .collect();
        actor.spendable.extend(newly_spendable);
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

    /// Sync and assert the actor decrypts nothing (view-tag isolation).
    pub(crate) fn assert_no_utxos(&mut self, name: &str) -> Result<()> {
        self.ensure_actor(name)?;
        let indexed = self.indexed.clone();
        let actor = self.actor_mut(name);
        actor.wallet.sync(&indexed, 0, DEFAULT_TAG_WINDOW)?;
        assert!(
            actor.wallet.utxos.is_empty(),
            "{name} should not decrypt any UTXOs but found {}",
            actor.wallet.utxos.len()
        );
        Ok(())
    }

    /// Build the `WalletUtxo` the scenario expects an actor to hold for a known
    /// `(owner, asset, amount, blinding)`, locating its on-chain output context in
    /// the indexed transaction so `assert_utxos` cross-checks the synced wallet.
    pub(crate) fn build_expected(
        &self,
        name: &str,
        owner: PublicKey,
        asset: Address,
        amount: u64,
        blinding: [u8; 31],
        tx: &ShieldedTransaction,
    ) -> Result<WalletUtxo> {
        let keypair = &self.actor(name).keypair;
        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let utxo = Utxo {
            owner,
            asset,
            amount,
            blinding,
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

    /// Register `count` SPL assets, extending `self.spls` until it holds at least
    /// `count` (idempotent). Each registration creates a mint, ensures the asset
    /// counter, creates + asserts the shielded-pool interface (registry + vault),
    /// creates a shared payer-owned funding token account, and adds the mint to the
    /// asset registry under the next asset id so transfers can resolve it.
    pub(crate) fn ensure_spl_assets(&mut self, count: usize) -> Result<()> {
        let payer = self.payer.insecure_clone();
        let authority = self.authority.insecure_clone();
        let protocol_vault = self.protocol_vault;
        let protocol_settings = self.protocol_settings;

        while self.spls.len() < count {
            let asset_id = FIRST_SPL_ASSET_ID + self.spls.len() as u64;

            let mint = create_mint(&self.rpc, &payer)?;

            // Both CreateAssetCounter and CreateSplInterface check protocol_authority
            // in ProtocolConfig, which is the protocol vault PDA. Wrap each in
            // execute_sync_ix so the vault signs via the Squads CPI mechanism.
            let counter_addr = Address::new_from_array(pda::spl_asset_counter().to_bytes());
            if self.rpc.get_account(counter_addr)?.is_none() {
                let ix = CreateAssetCounter {
                    authority: protocol_vault,
                }
                .instruction();
                let sync_ix = execute_sync_ix(&protocol_settings, 0, &[authority.pubkey()], &[ix]);
                send_transaction(
                    &mut self.rpc,
                    &[sync_ix],
                    &payer.pubkey(),
                    &[&payer, &authority],
                )?;
            }

            let ix = CreateSplInterface {
                authority: protocol_vault,
                mint,
            }
            .instruction();
            let sync_ix = execute_sync_ix(&protocol_settings, 0, &[authority.pubkey()], &[ix]);
            send_transaction(
                &mut self.rpc,
                &[sync_ix],
                &payer.pubkey(),
                &[&payer, &authority],
            )?;
            let registry = pda::spl_asset_registry(&mint);
            let vault = pda::spl_asset_vault(&mint);

            assert_create_spl_interface(
                &self.rpc,
                &registry,
                &vault,
                &mint,
                asset_id,
                asset_id + 1,
            )?;
            let user_token = create_token_account(&self.rpc, &payer, &mint, &payer.pubkey())?;

            self.assets
                .insert(asset_id, Address::new_from_array(mint.to_bytes()))
                .map_err(|e| anyhow!("register SPL asset: {e}"))?;
            self.spls.push(SplAsset {
                mint,
                vault,
                user_token,
            });
        }
        Ok(())
    }

    /// Register one SPL asset (idempotent), used by single-asset features.
    pub(crate) fn ensure_spl_asset(&mut self) -> Result<()> {
        self.ensure_spl_assets(1)
    }

    pub(crate) fn spl_asset(&self) -> Result<&SplAsset> {
        self.spls
            .first()
            .ok_or_else(|| anyhow!("no SPL asset registered"))
    }
}

/// Decode the sender bundle's blinding seed from the sender slot (slot 0) of an
/// indexed transaction, so the expected change/recipient set can be rebuilt
/// independently of `Wallet::sync`.
pub(crate) fn decode_sender_seed(
    viewing_key: &zolana_keypair::ViewingKey,
    indexed: &ShieldedTransaction,
) -> Result<[u8; 31]> {
    let cx = DecodeCx::for_slot(viewing_key, indexed, 0);
    let slot0 = indexed
        .output_slots
        .first()
        .ok_or_else(|| anyhow!("no sender slot"))?;
    let output_data = slot0
        .output_data()
        .ok_or_else(|| anyhow!("sender slot undecodable"))?;
    let body = match &output_data {
        zolana_event::OutputDataEncoding::Encrypted(blob) => blob
            .split_first()
            .map(|(_, body)| body)
            .ok_or_else(|| anyhow!("empty sender blob"))?,
        _ => return Err(anyhow!("sender slot not encrypted")),
    };
    let sender_plaintext = ConfidentialSenderBundle::decode(body, &cx)?;
    Ok(sender_plaintext.blinding_seed)
}
