//! Shared localnet lifecycle harness used by the `spp-test-validator` and
//! `zone-test-program` integration suites.
//!
//! [`LocalnetHarness`] carries the validator/indexer handles, the protocol
//! smart-account state, the per-actor map, and the SPL asset registrations that
//! both suites bootstrap identically. Each suite's own harness struct
//! ([`crate::lifecycle::LifecycleHarness`], [`crate::zone::ZoneHarness`]) embeds
//! it (via `Deref`) and adds its suite-specific state (zone config, merge
//! records, rails).

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use solana_account::Account;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateProtocolConfig, CreateSplInterface, CreateTree},
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_smart_account_client::execute_sync_ix;
use zolana_transaction::{AssetRegistry, ShieldedTransaction, Utxo, Wallet, WalletUtxo};
use zolana_tree::InitAddressTreeAccountsInstructionData;

use crate::{
    localnet::{
        send_transaction, start_shielded_pool_localnet, DEFAULT_INDEXER_URL, DEFAULT_RPC_URL,
    },
    smart_account::{self, StandardAccounts, StandardSigners},
    spl::{create_mint, create_token_account},
    test_validator_asserts::assert_create_spl_interface,
};

/// Lamports airdropped to each actor's ed25519 signer to pay the fees of the
/// spends it authorizes; deposits stay funded by the global payer.
pub const ACTOR_FEE_FUNDING: u64 = 1_000_000_000;

// SOL occupies asset id 1; the first registered SPL mint gets id 2.
const FIRST_SPL_ASSET_ID: u64 = 2;

/// An SPL asset a scenario registers: its mint, the vault the deposit credits,
/// and the shared funding token account (owned by the payer).
#[derive(Clone, Copy)]
pub struct SplAsset {
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub user_token: Pubkey,
}

/// The extra account snapshots an SPL deposit assert needs.
#[derive(Clone)]
pub struct SplDepositAccounts {
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub user_token: Pubkey,
    pub vault_before: Account,
    pub user_token_before: Account,
}

/// What a deposit's action recorded, so the separate assert step can verify it
/// with the typed deposit asserts (which need the sent data and the pre-deposit
/// account snapshots). `spl` is `Some` for token deposits. `D` is the
/// suite-specific deposit instruction data (`AssetDeposit` for the plain pool,
/// `ZoneAssetDeposit` for zone deposits).
#[derive(Clone)]
pub struct DepositRecord<D> {
    pub signature: Signature,
    pub data: D,
    pub tree_before: Account,
    pub spl: Option<SplDepositAccounts>,
}

/// One shielded participant: its key material, the wallet it syncs into, the
/// UTXOs it can currently spend, and the full set of UTXOs its wallet is expected
/// to hold after a sync (with `spent` flags), tracked for full-struct assertions.
pub struct Actor<D> {
    pub keypair: ShieldedKeypair,
    pub wallet: Wallet,
    pub spendable: Vec<Utxo>,
    pub expected: Vec<WalletUtxo>,
    pub last_deposit: Option<DepositRecord<D>>,
    /// The ed25519 keypair that authorizes this actor's eddsa spends: the eddsa
    /// rail binds the payer (signer-run slot 0), so the actor pays and signs its
    /// own transfers/withdrawals with this key. `None` for P256 actors, which
    /// prove ownership inside the proof and let the harness payer fund the spend.
    pub solana_signer: Option<Keypair>,
}

impl<D> Actor<D> {
    /// An eddsa-rail actor whose shielded identity is derived from `signer`'s ed25519
    /// seed (so its shielded signing pubkey equals `signer`'s pubkey) and which
    /// authorizes its own spends with `signer`.
    pub fn eddsa(signer: Keypair) -> Result<Self> {
        let seed: [u8; 32] = signer.to_bytes()[..32]
            .try_into()
            .expect("ed25519 seed is the first 32 bytes");
        let keypair = ShieldedKeypair::from_ed25519(&seed, ViewingKey::new())?;
        let wallet = Wallet::new(keypair.shielded_address()?, AssetRegistry::default())?;
        Ok(Self {
            keypair,
            wallet,
            spendable: Vec::new(),
            expected: Vec::new(),
            last_deposit: None,
            solana_signer: Some(signer),
        })
    }

    /// A P256-rail actor with a fresh P256 shielded signing key. Spend
    /// authorization is proved inside ZoneP256; the harness payer funds and
    /// signs its transactions.
    pub fn p256() -> Result<Self> {
        let keypair = ShieldedKeypair::new()?;
        let wallet = Wallet::new(keypair.shielded_address()?, AssetRegistry::default())?;
        Ok(Self {
            keypair,
            wallet,
            spendable: Vec::new(),
            expected: Vec::new(),
            last_deposit: None,
            solana_signer: None,
        })
    }
}

/// The suite-specific knobs of [`LocalnetHarness::bootstrap`].
pub struct BootstrapConfig {
    /// Temp-path label for the validator ledger/account dirs (per suite, so
    /// concurrent suites do not share validator state).
    pub label: &'static str,
    /// Extra `(program_id, workspace-relative .so path)` programs the validator
    /// loads (e.g. the zone fixture program).
    pub extra_programs: Vec<(String, String)>,
    /// `CreateProtocolConfig::zone_creation_is_permissionless`. The zone suite
    /// sets it so the fixture's payer can create zone configs without the zone
    /// smart-account signing.
    pub zone_creation_is_permissionless: bool,
    /// Whether to fund the merge vault so it can collect the per-nullifier
    /// forester fee (only suites that execute merges need it).
    pub fund_merge_vault: bool,
}

/// The keypairs and smart-account layout minted by
/// [`LocalnetHarness::setup_protocol_accounts`], handed to the remaining
/// bootstrap steps (and to suites that drive the steps individually, e.g. to
/// create a tree with custom nullifier-batch params).
pub struct ProtocolSetup {
    pub payer: Keypair,
    pub authority: Keypair,
    pub forester_key: Keypair,
    pub merge_key: Keypair,
    pub tree_key: Keypair,
    pub zone_key: Keypair,
    pub accounts: StandardAccounts,
}

/// The validator/indexer handles, protocol smart-account state, actor map, and
/// SPL registrations shared by the localnet lifecycle suites. `D` is the
/// suite-specific deposit instruction data recorded in [`Actor::last_deposit`].
pub struct LocalnetHarness<D> {
    pub rpc: SolanaRpc,
    pub indexer: ZolanaIndexer,
    pub assets: AssetRegistry,
    pub payer: Keypair,
    pub authority: Keypair,
    pub tree: Pubkey,
    pub tree_address: Address,
    pub actors: BTreeMap<String, Actor<D>>,
    pub indexed: Vec<ShieldedTransaction>,
    pub spls: Vec<SplAsset>,
    pub protocol_settings: Pubkey,
    pub protocol_vault: Pubkey,
    pub merge_settings: Pubkey,
    pub merge_vault: Pubkey,
}

impl<D> LocalnetHarness<D> {
    /// Restart the validator + Photon and the workspace prover, then bring up the
    /// protocol config, the smart accounts, and a fresh Merkle tree (the composed
    /// default over [`start_stack`](Self::start_stack),
    /// [`setup_protocol_accounts`](Self::setup_protocol_accounts), and
    /// [`create_tree`](Self::create_tree)). Returns the harness and the merge key
    /// (the one bootstrap keypair used after startup: it authorizes merge
    /// instructions).
    pub fn bootstrap(config: BootstrapConfig) -> Result<(Self, Keypair)> {
        let (mut rpc, indexer) = Self::start_stack(&config)?;
        let setup = Self::setup_protocol_accounts(&mut rpc, &config)?;
        let (tree, tree_address) = Self::create_tree(&mut rpc, &setup, None)?;
        let harness = Self {
            rpc,
            indexer,
            assets: AssetRegistry::default(),
            payer: setup.payer,
            authority: setup.authority,
            tree,
            tree_address,
            actors: BTreeMap::new(),
            indexed: Vec::new(),
            spls: Vec::new(),
            protocol_settings: setup.accounts.protocol_settings,
            protocol_vault: setup.accounts.protocol_vault,
            merge_settings: setup.accounts.merge_settings,
            merge_vault: setup.accounts.merge_vault,
        };
        Ok((harness, setup.merge_key))
    }

    /// Bootstrap step 1: restart the validator + Photon and the workspace
    /// prover, then connect the RPC and indexer clients.
    pub fn start_stack(config: &BootstrapConfig) -> Result<(SolanaRpc, ZolanaIndexer)> {
        // The prover is independent of the validator and indexer, so start it
        // concurrently with the validator + Photon restart and join before use.
        let prover = std::thread::spawn(crate::prover::spawn_workspace_prover);
        let extra_programs: Vec<(String, &str)> = config
            .extra_programs
            .iter()
            .map(|(id, path)| (id.clone(), path.as_str()))
            .collect();
        start_shielded_pool_localnet(config.label, &extra_programs);
        prover.join().expect("prover startup thread panicked");

        let rpc_url =
            std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
        let indexer_url =
            std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
        let rpc = SolanaRpc::new(rpc_url);
        let indexer = ZolanaIndexer::new(indexer_url);
        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        rpc.assert_executable(&program_id)?;
        Ok((rpc, indexer))
    }

    /// Bootstrap step 2: fund the bootstrap keypairs, create the standard
    /// smart accounts, and create the protocol config.
    pub fn setup_protocol_accounts(
        rpc: &mut SolanaRpc,
        config: &BootstrapConfig,
    ) -> Result<ProtocolSetup> {
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
            send_transaction(rpc, &[ix], &payer.pubkey(), &[&payer])?;
        }

        // The shielded pool program requires the fee payer == protocol_authority,
        // so we CPI via execute_sync_ix with the protocol vault as the inner fee payer.
        rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?;
        if config.fund_merge_vault {
            // Merge instructions likewise use the merge vault as their inner payer.
            // Fund it so it can collect the per-nullifier forester fee.
            rpc.airdrop(&accounts.merge_vault, 5_000_000_000)?;
        }

        let create_config_ix = CreateProtocolConfig {
            authority: accounts.protocol_vault,
            protocol_authority: accounts.protocol_vault.to_bytes().into(),
            tree_creation_authority: accounts.tree_vault.to_bytes().into(),
            tree_creation_is_permissionless: false,
            forester_authority: accounts.forester_vault.to_bytes().into(),
            zone_creation_authority: accounts.zone_vault.to_bytes().into(),
            zone_creation_is_permissionless: config.zone_creation_is_permissionless,
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
            rpc,
            &[create_config_sync],
            &payer.pubkey(),
            &[&payer, &authority],
        )?;

        Ok(ProtocolSetup {
            payer,
            authority,
            forester_key,
            merge_key,
            tree_key,
            zone_key,
            accounts,
        })
    }

    /// Bootstrap step 3: allocate a fresh Merkle tree account and create it
    /// through the tree smart account. `nullifier_params` overrides the
    /// canonical nullifier-tree layout (e.g. the photon forester suite shrinks
    /// the ZKP batch size); `None` uses the canonical params.
    pub fn create_tree(
        rpc: &mut SolanaRpc,
        setup: &ProtocolSetup,
        nullifier_params: Option<InitAddressTreeAccountsInstructionData>,
    ) -> Result<(Pubkey, Address)> {
        let tree = Keypair::new();
        let rent = rpc
            .get_minimum_balance_for_rent_exemption(tree_account_size())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let alloc_ix = zolana_program_test::system_create_account_ix(
            &setup.payer.pubkey(),
            &tree.pubkey(),
            rent,
            tree_account_size() as u64,
            &pda::shielded_pool_program_id(),
        );
        let create = CreateTree {
            authority: setup.accounts.tree_vault,
            tree: tree.pubkey(),
        };
        let create_tree_ix = match nullifier_params {
            Some(params) => create.instruction_with_nullifier_params(params),
            None => create.instruction(),
        };
        let create_tree_sync = execute_sync_ix(
            &setup.accounts.tree_settings,
            0,
            &[setup.tree_key.pubkey()],
            &[create_tree_ix],
        );
        send_transaction(
            rpc,
            &[alloc_ix, create_tree_sync],
            &setup.payer.pubkey(),
            &[&setup.payer, &tree, &setup.tree_key],
        )?;

        let tree = tree.pubkey();
        Ok((tree, Address::new_from_array(tree.to_bytes())))
    }

    /// Create `name` (idempotently) as an eddsa-rail actor backed by a FRESH
    /// ed25519 signer, funded to pay the fees of the spends it authorizes (the
    /// eddsa rail reads the owner at signer index 0 / the fee payer).
    pub fn ensure_fresh_actor(&mut self, name: &str) -> Result<()> {
        if !self.actors.contains_key(name) {
            let signer = Keypair::new();
            self.rpc.airdrop(&signer.pubkey(), ACTOR_FEE_FUNDING)?;
            let actor = Actor::eddsa(signer)?;
            self.actors.insert(name.to_string(), actor);
        }
        Ok(())
    }

    /// Create `name` as an eddsa-rail actor whose owner is the PAYER's ed25519 key,
    /// so the payer's transaction signature satisfies the owner check (the actor pays
    /// and signs its own spends; the payer is its `solana_signer`). Its UTXOs take the
    /// eddsa rail.
    pub fn make_payer_actor(&mut self, name: &str) -> Result<()> {
        let actor = Actor::eddsa(self.payer.insecure_clone())?;
        self.actors.insert(name.to_string(), actor);
        Ok(())
    }

    /// Create `name` with a P256 shielded signing key. Its Solana transaction is
    /// paid by the harness payer; spend authorization is proved inside ZoneP256.
    pub fn make_p256_actor(&mut self, name: &str) -> Result<()> {
        self.actors.insert(name.to_string(), Actor::p256()?);
        Ok(())
    }

    pub fn actor(&self, name: &str) -> &Actor<D> {
        self.actors.get(name).expect("actor exists")
    }

    pub fn actor_mut(&mut self, name: &str) -> &mut Actor<D> {
        self.actors.get_mut(name).expect("actor exists")
    }

    /// Register `count` SPL assets, extending `self.spls` until it holds at least
    /// `count` (idempotent). Each registration creates a mint, ensures the asset
    /// counter, creates + asserts the shielded-pool interface (registry + vault),
    /// creates a shared payer-owned funding token account, and adds the mint to the
    /// asset registry under the next asset id so transfers can resolve it.
    pub fn ensure_spl_assets(&mut self, count: usize) -> Result<()> {
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
                token_program: zolana_interface::pda::spl_token_program_id(),
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
            let vault = pda::spl_interface(&mint);

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
    pub fn ensure_spl_asset(&mut self) -> Result<()> {
        self.ensure_spl_assets(1)
    }

    pub fn spl_asset(&self) -> Result<&SplAsset> {
        self.spls
            .first()
            .ok_or_else(|| anyhow!("no SPL asset registered"))
    }
}
