//! The cucumber `World`: localnet/indexer handles, per-recipient deposit state,
//! and setup. Each scenario boots a fresh validator + Photon, initializes SPP's
//! protocol config and a state tree, creates the Squads zone's own `zone_config`,
//! and registers it with SPP via `init_spp_zone_config` (a real CPI) so the zone
//! `deposit` can settle through SPP. The lifecycle operations live next to their
//! cucumber steps in `steps/*`, each adding an `impl SquadsLifecycleWorld` block;
//! the fields and accessors here are `pub(crate)` so those modules can drive it.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

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
use zolana_squads_client::{DecryptedUtxo, GetBalancesRequest, SquadsBackend};
use zolana_squads_interface::{
    instruction::{
        builders::{CreateZoneConfig, InitSppZoneConfig},
        CreateZoneConfigIxData,
    },
    SQUADS_ZONE_PROGRAM_ID, ZONE_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};
use zolana_test_utils::{
    smart_account::{self, execute_sync_ix, Permissions, SmartAccountSigner, StandardSigners},
    spl::create_mint,
    test_validator_asserts::assert_create_spl_interface,
};
use zolana_transaction::AssetRegistry;

use crate::fixture::PROPOSER_SETTINGS_SEED;

use crate::localnet::{
    restart_localnet, send_transaction, start_prover, DEFAULT_INDEXER_URL, DEFAULT_RPC_URL,
};

// SOL occupies asset id 1; the first registered SPL mint gets id 2.
const FIRST_SPL_ASSET_ID: u64 = 2;

/// An SPL asset a scenario registers: its mint (each deposit funds its own
/// vault-owned token account).
#[derive(Clone, Copy)]
pub(crate) struct SplAsset {
    pub(crate) mint: Pubkey,
}

/// The pre-deposit settlement-account snapshots a deposit assert compares against.
#[derive(Clone)]
pub(crate) enum SettlementSnapshot {
    Sol {
        sol_interface: Pubkey,
        sol_interface_before: Account,
    },
    Spl {
        vault: Pubkey,
        user_token: Pubkey,
        vault_before: Account,
        user_token_before: Account,
    },
}

/// What a deposit recorded, so the separate assert step can verify the full state
/// transition through SPP.
#[derive(Clone)]
pub(crate) struct DepositRecord {
    pub(crate) signature: Signature,
    pub(crate) view_tag: [u8; 32],
    pub(crate) blinding: [u8; 31],
    pub(crate) asset: Address,
    pub(crate) tree_before: Account,
    pub(crate) settlement: SettlementSnapshot,
}

/// What a withdrawal recorded, so the assert step can verify the on-chain
/// fund-movement OUT of the pool (the shielded change is verified separately via
/// the backend `get_balances`). The public destination and the pool settlement
/// account are snapshotted before settlement; the assert compares the deltas.
#[derive(Clone)]
pub(crate) struct WithdrawalRecord {
    pub(crate) withdrawn: u64,
    /// The public destination (a system account for SOL, a token account for SPL).
    pub(crate) recipient: Pubkey,
    pub(crate) recipient_before: u64,
    /// The pool settlement account funds leave (SOL interface or SPL vault).
    pub(crate) pool: Pubkey,
    pub(crate) pool_before: u64,
    pub(crate) is_spl: bool,
}

fn squads_program_id() -> Pubkey {
    Pubkey::new_from_array(SQUADS_ZONE_PROGRAM_ID)
}

fn zone_config_pda() -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], &squads_program_id()).0
}

fn zone_auth_pda() -> Pubkey {
    Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], &squads_program_id()).0
}

#[derive(cucumber::World)]
#[world(init = Self::new)]
pub struct SquadsLifecycleWorld {
    pub(crate) rpc: SolanaRpc,
    pub(crate) indexer: ZolanaIndexer,
    pub(crate) assets: AssetRegistry,
    pub(crate) payer: Keypair,
    pub(crate) authority: Keypair,
    pub(crate) tree: Pubkey,
    /// The Squads zone's `zone_auth` PDA, which is SPP's `ZoneConfig` account.
    pub(crate) zone_auth: Pubkey,
    pub(crate) spls: Vec<SplAsset>,
    pub(crate) deposits: BTreeMap<String, DepositRecord>,
    pub(crate) withdrawals: BTreeMap<String, WithdrawalRecord>,
    pub(crate) protocol_settings: Pubkey,
    pub(crate) protocol_vault: Pubkey,
    /// The configured zone co-signer, which must sign every `transact` /
    /// `execute_proposal`.
    pub(crate) co_signer: Keypair,
    /// The proposer smart account's `settings` PDA (seed 6). Its vault owns and
    /// executes every deposit / `transact` / `create_proposal`.
    pub(crate) proposer_settings: Pubkey,
    /// The proposer smart account's vault (account index 0); the shielded UTXO
    /// owner and the inner-instruction executor.
    pub(crate) proposer_vault: Pubkey,
    /// The proposer smart account is a 2-of-2 multisig. The operations that require
    /// the vault to sign -- the deposit and the async `create_proposal` -- are wrapped
    /// in `executeTransactionSyncV2` and need BOTH members. Sync `transact` settles on
    /// the zone-authority rail, which needs no vault signature, so it is not wrapped
    /// (a single fee payer + the co-signer authorize it).
    pub(crate) proposer_member: Keypair,
    pub(crate) proposer_member_b: Keypair,
    /// The vault's shielded owner field (`owner_pk_field = hash_field(vault)`), the
    /// on-chain `owner` of the smart-account sender VKA.
    pub(crate) owner_field: [u8; 32],
    /// The `Proposal` PDA created by the current scenario's `create_proposal` step,
    /// polled by the crank-settle wait step until it is closed.
    pub(crate) pending_proposal: Option<Pubkey>,
    /// The Squads backend mock: holds the auditor key and decrypts every account's
    /// balances via each account's shared viewing key (user keys are recovery-only).
    pub(crate) backend: SquadsBackend<ZolanaIndexer, SolanaRpc>,
}

impl std::fmt::Debug for SquadsLifecycleWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SquadsLifecycleWorld")
    }
}

impl SquadsLifecycleWorld {
    async fn new() -> Result<Self> {
        // The prover is independent of the validator and indexer, so start it
        // concurrently with the localnet restart. Proof-gated scenarios
        // (`transact` / `execute_proposal`) need it; the proofless `deposit`
        // never calls it.
        let prover = std::thread::spawn(start_prover);
        restart_localnet();
        prover.join().expect("prover startup thread panicked")?;

        let rpc_url =
            std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
        let indexer_url =
            std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
        let mut rpc = SolanaRpc::new(rpc_url);
        let indexer = ZolanaIndexer::new(indexer_url);
        rpc.assert_executable(&Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID))?;
        rpc.assert_executable(&squads_program_id())?;

        let payer = Keypair::new();
        let authority = Keypair::new();
        let forester_key = Keypair::new();
        let merge_key = Keypair::new();
        let tree_key = Keypair::new();
        let zone_key = Keypair::new();
        rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
        for keypair in [&authority, &forester_key, &merge_key, &tree_key, &zone_key] {
            rpc.airdrop(&keypair.pubkey(), 1_000_000_000)?;
        }

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

        // The shielded pool requires the fee payer == protocol_authority, so the
        // protocol config is created via the smart-account CPI with the protocol
        // vault as the inner fee payer. Permissionless zone creation lets
        // `init_spp_zone_config`'s payer create SPP's zone config.
        rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?;
        let create_config_ix = CreateProtocolConfig {
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
            .map_err(|e| anyhow!("{e}"))?;
        let alloc_ix = zolana_program_test::system_create_account_ix(
            &payer.pubkey(),
            &tree.pubkey(),
            rent,
            tree_account_size() as u64,
            &pda::shielded_pool_program_id(),
        );
        let create_tree_ix = CreateTree {
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

        // The Squads zone's own zone config, then register it with SPP. The auditor
        // key is the backend's deterministic auditor key: every viewing key account
        // publishes its shared viewing key encrypted to it, so the backend recovers
        // and decrypts balances with the auditor secret (user keys are recovery-only).
        // A real co-signer keypair is configured so a `transact` withdrawal can
        // sign for it (the proofless deposit never touches the co-signer).
        let squads_authority = Keypair::new();
        rpc.airdrop(&squads_authority.pubkey(), 1_000_000_000)?;
        let co_signer = Keypair::new();
        rpc.airdrop(&co_signer.pubkey(), 1_000_000_000)?;
        let create_zone_config_ix = CreateZoneConfig {
            creator: payer.pubkey(),
            zone_config: zone_config_pda(),
            system_program: Pubkey::default(),
            data: CreateZoneConfigIxData {
                authority: squads_authority.pubkey(),
                co_signer: co_signer.pubkey(),
                max_proposal_lifetime: 3_600,
                auditor_keys: vec![*crate::fixture::auditor_pubkey().as_bytes()],
                // The backend crank relays merge_transact signed by the zone
                // co-signer, so it must be whitelisted or every merge is rejected.
                merge_authorities: vec![co_signer.pubkey()],
            },
        }
        .instruction();
        send_transaction(
            &mut rpc,
            &[create_zone_config_ix],
            &payer.pubkey(),
            &[&payer],
        )?;

        let zone_auth = zone_auth_pda();
        let init_ix = InitSppZoneConfig {
            authority: squads_authority.pubkey(),
            zone_config: zone_config_pda(),
            protocol_config: pda::protocol_config(),
            zone_auth,
            system_program: Pubkey::default(),
            spp_program: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        }
        .instruction();
        send_transaction(
            &mut rpc,
            &[init_ix],
            &payer.pubkey(),
            &[&payer, &squads_authority],
        )?;

        // One more smart account (seed 6, autonomous) whose vault owns the shielded
        // lifecycle. It is a 2-of-2 multisig: the operations that require the vault to
        // sign -- the deposit and the async `create_proposal` -- are wrapped in
        // `executeTransactionSyncV2` and need BOTH members. Sync `transact` settles on
        // the zone-authority rail (no vault signature), so it is not wrapped. The vault
        // settles signatureless via the SPP zone-authority rail either way.
        let proposer_member = Keypair::new();
        let proposer_member_b = Keypair::new();
        rpc.airdrop(&proposer_member.pubkey(), 5_000_000_000)?;
        rpc.airdrop(&proposer_member_b.pubkey(), 5_000_000_000)?;
        let (proposer_settings, _) = smart_account::settings_pda(PROPOSER_SETTINGS_SEED);
        let (proposer_vault, _) = smart_account::smart_account_pda(&proposer_settings, 0);
        let create_proposer_ix = smart_account::create_smart_account_ix(
            &payer.pubkey(),
            &smart_account::treasury_pda(),
            PROPOSER_SETTINGS_SEED,
            None,
            &[
                SmartAccountSigner {
                    key: proposer_member.pubkey(),
                    permissions: Permissions::all(),
                },
                SmartAccountSigner {
                    key: proposer_member_b.pubkey(),
                    permissions: Permissions::all(),
                },
            ],
            2,
            0,
        );
        send_transaction(&mut rpc, &[create_proposer_ix], &payer.pubkey(), &[&payer])?;
        rpc.airdrop(&proposer_vault, 5_000_000_000)?;

        let owner_field = crate::fixture::vault_owner_field();

        // The backend builds its own indexer + RPC handles (same endpoints) so it
        // can fetch ciphertexts and account data independently of the scenario
        // steps. Construction also starts the autonomous settlement crank that
        // discovers, decrypts (via the auditor key), and settles pending `Proposal`
        // PDAs on the smart-account rail; dropping the World stops it.
        let prover_url =
            std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".into());
        let backend_indexer_url =
            std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
        let backend_rpc_url =
            std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
        let backend = SquadsBackend::new_with_crank(
            crate::fixture::auditor_secret(),
            co_signer.insecure_clone(),
            Address::new_from_array(zone_config_pda().to_bytes()),
            Address::new_from_array(tree.pubkey().to_bytes()),
            prover_url,
            backend_indexer_url,
            backend_rpc_url,
        );

        Ok(Self {
            rpc,
            indexer,
            assets: AssetRegistry::default(),
            payer,
            authority,
            tree: tree.pubkey(),
            zone_auth,
            spls: Vec::new(),
            deposits: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            protocol_settings: accounts.protocol_settings,
            protocol_vault: accounts.protocol_vault,
            co_signer,
            proposer_settings,
            proposer_vault,
            proposer_member,
            proposer_member_b,
            owner_field,
            pending_proposal: None,
            backend,
        })
    }

    /// Register one SPL asset (idempotent): a mint, the asset counter, the
    /// shielded-pool interface (registry + vault), and a shared payer-owned
    /// funding token account.
    pub(crate) fn ensure_spl_asset(&mut self) -> Result<()> {
        if !self.spls.is_empty() {
            return Ok(());
        }
        let payer = self.payer.insecure_clone();
        let authority = self.authority.insecure_clone();
        let protocol_vault = self.protocol_vault;
        let protocol_settings = self.protocol_settings;
        let asset_id = FIRST_SPL_ASSET_ID;

        let mint = create_mint(&self.rpc, &payer)?;
        self.backend
            .register_asset(asset_id, Address::new_from_array(mint.to_bytes()));

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
        assert_create_spl_interface(&self.rpc, &registry, &vault, &mint, asset_id, asset_id + 1)?;

        self.assets
            .insert(asset_id, Address::new_from_array(mint.to_bytes()))
            .map_err(|e| anyhow!("register SPL asset: {e}"))?;
        self.spls.push(SplAsset { mint });
        Ok(())
    }

    pub(crate) fn spl_asset(&self) -> Result<SplAsset> {
        self.spls
            .first()
            .copied()
            .ok_or_else(|| anyhow!("no SPL asset registered"))
    }

    /// Both members of the 2-of-2 proposer smart account, in signing order. Passed
    /// as the `executeTransactionSyncV2` threshold signers and signed on the outer
    /// transaction.
    pub(crate) fn proposer_member_pubkeys(&self) -> [Pubkey; 2] {
        [
            self.proposer_member.pubkey(),
            self.proposer_member_b.pubkey(),
        ]
    }

    /// The backend-decrypted unspent UTXOs of `asset_id` for `name` (auditor key).
    pub(crate) fn backend_utxos(&self, name: &str, asset_id: u64) -> Result<Vec<DecryptedUtxo>> {
        let response = self
            .backend
            .get_balances(GetBalancesRequest {
                viewing_key_account: self.viewing_key_account_address(name),
                skip_utxos: false,
                signature: [0u8; 64],
            })
            .map_err(|e| anyhow!("get_balances: {e}"))?;
        Ok(response
            .balances
            .into_iter()
            .find(|balance| balance.asset_id == asset_id)
            .map(|balance| balance.utxos)
            .unwrap_or_default())
    }

    /// Poll the backend until at least `min_count` unspent UTXOs of `asset_id` are
    /// decryptable for `name` (deposits must be indexed first), or time out.
    pub(crate) fn wait_for_utxos(
        &self,
        name: &str,
        asset_id: u64,
        min_count: usize,
    ) -> Result<Vec<DecryptedUtxo>> {
        let started = Instant::now();
        loop {
            let utxos = self.backend_utxos(name, asset_id)?;
            if utxos.len() >= min_count {
                return Ok(utxos);
            }
            if started.elapsed() > Duration::from_secs(30) {
                return Err(anyhow!(
                    "{name} did not reach {min_count} unspent UTXOs of asset {asset_id} in time (have {})",
                    utxos.len()
                ));
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// Poll the backend until `name` holds EXACTLY ONE unspent UTXO of `asset_id`
    /// whose amount equals `expected_amount` (the auto-merge crank consolidates all
    /// spendable UTXOs of an asset into one), or time out. When deposits index at
    /// staggered times the crank consolidates in more than one merge round (each a
    /// full proof + settlement through a possibly-cold prover), so this allows the
    /// same window as the proposal-settle wait rather than a single-round budget.
    pub(crate) fn wait_for_consolidated(
        &self,
        name: &str,
        asset_id: u64,
        expected_amount: u64,
    ) -> Result<DecryptedUtxo> {
        let started = Instant::now();
        loop {
            let utxos = self.backend_utxos(name, asset_id)?;
            if let [utxo] = utxos.as_slice() {
                if utxo.amount == expected_amount {
                    return Ok(*utxo);
                }
            }
            if started.elapsed() > Duration::from_secs(120) {
                let amounts: Vec<u64> = utxos.iter().map(|utxo| utxo.amount).collect();
                return Err(anyhow!(
                    "{name} did not consolidate asset {asset_id} into one UTXO of {expected_amount} in time (have {amounts:?})"
                ));
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// Poll until the background crank settles (and closes) the proposal PDA, or
    /// time out. A settled proposal is closed to its rent recipient, so the account
    /// disappearing is the settlement signal.
    pub(crate) fn wait_for_proposal_settled(&self, address: Pubkey) -> Result<()> {
        let addr = Address::new_from_array(address.to_bytes());
        let started = Instant::now();
        loop {
            if self.rpc.get_account(addr)?.is_none() {
                return Ok(());
            }
            if started.elapsed() > Duration::from_secs(120) {
                return Err(anyhow!("crank did not settle proposal {address} in time"));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}
