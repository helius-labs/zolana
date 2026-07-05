//! The cucumber `World`: localnet/indexer handles, per-recipient deposit state,
//! and setup. Each scenario boots a fresh validator + Photon, initializes SPP's
//! protocol config and a state tree, creates the Squads zone's own `zone_config`,
//! and registers it with SPP via `init_spp_zone_config` (a real CPI) so the zone
//! `deposit` can settle through SPP. The lifecycle operations live next to their
//! cucumber steps in `steps/*`, each adding an `impl SquadsLifecycleWorld` block;
//! the fields and accessors here are `pub(crate)` so those modules can drive it.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use solana_account::Account;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
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
use zolana_squads_client::{
    RequestCreateViewingKeyAccountRequest, RequestCreateViewingKeyAccountResponse, SquadsBackend,
};
use zolana_squads_interface::{
    constants::OWNER_KIND_KEYPAIR,
    instruction::{
        builders::{CreateZoneConfig, InitSppZoneConfig},
        CreateZoneConfigIxData,
    },
    SQUADS_ZONE_PROGRAM_ID, ZONE_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};
use zolana_test_utils::{
    smart_account::{self, execute_sync_ix, StandardSigners},
    spl::{create_mint, create_token_account},
    test_validator_asserts::assert_create_spl_interface,
};
use zolana_transaction::AssetRegistry;

use crate::fixture::owner_keypair;

use crate::localnet::{
    restart_localnet, send_transaction, start_prover, DEFAULT_INDEXER_URL, DEFAULT_RPC_URL,
};

// SOL occupies asset id 1; the first registered SPL mint gets id 2.
const FIRST_SPL_ASSET_ID: u64 = 2;

/// An SPL asset a scenario registers: its mint, the vault the deposit credits,
/// and the shared funding token account (owned by the payer).
#[derive(Clone, Copy)]
pub(crate) struct SplAsset {
    pub(crate) mint: Pubkey,
    pub(crate) user_token: Pubkey,
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
/// transition (and a later withdrawal can reconstruct the deposited zone UTXO).
#[derive(Clone)]
pub(crate) struct DepositRecord {
    pub(crate) signature: Signature,
    pub(crate) view_tag: [u8; 32],
    pub(crate) blinding: [u8; 31],
    pub(crate) asset: Address,
    pub(crate) tree_before: Account,
    pub(crate) settlement: SettlementSnapshot,
}

/// The pre-withdrawal settlement-account snapshots a withdrawal assert compares
/// against.
#[derive(Clone)]
pub(crate) enum WithdrawalSettlement {
    Sol {
        sol_interface: Pubkey,
        sol_interface_before: Account,
        recipient: Pubkey,
        recipient_before: Account,
    },
    Spl {
        vault: Pubkey,
        vault_before: Account,
        recipient_token: Pubkey,
        recipient_token_before: Account,
    },
}

/// What a withdrawal recorded, so the separate assert step can verify the on-chain
/// fund movement out of the pool. The backend builds and settles the proof
/// internally and returns only the assembled instruction, so no proof internals
/// (change leaf / nullifier) are available here; the assert checks fund movement
/// plus the sender's remaining balance via `getBalances`.
#[derive(Clone)]
pub(crate) struct WithdrawalRecord {
    pub(crate) withdrawn: u64,
    pub(crate) settlement: WithdrawalSettlement,
}

/// What a `(2, 2)` transfer recorded, so the separate assert step can verify the
/// outcome: the recipient's decrypted balance rises by `transferred`, the sender's
/// falls to its `change_amount`, and no funds leave the pool. The backend builds and
/// settles the proof internally, so balances are read via `getBalances` (auditor).
#[derive(Clone)]
pub(crate) struct TransferRecord {
    pub(crate) sender: String,
    pub(crate) transferred: u64,
    pub(crate) change_amount: u64,
    /// The pool settlement account (SOL interface) balance before, to assert no
    /// funds left the pool.
    pub(crate) pool_before: Account,
    pub(crate) pool_account: Pubkey,
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
    pub(crate) transfers: BTreeMap<String, TransferRecord>,
    pub(crate) protocol_settings: Pubkey,
    pub(crate) protocol_vault: Pubkey,
    /// The configured zone co-signer, which the backend uses as its relayer /
    /// fee payer for every `transact` it builds.
    pub(crate) co_signer: Keypair,
    /// Names whose viewing key account has already been created at runtime, so the
    /// idempotent creation step is a no-op on re-entry.
    pub(crate) viewing_key_accounts: std::collections::BTreeSet<String>,
    /// The Squads backend mock: holds the auditor key and decrypts every account's
    /// balances via each account's shared viewing key (user owner keys sign only).
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
        // concurrently with the localnet restart. Proof-gated `transact` scenarios
        // (the backend proves through it) need it; the proofless `deposit` never
        // calls it.
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
        // and decrypts balances with the auditor secret. The co-signer keypair is the
        // backend's relayer / fee payer for every `transact` and the rent payer for
        // runtime viewing-key-account creation.
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
                // The backend crank is the zone co-signer; whitelist it as a merge
                // authority so its auto-merge `merge_transact` is accepted on-chain.
                merge_authorities: vec![Address::new_from_array(co_signer.pubkey().to_bytes())],
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

        // The backend builds its own indexer + RPC handles (same endpoints) so it
        // can fetch ciphertexts and account data independently of the scenario
        // steps. Its relayer / fee payer is the zone co-signer; its auditor secret
        // matches the key configured in `zone_config`. Construction also starts the
        // settlement crank; this suite creates no proposals, so it idles.
        let prover_url =
            std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".into());
        let backend = SquadsBackend::new_with_crank(
            crate::fixture::auditor_secret(),
            co_signer.insecure_clone(),
            Address::new_from_array(zone_config_pda().to_bytes()),
            Address::new_from_array(tree.pubkey().to_bytes()),
            prover_url,
            std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into()),
            std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into()),
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
            transfers: BTreeMap::new(),
            protocol_settings: accounts.protocol_settings,
            protocol_vault: accounts.protocol_vault,
            co_signer,
            viewing_key_accounts: std::collections::BTreeSet::new(),
            backend,
        })
    }

    /// Create `name`'s viewing key account at runtime through the backend's
    /// `requestCreateViewingKeyAccount` (auditor-only, P256 keypair owner: no owner
    /// signer, backend-minted viewing/nullifier secrets). Idempotent. The returned
    /// instruction's rent payer is the backend relayer (co-signer), so the plain
    /// transaction is signed by both the fee payer and the co-signer.
    pub(crate) fn ensure_viewing_key_account(&mut self, name: &str) -> Result<Pubkey> {
        let owner = owner_keypair(name);
        let expected = owner.viewing_key_account();
        if self.viewing_key_accounts.contains(name) {
            return Ok(expected);
        }

        let response = self
            .backend
            .request_create_viewing_key_account(RequestCreateViewingKeyAccountRequest {
                owner: Address::new_from_array(owner.owner_field()),
                recovery_keys: Vec::new(),
                owner_signature: None,
                owner_kind: OWNER_KIND_KEYPAIR,
            })
            .map_err(|e| anyhow!("request create viewing key account: {e}"))?;

        let (viewing_key_account, instruction) = match response {
            RequestCreateViewingKeyAccountResponse::Instruction {
                viewing_key_account,
                instruction,
            } => (
                Pubkey::new_from_array(viewing_key_account.to_bytes()),
                instruction,
            ),
            RequestCreateViewingKeyAccountResponse::Signature { .. } => {
                return Err(anyhow!("backend unexpectedly sent the VKA transaction"));
            }
        };
        if viewing_key_account != expected {
            return Err(anyhow!(
                "backend VKA address {viewing_key_account} != canonical PDA {expected}"
            ));
        }

        // The key-encryption proof verification exceeds the default 200k CU budget.
        let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let payer = self.payer.insecure_clone();
        let co_signer = self.co_signer.insecure_clone();
        send_transaction(
            &mut self.rpc,
            &[budget, instruction],
            &payer.pubkey(),
            &[&payer, &co_signer],
        )?;
        self.viewing_key_accounts.insert(name.to_string());
        Ok(viewing_key_account)
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

        let user_token = create_token_account(&self.rpc, &payer, &mint, &payer.pubkey())?;
        self.assets
            .insert(asset_id, Address::new_from_array(mint.to_bytes()))
            .map_err(|e| anyhow!("register SPL asset: {e}"))?;
        self.spls.push(SplAsset { mint, user_token });
        Ok(())
    }

    pub(crate) fn spl_asset(&self) -> Result<SplAsset> {
        self.spls
            .first()
            .copied()
            .ok_or_else(|| anyhow!("no SPL asset registered"))
    }
}
