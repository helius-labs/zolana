//! Localnet bring-up shared by the custom-ring test binaries.
//!
//! Mirrors `sdk-tests/zk-program-swap/test/tests/shared.rs`. SOL settles
//! through `zolana_interface::SOL_INTERFACE`, a system-owned PDA with a
//! hardcoded address that no instruction has to create, and
//! `AssetRegistry::default()` already carries SOL as asset id 1. The bring-up
//! also registers one SPL mint, named USDC in the tests, under asset id 2,
//! with the mint authority parked on the payer.

use std::path::Path;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use custom_ring_interface::RULES;
use custom_ring_sdk::{
    CreateConfig, CreatePolicy, CustomRing, InitSppRingConfig, V0WithLookupTable,
    TRANSACT_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_rent::Rent;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    prover::SERVER_ADDRESS, AsyncProverClient, AsyncZolanaIndexer, ClientError, ProverClient, Rpc,
    SolanaRpc, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::{
    instruction::{CreateProtocolConfig, CreateTree},
    pda,
    state::{tree_account_size, SplAssetCounter},
    DEFAULT_TREE_ADDRESS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{P256Pubkey, ShieldedKeypair};
use zolana_program_test::system_create_account_ix;
use zolana_ring_policy::ListId;
use zolana_test_utils::{
    localnet::{isolated_temp_path, LocalnetValidator, UpgradeableProgram, WorkspaceArtifacts},
    prover::spawn_workspace_prover,
    smart_account::{self, StandardSigners},
    spl::{create_mint, RegisterSplAsset},
};
use zolana_transaction::{AssetRegistry, Wallet};
use zolana_user_registry_interface::user_registry_program_id;

/// Funds the fee payer for the whole bootstrap (smart accounts, protocol
/// config, tree allocation) plus every deposit a test drives through it.
pub const PAYER_AIRDROP: u64 = 100_000_000_000;
/// Each protocol signer only ever pays transaction fees.
pub const SIGNER_AIRDROP: u64 = 1_000_000_000;
/// The Squads protocol vault pays rent for the accounts its `execute_sync`
/// instructions create.
pub const PROTOCOL_VAULT_AIRDROP: u64 = 5_000_000_000;
/// Each actor signs its own ring deposits and transacts, and the deposits move
/// real lamports out of this balance.
pub const ACTOR_AIRDROP: u64 = 10_000_000_000;
/// The bring-up registers USDC first.
pub const USDC_ASSET_ID: u64 = SplAssetCounter::FIRST_ASSET_ID;
/// A live localnet with the protocol bootstrapped and two funded actors. The
/// custom-ring program's own config account is NOT created here: that is the
/// first step of the lifecycle under test.
pub struct TestEnv {
    pub client: ZolanaClient<SolanaRpc>,
    pub rpc_url: String,
    pub indexer_url: String,
    /// Fee payer for bootstrap and for instructions no actor must sign, also
    /// the USDC mint authority.
    pub payer: Keypair,
    pub tree: Address,
    pub usdc_mint: Address,
    pub assets: AssetRegistry,
    pub sender: TestWallet,
    pub recipient: TestWallet,
    tree_creation_authority: Keypair,
    standard_accounts: smart_account::StandardAccounts,
}

enum TreeSlot<'a> {
    /// Allocated in genesis at `DEFAULT_TREE_ADDRESS`, `CreateTree` takes it unsigned.
    Fixture,
    Fresh(&'a Keypair),
}

impl TestEnv {
    /// Allocate and register a second SPP tree owned by the shielded pool.
    pub fn create_registered_tree(&self) -> Result<Address> {
        let tree = Keypair::new();
        self.register_tree(TreeSlot::Fresh(&tree))
    }

    /// The tree the cli names by default.
    pub fn register_default_tree(&self) -> Result<Address> {
        self.register_tree(TreeSlot::Fixture)
    }

    fn register_tree(&self, slot: TreeSlot<'_>) -> Result<Address> {
        let rpc = self.client.rpc();
        let mut instructions = Vec::with_capacity(2);
        let mut signers: Vec<&dyn Signer> = vec![&self.payer, &self.tree_creation_authority];
        let tree = match slot {
            TreeSlot::Fixture => Address::from_str_const(DEFAULT_TREE_ADDRESS),
            TreeSlot::Fresh(keypair) => {
                let rent = rpc
                    .get_minimum_balance_for_rent_exemption(tree_account_size())
                    .map_err(|e| anyhow!("{e}"))?;
                instructions.push(system_create_account_ix(
                    &self.payer.pubkey(),
                    &keypair.pubkey(),
                    rent,
                    tree_account_size() as u64,
                    &pda::shielded_pool_program_id(),
                ));
                signers.push(keypair);
                keypair.pubkey()
            }
        };
        let create_tree_ix = CreateTree {
            authority: self.standard_accounts.tree_vault,
            tree,
        }
        .instruction();
        instructions.push(smart_account::execute_sync_ix(
            &self.standard_accounts.tree_settings,
            0,
            &[self.tree_creation_authority.pubkey()],
            &[create_tree_ix],
        ));
        rpc.create_and_send_transaction(&instructions, self.payer.pubkey(), &signers)?;
        Ok(tree)
    }

    pub fn fund(&self, recipient: Address, lamports: u64) -> Result<()> {
        send(
            self.client.rpc(),
            &self.payer,
            &[solana_system_interface::instruction::transfer(
                &self.payer.pubkey(),
                &recipient,
                lamports,
            )],
        )?;
        Ok(())
    }

    pub fn funded_keypair(&self) -> Result<Keypair> {
        let keypair = Keypair::new();
        self.fund(keypair.pubkey(), SIGNER_AIRDROP)?;
        Ok(keypair)
    }
}

/// Each actor is one ed25519 identity: `ShieldedKeypair` implements
/// `solana_signer::Signer` over the same key, so it is both the shielded owner
/// and the Solana fee payer for its own transactions.
pub struct TestWallet {
    pub wallet: Wallet,
    pub keypair: ShieldedKeypair,
}

impl std::ops::Deref for TestWallet {
    type Target = Wallet;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl std::ops::DerefMut for TestWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}

pub enum Tier {
    AuditOnly,
    Policy {
        entries_tree: Address,
        shared_sources: Vec<(ListId, CustomRing)>,
    },
}

impl Tier {
    /// Every referenced list served from the ring's own entries.
    pub fn policy(entries_tree: Address) -> Self {
        Self::Policy {
            entries_tree,
            shared_sources: Vec::new(),
        }
    }
}

/// The payer doubles as the config authority.
pub struct RegisterRing<'a> {
    pub ring: CustomRing,
    pub payer: &'a Keypair,
    pub auditor_pubkey: P256Pubkey,
    pub tier: Tier,
}

#[must_use]
pub struct ConfiguredRing<'a> {
    ring: CustomRing,
    payer: &'a Keypair,
    tier: Tier,
}

#[must_use]
pub struct PinnedRing<'a> {
    payer: &'a Keypair,
    registration: Instruction,
}

impl<'a> RegisterRing<'a> {
    pub fn send(self, rpc: &SolanaRpc) -> Result<()> {
        self.pin(rpc)?.register(rpc)
    }

    pub fn pin(self, rpc: &SolanaRpc) -> Result<PinnedRing<'a>> {
        self.configure(rpc)?.pin(rpc)
    }

    pub fn configure(self, rpc: &SolanaRpc) -> Result<ConfiguredRing<'a>> {
        let authority = self.payer.pubkey();
        send(
            rpc,
            self.payer,
            &[CreateConfig {
                ring: self.ring,
                payer: authority,
                authority,
                auditor_pubkey: self.auditor_pubkey,
                has_policy: matches!(self.tier, Tier::Policy { .. }),
            }
            .instruction()?],
        )?;
        Ok(ConfiguredRing {
            ring: self.ring,
            payer: self.payer,
            tier: self.tier,
        })
    }
}

impl<'a> ConfiguredRing<'a> {
    /// The program refuses it for a policy ring until the policy is pinned.
    pub fn registration(&self) -> Instruction {
        let authority = self.payer.pubkey();
        InitSppRingConfig {
            ring: self.ring,
            payer: authority,
            authority,
            has_policy: matches!(self.tier, Tier::Policy { .. }),
        }
        .instruction()
    }

    pub fn pin(self, rpc: &SolanaRpc) -> Result<PinnedRing<'a>> {
        let registration = self.registration();
        let authority = self.payer.pubkey();
        if let Tier::Policy {
            entries_tree,
            shared_sources,
        } = self.tier
        {
            send(
                rpc,
                self.payer,
                &[CreatePolicy {
                    ring: self.ring,
                    payer: authority,
                    authority,
                    entries_tree,
                    rules: &RULES,
                    shared_sources,
                }
                .instruction()?],
            )?;
        }
        Ok(PinnedRing {
            payer: self.payer,
            registration,
        })
    }
}

impl PinnedRing<'_> {
    pub fn register(self, rpc: &SolanaRpc) -> Result<()> {
        send(rpc, self.payer, &[self.registration])?;
        Ok(())
    }
}

/// URL the prover client talks to. Mirrors the client's own resolution
/// (`ZOLANA_PROVER_URL` overrides the default) so a per-clone port offset is
/// respected here too.
pub fn prover_url() -> String {
    match std::env::var("ZOLANA_PROVER_URL") {
        Ok(url) if !url.trim().is_empty() => url.trim().to_string(),
        _ => SERVER_ADDRESS.to_string(),
    }
}

pub fn setup() -> Result<TestEnv> {
    setup_with_extra_rings(&[])
}

/// Every extra address deploys the same ring image again as a full second ring,
/// every PDA derives from the runtime program id.
pub fn setup_with_extra_rings(extra_ring_programs: &[Address]) -> Result<TestEnv> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let artifacts = WorkspaceArtifacts::new(root);
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());

    let ring_program = custom_ring_program_id()?;
    let ring_program_so = ring_program_so();
    let spp_program = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let spp_program_so = artifacts.path("target/deploy/shielded_pool_program.so");
    let user_registry = user_registry_program_id();
    let user_registry_so = artifacts.path("target/deploy/zolana_user_registry.so");
    let smart_account = smart_account::SMART_ACCOUNT_PROGRAM_ID;
    let smart_account_so = artifacts.path("target/deploy/squads_smart_account_program.so");

    let payer = Keypair::new();
    let payer_address = payer.pubkey();
    let validator = LocalnetValidator {
        // The Squads smart-account program is loaded for the protocol bootstrap
        // only: `CreateProtocolConfig` and `CreateTree` check authorities that the
        // bootstrap parks in Squads vaults, so both are wrapped in
        // `execute_sync_ix`. The custom-ring program never touches a smart account.
        cli_bin: cli,
        working_dir: artifacts.root(),
        rpc_port,
        photon_port,
        ledger: isolated_temp_path("zolana-custom-ring-ledger"),
        account_dir: isolated_temp_path("zolana-custom-ring-smart-accounts"),
        programs: vec![
            (spp_program.to_string(), spp_program_so),
            (user_registry.to_string(), user_registry_so),
            (smart_account.to_string(), smart_account_so),
        ],
    };
    let upgrade_authority = payer_address.to_string();
    let ring_addresses: Vec<String> = std::iter::once(ring_program)
        .chain(extra_ring_programs.iter().copied())
        .map(|address| address.to_string())
        .collect();
    let ring_deployments: Vec<UpgradeableProgram<'_>> = ring_addresses
        .iter()
        .map(|address| UpgradeableProgram {
            address,
            path: &ring_program_so,
            authority: &upgrade_authority,
        })
        .collect();
    write_default_tree_fixture(&validator.account_dir)?;
    validator.start_with_upgradeable_programs(&ring_deployments);

    spawn_workspace_prover();

    let rpc_url = std::env::var("ZOLANA_LOCALNET_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    let indexer_url =
        std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| "http://127.0.0.1:8784".to_string());
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone());

    let authority = Keypair::new();
    let forester_authority = Keypair::new();
    let merge_authority = Keypair::new();
    let tree_creation_authority = Keypair::new();
    let ring_creation_authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), PAYER_AIRDROP)?;
    rpc.airdrop(&authority.pubkey(), SIGNER_AIRDROP)?;
    rpc.airdrop(&forester_authority.pubkey(), SIGNER_AIRDROP)?;
    rpc.airdrop(&merge_authority.pubkey(), SIGNER_AIRDROP)?;
    rpc.airdrop(&tree_creation_authority.pubkey(), SIGNER_AIRDROP)?;
    rpc.airdrop(&ring_creation_authority.pubkey(), SIGNER_AIRDROP)?;

    let accounts = smart_account::standard_accounts();
    for ix in accounts.create_ixs(
        &payer.pubkey(),
        StandardSigners {
            protocol: authority.pubkey(),
            forester: forester_authority.pubkey(),
            merge: merge_authority.pubkey(),
            tree: tree_creation_authority.pubkey(),
            ring: ring_creation_authority.pubkey(),
        },
    ) {
        rpc.create_and_send_transaction(&[ix], payer_address, &[&payer])?;
    }

    rpc.airdrop(&accounts.protocol_vault, PROTOCOL_VAULT_AIRDROP)?;

    // `ring_creation_is_permissionless` is the one bootstrap setting this
    // example needs to differ from the swap harness: with it set, the
    // custom-ring program can register its `ring_auth` PDA as an SPP ring
    // config with a plain payer, instead of the ring Squads vault having to
    // co-sign `create_ring_config`. Same precedent as the ring suite's
    // `BootstrapConfig` (program-tests/test-utils/src/ring/mod.rs).
    let create_config_ix = CreateProtocolConfig {
        authority: accounts.protocol_vault,
        protocol_authority: accounts.protocol_vault.to_bytes().into(),
        tree_creation_authority: accounts.tree_vault.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault.to_bytes().into(),
        ring_creation_authority: accounts.ring_vault.to_bytes().into(),
        ring_creation_is_permissionless: true,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction();
    let create_config_sync = smart_account::execute_sync_ix(
        &accounts.protocol_settings,
        0,
        &[authority.pubkey()],
        &[create_config_ix],
    );
    rpc.create_and_send_transaction(&[create_config_sync], payer_address, &[&payer, &authority])?;

    let tree = Keypair::new();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(tree_account_size())
        .map_err(|e| anyhow!("{e}"))?;
    let alloc_ix = system_create_account_ix(
        &payer.pubkey(),
        &tree.pubkey(),
        rent,
        tree_account_size() as u64,
        &pda::shielded_pool_program_id(),
    );
    let create_tree_ix = CreateTree {
        authority: accounts.tree_vault,
        tree: tree.pubkey(),
    }
    .instruction();
    let create_tree_sync = smart_account::execute_sync_ix(
        &accounts.tree_settings,
        0,
        &[tree_creation_authority.pubkey()],
        &[create_tree_ix],
    );
    rpc.create_and_send_transaction(
        &[alloc_ix, create_tree_sync],
        payer_address,
        &[&payer, &tree, &tree_creation_authority],
    )?;

    let tree = tree.pubkey();

    let usdc_mint = create_mint(&rpc, &payer)?;
    RegisterSplAsset {
        payer: &payer,
        authority: &authority,
        protocol_settings: accounts.protocol_settings,
        protocol_vault: accounts.protocol_vault,
        mint: usdc_mint,
        token_program: pda::spl_token_program_id(),
    }
    .send(&rpc)?;

    let mut assets = AssetRegistry::default();
    assets.insert(USDC_ASSET_ID, usdc_mint)?;

    let sender = new_actor(&mut rpc, &assets)?;
    let recipient = new_actor(&mut rpc, &assets)?;

    let client = ZolanaClient::new(
        rpc,
        indexer,
        ProverClient::default(),
        AsyncZolanaIndexer::new(indexer_url.clone()),
        AsyncProverClient::default(),
        tree,
    );

    Ok(TestEnv {
        client,
        rpc_url,
        indexer_url,
        payer,
        tree,
        usdc_mint,
        assets,
        sender,
        recipient,
        tree_creation_authority,
        standard_accounts: accounts,
    })
}

pub fn custom_ring_program_id() -> Result<Address> {
    let id = match std::env::var("CUSTOM_RING_PROGRAM_ID") {
        Ok(id) if !id.trim().is_empty() => id,
        _ => zolana_test_utils::localnet::CUSTOM_RING_PROGRAM_ADDRESS.to_string(),
    };
    id.trim()
        .parse()
        .map_err(|e| anyhow!("CUSTOM_RING_PROGRAM_ID {id} failed {e}"))
}

pub fn ring_program_so() -> String {
    let artifacts = WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    std::env::var("CUSTOM_RING_PROGRAM_SO")
        .unwrap_or_else(|_| artifacts.path("target/deploy/custom_ring_program.so"))
}

/// The default tree account as the release snapshots ship it.
fn write_default_tree_fixture(account_dir: &str) -> Result<()> {
    let size = tree_account_size();
    let json = format!(
        r#"{{"pubkey":"{DEFAULT_TREE_ADDRESS}","account":{{"lamports":{},"data":["{}","base64"],"owner":"{}","executable":false,"rentEpoch":{}}}}}"#,
        Rent::default().minimum_balance(size),
        STANDARD.encode(vec![0u8; size]),
        pda::shielded_pool_program_id(),
        u64::MAX,
    );
    std::fs::create_dir_all(account_dir)?;
    std::fs::write(
        Path::new(account_dir).join(format!("{DEFAULT_TREE_ADDRESS}.json")),
        json,
    )?;
    Ok(())
}

/// A fresh ed25519 actor: one keypair funded on chain, its shielded address,
/// and an empty wallet over the shared asset registry.
fn new_actor(rpc: &mut SolanaRpc, assets: &AssetRegistry) -> Result<TestWallet> {
    let keypair = ShieldedKeypair::new_ed25519()?;
    rpc.airdrop(&keypair.pubkey(), ACTOR_AIRDROP)?;
    let address = keypair
        .shielded_address()
        .map_err(|e| anyhow!("actor address failed {e:?}"))?;
    let wallet =
        Wallet::new(address, assets.clone()).map_err(|e| anyhow!("actor wallet failed {e:?}"))?;
    Ok(TestWallet { wallet, keypair })
}

/// Send instructions as a legacy transaction paid and signed by `payer`.
pub fn send(rpc: &SolanaRpc, payer: &dyn Signer, ixs: &[Instruction]) -> Result<Signature> {
    let instructions = std::iter::once(ComputeBudgetInstruction::set_compute_unit_limit(
        TRANSACT_COMPUTE_UNIT_LIMIT,
    ))
    .chain(ixs.iter().cloned())
    .collect::<Vec<_>>();
    let signature = rpc.create_and_send_transaction(&instructions, payer.pubkey(), &[payer])?;
    Ok(signature)
}

/// Submit a single (large) instruction as a v0 transaction behind a throwaway
/// address lookup table. Prepends a 1.4M CU budget; `payer` signs and pays.
/// The same submission path for a transaction that must be REJECTED: returns the
/// runtime's typed failure so a test can assert the exact program error code and
/// the failing instruction index (`Rejection::custom(..).at(1)`, index 1 because
/// of the prepended compute budget). [`send_v0_with_lookup_table`] stringifies
/// the error, which cannot be asserted on.
pub fn send_v0_expecting_rejection(
    rpc: &SolanaRpc,
    payer: &dyn Signer,
    ix: Instruction,
) -> Result<ClientError> {
    let tx = V0WithLookupTable {
        payer,
        signers: &[],
        instruction: ix,
    }
    .build(rpc)?;
    match rpc.client().send_and_confirm_transaction(&tx) {
        Ok(signature) => Err(anyhow!(
            "transaction {signature} was expected to be rejected but landed"
        )),
        Err(source) => Ok(ClientError::SolanaRpcTransaction {
            operation: "send v0",
            source,
        }),
    }
}

/// Over [`send`], the failing instruction sits at index 1 behind its compute budget.
#[must_use]
pub struct ExpectRejection<'a> {
    pub payer: &'a dyn Signer,
    pub instructions: &'a [Instruction],
}

impl ExpectRejection<'_> {
    pub fn send(self, rpc: &SolanaRpc) -> Result<ClientError> {
        match send(rpc, self.payer, self.instructions) {
            Ok(signature) => Err(anyhow!(
                "transaction {signature} was expected to be rejected but landed"
            )),
            Err(error) => error.downcast::<ClientError>(),
        }
    }
}
