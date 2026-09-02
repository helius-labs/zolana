//! Localnet bring-up shared by the custom-ring test binaries.
//!
//! Mirrors `sdk-tests/zk-program-swap/test/tests/shared.rs`, reduced to what a
//! SOL-only ring example needs: no SPL mint, no token accounts, and neither
//! `CreateAssetCounter` nor `CreateSplInterface`. SOL settles through
//! `zolana_interface::SOL_INTERFACE`, a system-owned PDA with a hardcoded
//! address that no instruction has to create, and `AssetRegistry::default()`
//! already carries SOL as asset id 1.

use anyhow::{anyhow, Result};
use custom_ring_sdk::{V0WithLookupTable, TRANSACT_COMPUTE_UNIT_LIMIT};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    prover::SERVER_ADDRESS, AsyncProverClient, AsyncZolanaIndexer, ClientError, ProverClient, Rpc,
    SolanaRpc, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::{
    instruction::CreateProtocolConfig,
    state::{default_tree_fees, nullifier_tree_params},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::create_tree_instructions;
use zolana_test_utils::{
    localnet::{isolated_temp_path, LocalnetValidator, UpgradeableProgram, WorkspaceArtifacts},
    prover::spawn_workspace_prover,
    smart_account::{self, StandardSigners},
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
/// A live localnet with the protocol bootstrapped and two funded actors. The
/// custom-ring program's own config account is NOT created here: that is the
/// first step of the lifecycle under test.
pub struct TestEnv {
    pub client: ZolanaClient<SolanaRpc>,
    pub rpc_url: String,
    pub indexer_url: String,
    /// Fee payer for bootstrap and for instructions no actor must sign.
    pub payer: Keypair,
    pub tree: Address,
    pub assets: AssetRegistry,
    pub sender: TestWallet,
    pub recipient: TestWallet,
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
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let artifacts = WorkspaceArtifacts::new(root);
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());

    let ring_program = custom_ring_program_id()?;
    let ring_program_so = std::env::var("CUSTOM_RING_PROGRAM_SO")
        .unwrap_or_else(|_| artifacts.path("target/deploy/custom_ring_program.so"));
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
    validator.start_with_upgradeable_programs(&[UpgradeableProgram {
        address: &ring_program.to_string(),
        path: &ring_program_so,
        authority: &payer_address.to_string(),
    }]);

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
        fee_authority: accounts.protocol_vault.to_bytes().into(),
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

    let tree_creation = create_tree_instructions(
        &rpc,
        &payer.pubkey(),
        &accounts.tree_vault,
        nullifier_tree_params(),
        default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size),
    )?;
    let create_tree_syncs = smart_account::execute_sync_each(
        &accounts.tree_settings,
        0,
        &[tree_creation_authority.pubkey()],
        &tree_creation.instructions,
    );
    rpc.create_and_send_transaction(
        &create_tree_syncs,
        payer_address,
        &[&payer, &tree_creation_authority],
    )?;

    let tree = tree_creation.tree;

    let assets = AssetRegistry::default();

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
        assets,
        sender,
        recipient,
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
