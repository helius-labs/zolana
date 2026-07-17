use anyhow::{anyhow, Result};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{spawn_prover, ProverClient, Rpc, SolanaRpc, ZolanaClient, ZolanaIndexer};
use zolana_interface::{
    instruction::{CreateProtocolConfig, CreateTree},
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_program_test::system_create_account_ix;
use zolana_test_utils::{
    localnet::LocalnetValidator,
    smart_account::{self, StandardSigners},
};
use zolana_transaction::{instructions::types::SppProofInputUtxo, Address, AssetRegistry, Wallet};

pub mod wallet;
pub use wallet::{Confirmation, TestWallet};

pub const DEPOSIT_AMOUNT: u64 = 1_000_000_000;
pub const TRANSFER_AMOUNT: u64 = 300_000_000;
pub const WITHDRAW_AMOUNT: u64 = 300_000_000;

pub struct SetupContext {
    pub rpc: SolanaRpc,
    pub indexer: ZolanaIndexer,
    pub rpc_url: String,
    pub indexer_url: String,
    pub prover_url: String,
    pub tree: Pubkey,
    pub alice: TestWallet,
    pub bob: TestWallet,
}

/// ZolanaClient over a fresh RPC, used to fetch input merkle proofs from the
/// indexer and to submit the assembled `transact` transaction.
pub fn client(ctx: &SetupContext) -> ZolanaClient<SolanaRpc> {
    ZolanaClient::from_urls(
        SolanaRpc::new(ctx.rpc_url.clone()),
        &ctx.indexer_url,
        ctx.prover_url.clone(),
        ctx.tree,
    )
}

pub fn prover(ctx: &SetupContext) -> ProverClient {
    ProverClient::new(ctx.prover_url.clone())
}

/// Spend inputs covering `amount`, each bound to `keypair`'s nullifier key.
pub fn select_inputs(
    wallet: &Wallet,
    keypair: &ShieldedKeypair,
    asset: Address,
    amount: u64,
) -> Result<Vec<SppProofInputUtxo>> {
    let mut inputs = Vec::new();
    let mut total = 0u64;
    for utxo in wallet.balance(asset, None)?.utxos {
        total = total.saturating_add(utxo.amount);
        inputs.push(SppProofInputUtxo::new(utxo, keypair));
        if total >= amount {
            return Ok(inputs);
        }
    }
    Err(anyhow!(
        "insufficient shielded balance: have {total}, need {amount}"
    ))
}

pub fn setup() -> Result<SetupContext> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());

    let spp_program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
    let spp_program_so = format!("{root}/target/deploy/shielded_pool_program.so");
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");
    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");

    LocalnetValidator {
        cli_bin: cli,
        working_dir: root.to_string(),
        rpc_port,
        photon_port,
        ledger: "/tmp/zolana-client-example-test-ledger".to_string(),
        account_dir: "/tmp/zolana-client-example-accounts".to_string(),
        programs: vec![
            (spp_program_id, spp_program_so),
            (
                zolana_user_registry_interface::user_registry_program_id().to_string(),
                user_registry_so,
            ),
            (smart_account_id, smart_account_so),
        ],
    }
    .start();

    std::env::set_var(
        "ZOLANA_PROVER_KEYS_DIR",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../prover/server/proving-keys"),
    );
    spawn_prover()?;

    let rpc_url = std::env::var("ZOLANA_LOCALNET_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    let indexer_url =
        std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| "http://127.0.0.1:8784".to_string());
    let prover_url = std::env::var("ZOLANA_PROVER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3001".to_string());

    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone());

    rpc.assert_executable(&Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID))?;

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

    let payer_address = payer.pubkey();

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
        rpc.create_and_send_transaction(&[ix], payer_address, &[&payer])?;
    }

    rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?;

    let create_config_ix = CreateProtocolConfig {
        authority: accounts.protocol_vault,
        protocol_authority: accounts.protocol_vault,
        tree_creation_authority: accounts.tree_vault,
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault,
        zone_creation_authority: accounts.zone_vault,
        zone_creation_is_permissionless: false,
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
        owner: accounts.tree_vault,
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

    let alice = new_wallet(&mut rpc, tree)?;
    let bob = new_wallet(&mut rpc, tree)?;

    Ok(SetupContext {
        rpc,
        indexer,
        rpc_url,
        indexer_url,
        prover_url,
        tree,
        alice,
        bob,
    })
}

fn new_wallet(rpc: &mut SolanaRpc, tree: Pubkey) -> Result<TestWallet> {
    let solana_keypair = Keypair::new();
    let seed: [u8; 32] = solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let keypair = ShieldedKeypair::from_ed25519(&seed, ViewingKey::new())?;
    rpc.airdrop(&solana_keypair.pubkey(), 10_000_000_000)?;
    Ok(TestWallet::new(keypair, AssetRegistry::default())?.with_tree(tree))
}
