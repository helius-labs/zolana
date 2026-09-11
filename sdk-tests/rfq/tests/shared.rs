use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    spawn_prover, AsyncProverClient, AsyncZolanaIndexer, ComputeBudgetConfig, ProverClient, Rpc,
    SolanaRpc, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateProtocolConfig, CreateSplInterface},
    pda,
    state::{default_tree_fees, nullifier_tree_params},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_program_test::create_tree_instructions;
use zolana_test_utils::{
    localnet::{LocalnetValidator, UpgradeableProgram},
    smart_account::{self, StandardSigners},
    spl::{create_mint, create_token_account, mint_to},
};
use zolana_transaction::{AssetRegistry, Wallet, SOL_MINT};
use zolana_user_registry_interface::user_registry_program_id;
use zolana_wallet::{sync_wallet, Deposit, DepositParams};

// The whole per-transaction budget: the settlement verifies an SPP proof.
const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub const SELL_SOL: u64 = 250_000_000;
pub const BUY_USDC: u64 = 100_000_000;
pub const MAKER_SHIELD_SOL: u64 = SELL_SOL;
pub const TAKER_SHIELD_USDC: u64 = BUY_USDC;

pub struct TestEnv {
    pub client: ZolanaClient<SolanaRpc>,
    pub tree: Pubkey,
    /// Raw id of `tree`, read from its account. Every UTXO commitment folds it
    /// in, so the client and the pool must hash under the same value.
    pub tree_id: u16,
    pub maker: TestWallet,
    pub taker: TestWallet,
    pub usdc_mint: Address,
}

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

pub fn setup() -> Result<TestEnv> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());

    let spp_program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
    let spp_program_so = format!("{root}/target/deploy/shielded_pool_program.so");
    let user_registry_id = user_registry_program_id().to_string();
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");
    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");

    let protocol_vault = smart_account::standard_accounts()
        .protocol_vault
        .to_string();
    LocalnetValidator {
        cli_bin: cli,
        working_dir: root.to_string(),
        rpc_port,
        photon_port,
        ledger: "/tmp/zolana-rfq-inline-test-ledger".to_string(),
        account_dir: "/tmp/zolana-rfq-inline-smart-account-accounts".to_string(),
        programs: vec![
            (user_registry_id, user_registry_so),
            (smart_account_id, smart_account_so),
        ],
    }
    .start_with_upgradeable_programs(&[UpgradeableProgram {
        address: &spp_program_id,
        path: &spp_program_so,
        authority: &protocol_vault,
    }]);

    std::env::set_var(
        "ZOLANA_PROVER_KEYS_DIR",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../prover/server/proving-keys"
        ),
    );
    spawn_prover()?;

    let rpc_url = std::env::var("ZOLANA_LOCALNET_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    let indexer_url =
        std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| "http://127.0.0.1:8784".to_string());
    let mut rpc = SolanaRpc::new(rpc_url);
    let indexer = ZolanaIndexer::new(indexer_url.clone());

    rpc.assert_executable(&Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID))?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    let forester_authority = Keypair::new();
    let merge_authority = Keypair::new();
    let tree_creation_authority = Keypair::new();
    let ring_creation_authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
    rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&forester_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&merge_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&tree_creation_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&ring_creation_authority.pubkey(), 1_000_000_000)?;

    let payer_address = payer.pubkey();

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

    rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?;

    let create_config_ix = CreateProtocolConfig {
        fee_payer: payer.pubkey(),
        initialization_authority: accounts.protocol_vault,
        protocol_authority: accounts.protocol_vault,
        fee_authority: accounts.protocol_vault,
        tree_creation_authority: accounts.tree_vault,
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault,
        ring_creation_authority: accounts.ring_vault,
        ring_activation_is_permissionless: false,
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
        default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .expect("default tree fees"),
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
    let tree_id = zolana_test_utils::nullifier_pda::tree_id(&rpc, &tree)?;

    let usdc_mint = create_mint(&rpc, &payer)?;
    if rpc.get_account(pda::spl_asset_counter())?.is_none() {
        let counter_ix = CreateAssetCounter {
            authority: accounts.protocol_vault,
        }
        .instruction();
        let counter_sync = smart_account::execute_sync_ix(
            &accounts.protocol_settings,
            0,
            &[authority.pubkey()],
            &[counter_ix],
        );
        rpc.create_and_send_transaction(&[counter_sync], payer_address, &[&payer, &authority])?;
    }
    let interface_ix = CreateSplInterface {
        authority: accounts.protocol_vault,
        mint: usdc_mint,
        token_program: zolana_interface::pda::spl_token_program_id(),
    }
    .instruction();
    let interface_sync = smart_account::execute_sync_ix(
        &accounts.protocol_settings,
        0,
        &[authority.pubkey()],
        &[interface_ix],
    );
    rpc.create_and_send_transaction(&[interface_sync], payer_address, &[&payer, &authority])?;

    let usdc_asset_id = 2u64;
    let mut assets = AssetRegistry::default();
    assets.insert(usdc_asset_id, usdc_mint)?;

    let usdc_funding = create_token_account(&rpc, &payer, &usdc_mint, &payer.pubkey())?;
    mint_to(&rpc, &payer, &usdc_mint, &usdc_funding, 1_000_000_000)?;

    let maker_solana_keypair = Keypair::new();
    let maker_seed: [u8; 32] = maker_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let maker_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&maker_seed))?;
    rpc.airdrop(&maker_solana_keypair.pubkey(), 10_000_000_000)?;

    let taker_solana_keypair = Keypair::new();
    rpc.airdrop(&taker_solana_keypair.pubkey(), 10_000_000_000)?;
    let taker_seed: [u8; 32] = taker_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let taker_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&taker_seed))?;

    Deposit::new(DepositParams {
        recipient: &maker_shielded_keypair.shielded_address()?,
        asset: SOL_MINT,
        amount: MAKER_SHIELD_SOL,
        spl_token_account: None,
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?
    .send(&rpc, &payer, tree, &payer)?;
    Deposit::new(DepositParams {
        recipient: &taker_shielded_keypair.shielded_address()?,
        asset: usdc_mint,
        amount: TAKER_SHIELD_USDC,
        spl_token_account: Some(usdc_funding),
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?
    .send(&rpc, &payer, tree, &payer)?;

    let maker_address = maker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("maker address: {e:?}"))?;
    let taker_address = taker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("taker address: {e:?}"))?;

    let mut maker_wallet =
        Wallet::new(maker_address, assets.clone()).map_err(|e| anyhow!("maker wallet: {e:?}"))?;
    sync_wallet(&mut maker_wallet, &maker_shielded_keypair, &indexer)
        .map_err(|e| anyhow!("sync maker deposit: {e:?}"))?;

    let mut taker_wallet =
        Wallet::new(taker_address, assets.clone()).map_err(|e| anyhow!("taker wallet: {e:?}"))?;
    sync_wallet(&mut taker_wallet, &taker_shielded_keypair, &indexer)
        .map_err(|e| anyhow!("sync taker deposit: {e:?}"))?;

    let client = ZolanaClient::new(
        rpc,
        indexer,
        ProverClient::default(),
        AsyncZolanaIndexer::new(indexer_url),
        AsyncProverClient::default(),
        tree,
    );

    Ok(TestEnv {
        client,
        tree,
        tree_id,
        maker: TestWallet {
            wallet: maker_wallet,
            keypair: maker_shielded_keypair,
        },
        taker: TestWallet {
            wallet: taker_wallet,
            keypair: taker_shielded_keypair,
        },
        usdc_mint,
    })
}

// Submit the maker/taker co-signed settlement as a transaction **v1** message:
// its 4096-byte limit is what holds an RFQ transact, which no longer fits a
// 1232-byte legacy packet. v1 has no address lookup table, and it carries the
// compute ceilings in the message header rather than in a compute-budget
// instruction. An unset ceiling means zero, not a default, so both are written.
pub fn send_cosigned_v1(
    rpc: &SolanaRpc,
    payer: &dyn Signer,
    cosigner: &dyn Signer,
    ix: Instruction,
) -> Result<Signature> {
    Ok(rpc.create_and_send_v1_transaction(
        std::slice::from_ref(&ix),
        payer.pubkey(),
        &[payer, cosigner],
        ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
    )?)
}
