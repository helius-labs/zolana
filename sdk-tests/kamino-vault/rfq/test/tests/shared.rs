use anyhow::{anyhow, Result};
use kamino_vault_market_maker::{MakerConfig, MakerSetup, MarketMaker, WatcherConfig};
use kamino_vault_rfq_sdk::{
    kvault::{self, InitVault, VaultAccounts},
    swap::Holdings,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction_status_client_types::EncodedTransaction;
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_interface::{
    instruction::CreateCacheData,
    pda::{self, spl_token_program_id},
    state::SplAssetRegistry,
};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_program::instruction::{CreateCache, CreateSplInterface};
use zolana_program_test::{
    fixture,
    instructions::system_create_account_ix,
    localnet::{FixtureLocalnet, LocalnetPaths, LocalnetPorts},
    workspace_path,
};
use zolana_test_utils::wallet::{
    create_associated_token_account, sync_wallet, Deposit, DepositParams, Wallet,
};
use zolana_transaction::AssetRegistry;

use crate::user::User;

pub const FEE_BPS: u64 = 30;
pub const USER_SHIELD_USDC: u64 = 100_000_000;
const USER_UTXOS: u64 = 2;
const MAKER_CACHE_NONCE: u64 = 0;
const MAKER_ACTOR: u8 = 0;
const FIRST_USER_ACTOR: u8 = 1;
const MAKER_CACHE_EXPIRES_AT: i64 = 2_000_000_000;
pub const MARKET_MAKER_PUBLIC_USDC: u64 = 500_000_000;
const COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub struct TestEnv {
    pub localnet: FixtureLocalnet,
    pub user: User,
    pub users: Vec<User>,
    pub market_maker: MarketMaker,
    pub usdc_mint: Address,
    pub vault: VaultAccounts,
}

#[derive(Clone, Copy, Debug)]
pub struct SetupConfig {
    pub test: u16,
    pub extra_users: u8,
    pub lanes: usize,
    pub websocket: bool,
    pub user_usdc: u64,
}

impl SetupConfig {
    pub fn new(test: u16) -> Self {
        Self {
            test,
            extra_users: 0,
            lanes: 1,
            websocket: false,
            user_usdc: USER_SHIELD_USDC,
        }
    }
}

fn watcher(ports: LocalnetPorts, websocket: bool) -> Result<WatcherConfig> {
    if !websocket {
        return Ok(MakerConfig::new(0, FEE_BPS).watcher);
    }
    let port = ports
        .rpc
        .checked_add(1)
        .ok_or_else(|| anyhow!("rpc port {} has no websocket port above it", ports.rpc))?;
    Ok(WatcherConfig::Websocket {
        url: format!("ws://127.0.0.1:{port}"),
    })
}

pub fn blocking<R>(work: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => tokio::task::block_in_place(work),
        Err(_) => work(),
    }
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

impl TestWallet {
    fn new(actor: u8, assets: &AssetRegistry) -> Result<Self> {
        let solana = fixture::actor(actor);
        let seed: [u8; 32] = solana
            .to_bytes()
            .get(..32)
            .ok_or_else(|| anyhow!("ed25519 keypair without a seed"))?
            .try_into()?;
        let keypair = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed))?;
        let wallet = Wallet::new(keypair.shielded_address()?, assets.clone())
            .map_err(|e| anyhow!("wallet of actor {actor}: {e:?}"))?;
        Ok(Self { wallet, keypair })
    }

    pub fn address(&self) -> Address {
        self.keypair.pubkey()
    }

    pub fn sync(&mut self, localnet: &FixtureLocalnet) -> Result<()> {
        sync_wallet(&mut self.wallet, &self.keypair, localnet.client.indexer())
            .map_err(|e| anyhow!("sync wallet {}: {e:?}", self.keypair.pubkey()))?;
        Ok(())
    }

    pub fn holdings(&self, vault: &VaultAccounts) -> Result<Holdings> {
        Ok(Holdings {
            usdc: self.balance(vault.token_mint, None)?.amount,
            shares: self.balance(vault.shares_mint, None)?.amount,
        })
    }
}

fn send(
    rpc: &SolanaRpc,
    instructions: &[Instruction],
    payer: &dyn Signer,
    signers: &[&dyn Signer],
) -> Result<Signature> {
    Ok(rpc.create_and_send_transaction(
        instructions,
        payer.pubkey(),
        signers,
        ComputeBudgetConfig::new(COMPUTE_UNIT_LIMIT),
    )?)
}

pub fn compute_units(rpc: &SolanaRpc, signature: &Signature) -> Result<u64> {
    let confirmed = rpc.fetch_confirmed_transaction(signature)?;
    let meta = confirmed
        .transaction
        .meta
        .ok_or_else(|| anyhow!("transaction {signature} has no metadata"))?;
    Option::<u64>::from(meta.compute_units_consumed)
        .ok_or_else(|| anyhow!("transaction {signature} reports no compute units"))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Landed {
    pub signatures: usize,
    pub programs: Vec<Address>,
}

pub fn landed(rpc: &SolanaRpc, signature: &Signature) -> Result<Landed> {
    let signatures = match rpc
        .fetch_confirmed_transaction(signature)?
        .transaction
        .transaction
    {
        EncodedTransaction::Json(transaction) => transaction.signatures.len(),
        other => return Err(anyhow!("transaction {signature} came back as {other:?}")),
    };
    let programs = rpc
        .fetch_confirmed_instruction_groups(signature)?
        .groups
        .into_iter()
        .map(|group| group.outer.program_id)
        .collect();
    Ok(Landed {
        signatures,
        programs,
    })
}

pub fn public_balances(
    rpc: &SolanaRpc,
    owner: &Address,
    vault: &VaultAccounts,
) -> Result<Vec<u64>> {
    [vault.token_mint, vault.shares_mint]
        .iter()
        .map(|mint| kvault::token_balance(rpc, &pda::associated_token_address(owner, mint)))
        .collect()
}

fn token_transfer_ix(
    source: &Address,
    destination: &Address,
    authority: &Address,
    amount: u64,
) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: spl_token_program_id(),
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

fn create_vault(
    localnet: &FixtureLocalnet,
    payer: &Keypair,
    usdc_mint: Address,
) -> Result<VaultAccounts> {
    let rpc = localnet.client.rpc();
    let vault_keypair = Keypair::new();
    let vault = VaultAccounts::new(vault_keypair.pubkey(), usdc_mint);
    let rent = rpc.get_minimum_balance_for_rent_exemption(kvault::VAULT_STATE_SIZE)?;
    let create = system_create_account_ix(
        &payer.pubkey(),
        &vault.vault,
        rent,
        kvault::VAULT_STATE_SIZE as u64,
        &kvault::PROGRAM_ID,
    );
    let init = InitVault {
        admin: payer.pubkey(),
        admin_token_account: fixture::payer_token_account(),
        accounts: vault,
    }
    .instruction();
    send(rpc, &[create, init], payer, &[payer, &vault_keypair])?;
    Ok(vault)
}

fn register_share_mint(
    localnet: &FixtureLocalnet,
    payer: &Keypair,
    share_mint: Address,
) -> Result<u64> {
    let rpc = localnet.client.rpc();
    let ix = CreateSplInterface {
        authority: payer.pubkey(),
        mint: share_mint,
        token_program: spl_token_program_id(),
    }
    .instruction();
    send(rpc, &[ix], payer, &[payer])?;
    let registry = pda::spl_asset_registry(&share_mint);
    let data = rpc
        .get_account(registry)?
        .ok_or_else(|| anyhow!("share mint registry {registry} missing"))?
        .data;
    Ok(SplAssetRegistry::from_account_bytes(&data)
        .map_err(|e| anyhow!("share mint registry {registry}: {e:?}"))?
        .asset_id)
}

struct Booted {
    localnet: FixtureLocalnet,
    users: Vec<TestWallet>,
    maker: TestWallet,
    usdc_mint: Address,
    vault: VaultAccounts,
}

pub async fn setup(test: u16) -> Result<TestEnv> {
    setup_with(SetupConfig::new(test)).await
}

pub async fn setup_with(config: SetupConfig) -> Result<TestEnv> {
    let ports = LocalnetPorts::for_test(config.test)?;
    let Booted {
        localnet,
        users,
        maker,
        usdc_mint,
        vault,
    } = blocking(|| boot(ports, config))?;
    let market_maker = MarketMaker::start(MakerSetup {
        wallet: maker.wallet,
        keypair: maker.keypair,
        config: MakerConfig {
            base_lanes: config.lanes,
            watcher: watcher(ports, config.websocket)?,
            ..MakerConfig::new(localnet.tree_id, FEE_BPS)
        },
        rpc_url: ports.rpc_url(),
        photon_url: ports.photon_url(),
        tree: localnet.tree,
        assets: vec![usdc_mint, vault.shares_mint],
    })
    .await?;
    let mut users = users
        .into_iter()
        .map(|wallet| User::new(wallet, FEE_BPS))
        .collect::<Vec<_>>()
        .into_iter();
    let user = users
        .next()
        .ok_or_else(|| anyhow!("setup funded no user"))?;
    Ok(TestEnv {
        localnet,
        user,
        users: users.collect(),
        market_maker,
        usdc_mint,
        vault,
    })
}

fn boot(ports: LocalnetPorts, config: SetupConfig) -> Result<Booted> {
    let payer = fixture::payer();
    let localnet = FixtureLocalnet::start_with_accounts(
        "zolana-kamino-vault",
        ports,
        vec![
            (
                kvault::PROGRAM_ID,
                workspace_path("target/deploy/kamino_vault.so"),
            ),
            (
                kvault::KLEND_PROGRAM_ID,
                workspace_path("target/deploy/kamino_lending.so"),
            ),
        ],
        vec![(
            kvault::global_config(),
            kvault::global_config_account(&payer.pubkey()),
        )],
        &LocalnetPaths::workspace(),
    )?;
    let rpc = localnet.client.rpc();
    let usdc_mint = fixture::spl_mint();
    let vault = create_vault(&localnet, &payer, usdc_mint)?;
    let share_asset_id = register_share_mint(&localnet, &payer, vault.shares_mint)?;

    let mut assets = AssetRegistry::default();
    assets.insert(fixture::SPL_ASSET_ID, usdc_mint)?;
    assets.insert(share_asset_id, vault.shares_mint)?;
    let market_maker = TestWallet::new(MAKER_ACTOR, &assets)?;

    for mint in [usdc_mint, vault.shares_mint] {
        create_associated_token_account(rpc, &payer, &market_maker.address(), &mint)?;
    }
    send(
        rpc,
        &[token_transfer_ix(
            &fixture::payer_token_account(),
            &pda::associated_token_address(&market_maker.address(), &usdc_mint),
            &payer.pubkey(),
            MARKET_MAKER_PUBLIC_USDC,
        )],
        &payer,
        &[&payer],
    )?;

    let mut users = Vec::new();
    for actor in FIRST_USER_ACTOR..=FIRST_USER_ACTOR + config.extra_users {
        let mut user = TestWallet::new(actor, &assets)?;
        for _ in 0..USER_UTXOS {
            let user_deposit = Deposit::new(DepositParams {
                recipient: &user.keypair.shielded_address()?,
                asset: usdc_mint,
                amount: config.user_usdc / USER_UTXOS,
                spl_token_account: Some(fixture::payer_token_account()),
                spl_token_program: Some(spl_token_program_id()),
                memo: None,
            })?
            .send(rpc, &payer, localnet.tree, &payer)?;
            localnet
                .client
                .confirm_private_transaction_sync(user_deposit)
                .map_err(|e| anyhow!("index deposit of user {actor}: {e:?}"))?;
        }
        user.sync(&localnet)?;
        users.push(user);
    }

    let create_cache = CreateCache {
        payer: market_maker.address(),
        data: CreateCacheData {
            write_authority: market_maker.address(),
            nonce: MAKER_CACHE_NONCE,
            tree_id: localnet.tree_id,
            expires_at: MAKER_CACHE_EXPIRES_AT,
        },
    };
    send(
        rpc,
        &[create_cache.instruction()],
        &market_maker.keypair,
        &[&market_maker.keypair],
    )?;

    Ok(Booted {
        localnet,
        users,
        maker: market_maker,
        usdc_mint,
        vault,
    })
}
