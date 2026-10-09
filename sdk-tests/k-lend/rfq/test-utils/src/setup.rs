use std::time::Duration;

use anyhow::{anyhow, Result};
use k_lend_market_maker::{
    ConcurrencyConfig, ConnectionConfig, IdentityConfig, MarketMaker, MarketMakerConfig,
    PairConfig, QuoteConfig, TokenConfig,
};
use k_lend_rfq_sdk::pair::{Pair, PROGRAM_ID};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::{
    pda::{self, spl_token_program_id},
    state::SplAssetRegistry,
};
use zolana_program::instruction::CreateSplInterface;
use zolana_program_test::{
    fixture,
    instructions::system_create_account_ix,
    localnet::{FixtureLocalnet, LocalnetPaths, LocalnetPorts},
    workspace_path,
};
use zolana_test_utils::wallet::{create_associated_token_account, Deposit, DepositParams};
use zolana_transaction::AssetRegistry;

use crate::{
    chain::{blocking, send},
    kvault::{self, InitVault},
    user::User,
    wallet::TestWallet,
};

pub const FEE_BPS: u64 = 30;
pub const USER_SHIELD_COLLATERAL: u64 = 100_000_000;
const USER_UTXOS: u64 = 2;
const MAKER_ACTOR: u8 = 0;
const FIRST_USER_ACTOR: u8 = 1;
pub const MARKET_MAKER_PUBLIC_COLLATERAL: u64 = 500_000_000;

pub struct TestEnv {
    pub localnet: FixtureLocalnet,
    pub user: User,
    pub users: Vec<User>,
    pub market_maker: MarketMaker,
    pub collateral_mint: Address,
    pub pair: Pair,
}

#[derive(Clone, Debug)]
pub struct SetupConfig {
    pub test: u16,
    pub extra_users: u8,
    pub concurrency: ConcurrencyConfig,
    pub collateral: TokenConfig,
    pub shares: TokenConfig,
    pub quote_ttl: Duration,
    pub user_collateral: u64,
}

impl SetupConfig {
    pub fn new(test: u16) -> Self {
        Self {
            test,
            extra_users: 0,
            concurrency: ConcurrencyConfig::default(),
            collateral: TokenConfig::default(),
            shares: TokenConfig::default(),
            quote_ttl: QuoteConfig::default().ttl,
            user_collateral: USER_SHIELD_COLLATERAL,
        }
    }
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
    collateral_mint: Address,
) -> Result<Pair> {
    let rpc = localnet.client.rpc();
    let vault_keypair = Keypair::new();
    let pair = Pair::new(vault_keypair.pubkey(), collateral_mint);
    let rent = rpc.get_minimum_balance_for_rent_exemption(kvault::VAULT_STATE_SIZE)?;
    let create = system_create_account_ix(
        &payer.pubkey(),
        &pair.vault,
        rent,
        kvault::VAULT_STATE_SIZE as u64,
        &PROGRAM_ID,
    );
    let init = InitVault {
        admin: payer.pubkey(),
        admin_token_account: fixture::payer_token_account(),
        pair,
    }
    .instruction();
    send(rpc, &[create, init], payer, &[payer, &vault_keypair])?;
    Ok(pair)
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
    collateral_mint: Address,
    pair: Pair,
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
        collateral_mint,
        pair,
    } = blocking(|| boot(ports, &config))?;
    let market_maker = MarketMaker::start(MarketMakerConfig {
        connection: ConnectionConfig {
            rpc_url: ports.rpc_url(),
            photon_url: ports.photon_url(),
            prover_url: None,
            tree: localnet.tree,
            tree_id: localnet.tree_id,
        },
        identity: IdentityConfig {
            keypair: maker.keypair,
        },
        pairs: vec![PairConfig {
            pair,
            collateral: config.collateral,
            shares: config.shares,
        }],
        concurrency: config.concurrency,
        quotes: QuoteConfig {
            fee_bps: FEE_BPS,
            ttl: config.quote_ttl,
        },
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
        collateral_mint,
        pair,
    })
}

fn boot(ports: LocalnetPorts, config: &SetupConfig) -> Result<Booted> {
    let payer = fixture::payer();
    let localnet = FixtureLocalnet::start_with_accounts(
        "zolana-k-lend",
        ports,
        vec![
            (PROGRAM_ID, workspace_path("target/deploy/kamino_vault.so")),
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
    let collateral_mint = fixture::spl_mint();
    let pair = create_vault(&localnet, &payer, collateral_mint)?;
    let share_asset_id = register_share_mint(&localnet, &payer, pair.shares_mint)?;

    let mut assets = AssetRegistry::default();
    assets.insert(fixture::SPL_ASSET_ID, collateral_mint)?;
    assets.insert(share_asset_id, pair.shares_mint)?;
    let market_maker = TestWallet::new(MAKER_ACTOR, &assets)?;

    for mint in [collateral_mint, pair.shares_mint] {
        create_associated_token_account(rpc, &payer, &market_maker.address(), &mint)?;
    }
    send(
        rpc,
        &[token_transfer_ix(
            &fixture::payer_token_account(),
            &pda::associated_token_address(&market_maker.address(), &collateral_mint),
            &payer.pubkey(),
            MARKET_MAKER_PUBLIC_COLLATERAL,
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
                asset: collateral_mint,
                amount: config.user_collateral / USER_UTXOS,
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

    Ok(Booted {
        localnet,
        users,
        maker: market_maker,
        collateral_mint,
        pair,
    })
}
