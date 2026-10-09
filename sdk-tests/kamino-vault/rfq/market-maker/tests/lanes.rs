use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use solana_message::v1;
use solana_signature::Signature;
use tokio::{sync::Barrier, task::JoinSet};
use zolana_client::transaction_size;
use zolana_program_test::localnet::FixtureLocalnet;

use kamino_vault_market_maker::{ConcurrencyConfig, LaneProfile, MarketMaker, TokenConfig};
use kamino_vault_rfq_sdk::{
    kvault::VaultAccounts,
    swap::{instructions, Direction, Holdings, Quote, SWAP_COMPUTE_BUDGET},
};

use kamino_vault_rfq_example::{
    setup::{blocking, compute_units, setup_with, SetupConfig, TestEnv},
    user::User,
};

const TEST_NUMBER: u16 = 17;
const EXTRA_USERS: u8 = 4;
const USERS: usize = 5;
const USER_USDC: u64 = 80_000_000;
const BOOTSTRAP_USDC: u64 = 200_000_000;
const LARGE_USDC: u64 = 70_000_000;
const SMALL_USDC: u64 = 2_000_000;
const LARGE_LANES: [u64; 3] = [4, 8, 16];
const SMALL_LANES: usize = 47;
const LANES: usize = 50;
const LARGE_SWAP_INPUTS: usize = 2;
const BUILD_TIMEOUT: Duration = Duration::from_secs(240);
const POLL: Duration = Duration::from_millis(500);

struct Swapped {
    user: User,
    quote: Quote,
    inputs: usize,
    spent: Vec<[u8; 32]>,
    bytes: usize,
    addresses: usize,
    max_user_inputs: usize,
    signature: Signature,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn large_swap_fills_from_large_lanes_while_small_swaps_run() -> Result<()> {
    let concurrency = ConcurrencyConfig::default();
    let min_lane_value = concurrency.lanes.min_lane_value;
    let TestEnv {
        localnet,
        user,
        users,
        market_maker,
        vault,
        ..
    } = setup_with(SetupConfig {
        extra_users: EXTRA_USERS,
        shares: TokenConfig {
            range: None,
            lanes: Some(LaneProfile {
                large: LARGE_LANES.to_vec(),
                small: SMALL_LANES,
                min_lane_value,
            }),
        },
        concurrency: ConcurrencyConfig {
            lane_upkeep_delay: Some(Duration::ZERO),
            ..concurrency
        },
        user_usdc: USER_USDC,
        ..SetupConfig::new(TEST_NUMBER)
    })
    .await?;
    let bootstrap = market_maker
        .bootstrap(&localnet, &vault, BOOTSTRAP_USDC, 0)
        .await?;
    let built = Instant::now();
    wait_for_lanes(&market_maker, &vault, LANES).await?;
    let lanes = market_maker.lanes(&vault.shares_mint);
    let largest: Vec<u64> = lanes.iter().take(3).map(|lane| lane.amount).collect();
    assert_eq!(
        largest,
        LARGE_LANES
            .iter()
            .map(|divisor| bootstrap.shares / divisor)
            .collect::<Vec<_>>()
    );
    println!(
        "{LANES} share lanes built in {:?}, largest {largest:?}",
        built.elapsed()
    );

    let localnet = Arc::new(localnet);
    let filled = Arc::new(Barrier::new(USERS));
    let mut tasks = JoinSet::new();
    let amounts = std::iter::once(LARGE_USDC).chain(std::iter::repeat(SMALL_USDC));
    for (user, amount_in) in std::iter::once(user).chain(users).zip(amounts) {
        tasks.spawn(swap(
            localnet.clone(),
            vault,
            market_maker.clone(),
            user,
            amount_in,
            filled.clone(),
        ));
    }
    let mut swapped = Vec::with_capacity(USERS);
    while let Some(joined) = tasks.join_next().await {
        swapped.push(joined??);
    }
    swapped.sort_by_key(|swap| std::cmp::Reverse(swap.quote.amount_in));

    let mut spent: Vec<[u8; 32]> = swapped
        .iter()
        .flat_map(|swap| swap.spent.iter().copied())
        .collect();
    let spent_count = spent.len();
    spent.sort_unstable();
    spent.dedup();
    assert_eq!(spent.len(), spent_count);
    assert_eq!(
        swapped.iter().map(|swap| swap.inputs).collect::<Vec<_>>(),
        std::iter::once(LARGE_SWAP_INPUTS)
            .chain(std::iter::repeat_n(1, USERS - 1))
            .collect::<Vec<_>>()
    );
    let large = swapped.first().ok_or_else(|| anyhow!("no large swap"))?;
    assert!(large.bytes <= v1::MAX_TRANSACTION_SIZE);
    assert!(large.addresses <= usize::from(v1::MAX_ADDRESSES));
    let rpc = localnet.client.rpc();
    let large_signature = large.signature;
    println!(
        "large swap of {} USDC: {} maker inputs, {} of {} bytes, {} of {} addresses, user cap {} inputs, {} CU",
        large.quote.amount_in,
        large.inputs,
        large.bytes,
        v1::MAX_TRANSACTION_SIZE,
        large.addresses,
        v1::MAX_ADDRESSES,
        large.max_user_inputs,
        blocking(|| compute_units(rpc, &large_signature))?
    );

    for swap in &swapped {
        let signature = swap.signature;
        blocking(|| localnet.client.confirm_private_transaction_sync(signature))
            .map_err(|e| anyhow!("index swap {signature}: {e:?}"))?;
    }
    for swap in &mut swapped {
        swap.user.sync(&localnet).await?;
        assert_eq!(
            swap.user.holdings(&vault)?,
            Holdings {
                usdc: USER_USDC - swap.quote.amount_in,
                shares: swap.quote.amount_out,
            }
        );
    }
    market_maker.sync().await?;
    let usdc_received: u64 = swapped.iter().map(|swap| swap.quote.amount_in).sum();
    let shares_paid: u64 = swapped.iter().map(|swap| swap.quote.amount_out).sum();
    assert_eq!(
        market_maker.holdings(&vault),
        Holdings {
            usdc: usdc_received,
            shares: bootstrap.shares - shares_paid,
        }
    );
    market_maker.shutdown().await;
    Ok(())
}

async fn wait_for_lanes(
    market_maker: &MarketMaker,
    vault: &VaultAccounts,
    lanes: usize,
) -> Result<()> {
    let deadline = Instant::now() + BUILD_TIMEOUT;
    loop {
        market_maker.sync().await?;
        let current = market_maker.lanes(&vault.shares_mint);
        if current.len() == lanes && current.iter().all(|lane| !lane.reserved) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "{} of {lanes} share lanes after {BUILD_TIMEOUT:?}",
                current.len()
            ));
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn swap(
    localnet: Arc<FixtureLocalnet>,
    vault: VaultAccounts,
    market_maker: MarketMaker,
    user: User,
    amount_in: u64,
    filled: Arc<Barrier>,
) -> Result<Swapped> {
    let offer = market_maker
        .quote(&localnet, &vault, Direction::Deposit, amount_in)
        .await?;
    let order = user.order(&localnet, &vault, &offer, &[]).await?;
    let fill = market_maker.fill(&localnet, &vault, &order.request).await?;
    filled.wait().await;
    user.verify_quote(&localnet, &vault, &order, &fill.message)
        .await?;
    let size = transaction_size(
        &market_maker.address(),
        &instructions(&fill.message)?,
        SWAP_COMPUTE_BUDGET,
    )?;
    let spent = fill.spent.clone();
    let user_signature = user.sign(&fill.message)?;
    let signature = market_maker.settle(fill, user_signature).await?;
    Ok(Swapped {
        user,
        quote: offer.quote,
        inputs: spent.len(),
        spent,
        bytes: size.bytes,
        addresses: size.addresses,
        max_user_inputs: offer.max_user_inputs,
        signature,
    })
}
