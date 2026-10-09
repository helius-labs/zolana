use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use zolana_program_test::localnet::FixtureLocalnet;

use kamino_vault_market_maker::{MarketMaker, TargetRange, TokenConfig};
use kamino_vault_rfq_sdk::{
    kvault::{Pair, VaultState},
    swap::{Direction, Holdings, Offer, Quote, SwapError},
};

use kamino_vault_rfq_example::{
    setup::{blocking, setup_with, SetupConfig, TestEnv},
    user::User,
};

const TEST_NUMBER: u16 = 18;
const EXTRA_USERS: u8 = 3;
const USER_COLLATERAL: u64 = 80_000_000;
const SEED_DEPOSIT: u64 = 200_000_000;
const SEED_COLLATERAL: u64 = 20_000_000;
const LARGE_COLLATERAL: u64 = 35_000_000;
const SMALL_COLLATERAL: u64 = 4_000_000;
const COLLATERAL_RANGE: TargetRange = TargetRange {
    min: 0,
    max: 60_000_000,
};
const SHARE_RANGE: TargetRange = TargetRange {
    min: 100_000_000,
    max: 400_000_000,
};
const REBALANCE_TIMEOUT: Duration = Duration::from_secs(120);
const SETTLE_GRACE: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(500);

fn swap_error(result: Result<Offer>) -> Result<SwapError> {
    let error = result
        .err()
        .ok_or_else(|| anyhow!("expected a refused quote"))?;
    error
        .downcast_ref::<SwapError>()
        .cloned()
        .ok_or_else(|| anyhow!("expected a swap error, got {error:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn target_ranges_bound_quotes_and_trigger_rebalances() -> Result<()> {
    let TestEnv {
        localnet,
        user,
        users,
        market_maker,
        pair,
        ..
    } = setup_with(SetupConfig {
        extra_users: EXTRA_USERS,
        user_collateral: USER_COLLATERAL,
        collateral: TokenConfig {
            range: Some(COLLATERAL_RANGE),
            lanes: None,
        },
        shares: TokenConfig {
            range: Some(SHARE_RANGE),
            lanes: None,
        },
        ..SetupConfig::new(TEST_NUMBER)
    })
    .await?;
    let rpc = localnet.client.rpc();
    let mut users = users.into_iter();
    let mut depositor = user;
    let mut second = users.next().ok_or_else(|| anyhow!("no second user"))?;
    let mut third = users.next().ok_or_else(|| anyhow!("no third user"))?;
    let mut fourth = users.next().ok_or_else(|| anyhow!("no fourth user"))?;
    let seeded = market_maker
        .seed_inventory(&localnet, &pair, SEED_DEPOSIT, SEED_COLLATERAL)
        .await?;
    let vault_after_seed = blocking(|| VaultState::read(rpc, &pair.vault))?;

    let deposit = swap(
        &localnet,
        &pair,
        &mut depositor,
        &market_maker,
        Direction::Deposit,
        LARGE_COLLATERAL,
    )
    .await?;
    assert_eq!(
        swap_error(
            market_maker
                .quote(&localnet, &pair, Direction::Deposit, LARGE_COLLATERAL)
                .await
        )?,
        SwapError::OutsideTargetRange {
            asset: pair.token_mint,
            balance_after: SEED_COLLATERAL + 2 * LARGE_COLLATERAL,
            min: COLLATERAL_RANGE.min,
            max: COLLATERAL_RANGE.max,
        }
    );
    let withdrawal = swap(
        &localnet,
        &pair,
        &mut depositor,
        &market_maker,
        Direction::Withdrawal,
        deposit.amount_out,
    )
    .await?;
    let redeposit = swap(
        &localnet,
        &pair,
        &mut second,
        &market_maker,
        Direction::Deposit,
        LARGE_COLLATERAL,
    )
    .await?;
    assert_eq!(market_maker.rebalances(), Vec::new());
    assert_eq!(
        blocking(|| VaultState::read(rpc, &pair.vault))?,
        vault_after_seed
    );
    let collateral = SEED_COLLATERAL + 2 * LARGE_COLLATERAL - withdrawal.amount_out;
    assert!(COLLATERAL_RANGE.contains(collateral));

    let quotes = [
        market_maker
            .quote(&localnet, &pair, Direction::Deposit, SMALL_COLLATERAL)
            .await?,
        market_maker
            .quote(&localnet, &pair, Direction::Deposit, SMALL_COLLATERAL)
            .await?,
    ];
    let mut shares_paid = deposit.amount_out - withdrawal.amount_in + redeposit.amount_out;
    for (offer, user) in quotes.iter().zip([&mut third, &mut fourth]) {
        settle(&localnet, &pair, user, &market_maker, offer).await?;
        shares_paid += offer.quote.amount_out;
    }
    let accumulated = collateral + 2 * SMALL_COLLATERAL;
    assert!(accumulated > COLLATERAL_RANGE.max);

    let signature = wait_for_rebalance(&market_maker).await?;
    blocking(|| localnet.client.confirm_private_transaction_sync(signature))
        .map_err(|e| anyhow!("index rebalance {signature}: {e:?}"))?;
    tokio::time::sleep(SETTLE_GRACE).await;
    market_maker.sync().await?;
    assert_eq!(market_maker.rebalances(), vec![signature]);
    let vault_after = blocking(|| VaultState::read(rpc, &pair.vault))?;
    let deposited = vault_after.token_available - vault_after_seed.token_available;
    let minted = vault_after.shares_issued - vault_after_seed.shares_issued;
    let holdings = market_maker.holdings(&pair);
    assert_eq!(
        holdings,
        Holdings {
            collateral: accumulated - deposited,
            shares: seeded.shares - shares_paid + minted,
        }
    );
    assert!(COLLATERAL_RANGE.contains(holdings.collateral));
    assert!(SHARE_RANGE.contains(holdings.shares));
    println!(
        "automatic rebalance deposited {deposited} of {accumulated} collateral, {} left",
        holdings.collateral
    );
    market_maker.shutdown().await;
    Ok(())
}

async fn wait_for_rebalance(market_maker: &MarketMaker) -> Result<solana_signature::Signature> {
    let deadline = Instant::now() + REBALANCE_TIMEOUT;
    loop {
        if let Some(signature) = market_maker.rebalances().first() {
            return Ok(*signature);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "no automatic rebalance after {REBALANCE_TIMEOUT:?}"
            ));
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn swap(
    localnet: &FixtureLocalnet,
    pair: &Pair,
    user: &mut User,
    market_maker: &MarketMaker,
    direction: Direction,
    amount_in: u64,
) -> Result<Quote> {
    let offer = market_maker
        .quote(localnet, pair, direction, amount_in)
        .await?;
    settle(localnet, pair, user, market_maker, &offer).await?;
    Ok(offer.quote)
}

async fn settle(
    localnet: &FixtureLocalnet,
    pair: &Pair,
    user: &mut User,
    market_maker: &MarketMaker,
    offer: &Offer,
) -> Result<()> {
    let order = user.order(localnet, pair, offer).await?;
    let fill = market_maker.fill(localnet, pair, &order.request).await?;
    user.verify_quote(localnet, pair, &order, &fill.message)
        .await?;
    let user_signature = user.sign(&fill.message)?;
    let signature = market_maker.settle(fill, user_signature).await?;
    blocking(|| localnet.client.confirm_private_transaction_sync(signature))
        .map_err(|e| anyhow!("index swap {signature}: {e:?}"))?;
    user.sync(localnet).await?;
    market_maker.sync().await?;
    Ok(())
}
