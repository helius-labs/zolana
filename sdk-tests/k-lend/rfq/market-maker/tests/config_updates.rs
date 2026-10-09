use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_signature::Signature;
use zolana_program_test::localnet::FixtureLocalnet;

use k_lend_market_maker::{
    ConfigUpdate, Holdings, MakerError, MarketMaker, PairConfig, RangeUpdate, TargetRange,
};
use k_lend_rfq_sdk::{
    pair::{Pair, VaultState},
    swap::{Direction, Offer, Quote},
};

use k_lend_rfq_test_utils::{
    chain::blocking,
    setup::{setup, TestEnv, FEE_BPS, USER_SHIELD_COLLATERAL},
    user::User,
};

const TEST_NUMBER: u16 = 19;
const SEED_DEPOSIT: u64 = 200_000_000;
const SEED_COLLATERAL: u64 = 20_000_000;
const SWAP_COLLATERAL: u64 = 10_000_000;
const WITHDRAW_SHARES: u64 = 2_000_000;
const RAISED_FEE_BPS: u64 = FEE_BPS + 20;
const TIGHT_RANGE: TargetRange = TargetRange {
    min: 0,
    max: 10_000_000,
};
const REBALANCE_TIMEOUT: Duration = Duration::from_secs(120);
const RETIRE_TIMEOUT: Duration = Duration::from_secs(60);
const SETTLE_GRACE: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(500);

fn maker_error<T>(result: Result<T>) -> Result<MakerError> {
    let error = result
        .err()
        .ok_or_else(|| anyhow!("expected a market maker error"))?;
    error
        .downcast::<MakerError>()
        .map_err(|error| anyhow!("expected a market maker error, got {error:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_updates_apply_to_new_quotes_ranges_and_pairs() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        pair,
        ..
    } = setup(TEST_NUMBER).await?;
    let rpc = localnet.client.rpc();
    let seeded = market_maker
        .seed_inventory(&pair, SEED_DEPOSIT, SEED_COLLATERAL)
        .await?;

    let rate = blocking(|| VaultState::read(rpc, &pair.vault))?;
    let before_update = market_maker
        .quote(&pair, Direction::Deposit, SWAP_COLLATERAL)
        .await?;
    market_maker
        .update_config(ConfigUpdate {
            fee_bps: Some(RAISED_FEE_BPS),
            ..ConfigUpdate::default()
        })
        .await?;
    let after_update = market_maker
        .quote(&pair, Direction::Deposit, SWAP_COLLATERAL)
        .await?;
    assert_eq!(
        before_update.quote,
        Quote::price(&rate, Direction::Deposit, SWAP_COLLATERAL, FEE_BPS)?
    );
    assert_eq!(
        after_update.quote,
        Quote::price(&rate, Direction::Deposit, SWAP_COLLATERAL, RAISED_FEE_BPS)?
    );
    assert!(after_update.quote.amount_out < before_update.quote.amount_out);
    market_maker
        .update_config(ConfigUpdate {
            fee_bps: Some(FEE_BPS),
            ..ConfigUpdate::default()
        })
        .await?;
    swap(&localnet, &pair, &mut user, &market_maker, &before_update).await?;
    let shares_bought = before_update.quote.amount_out;
    assert_eq!(
        market_maker.holdings(&pair),
        Holdings {
            collateral: SEED_COLLATERAL + SWAP_COLLATERAL,
            shares: seeded.shares - shares_bought,
        }
    );

    let vault_before_rebalance = blocking(|| VaultState::read(rpc, &pair.vault))?;
    market_maker
        .update_config(ConfigUpdate {
            ranges: vec![RangeUpdate {
                vault: pair.vault,
                collateral: Some(TIGHT_RANGE),
                shares: None,
            }],
            ..ConfigUpdate::default()
        })
        .await?;
    let signature = wait_for_rebalance(&market_maker).await?;
    blocking(|| localnet.client.confirm_private_transaction_sync(signature))
        .map_err(|e| anyhow!("index rebalance {signature}: {e:?}"))?;
    tokio::time::sleep(SETTLE_GRACE).await;
    market_maker.sync().await?;
    assert_eq!(market_maker.rebalances(), vec![signature]);
    let vault_after_rebalance = blocking(|| VaultState::read(rpc, &pair.vault))?;
    let deposited = vault_after_rebalance.token_available - vault_before_rebalance.token_available;
    let minted = vault_after_rebalance.shares_issued - vault_before_rebalance.shares_issued;
    let holdings = market_maker.holdings(&pair);
    assert_eq!(
        holdings,
        Holdings {
            collateral: SEED_COLLATERAL + SWAP_COLLATERAL - deposited,
            shares: seeded.shares - shares_bought + minted,
        }
    );
    assert!(TIGHT_RANGE.contains(holdings.collateral));

    let offer = market_maker
        .quote(&pair, Direction::Withdrawal, WITHDRAW_SHARES)
        .await?;
    let order = user.order(&localnet, &pair, &offer).await?;
    let fill = market_maker.fill(&pair, &order.request).await?;
    market_maker
        .update_config(ConfigUpdate {
            remove_pairs: vec![pair.vault],
            ..ConfigUpdate::default()
        })
        .await?;
    assert!(matches!(
        maker_error(
            market_maker
                .quote(&pair, Direction::Withdrawal, WITHDRAW_SHARES)
                .await
        )?,
        MakerError::PairNotServed { vault } if vault == pair.vault
    ));
    user.verify_quote(&localnet, &pair, &order, &fill.fill.message)
        .await?;
    let user_signature = user.sign(&fill.fill.message)?;
    let settled = market_maker.settle(&fill.fill, user_signature).await?;
    blocking(|| localnet.client.confirm_private_transaction_sync(settled))
        .map_err(|e| anyhow!("index swap {settled}: {e:?}"))?;
    user.sync(&localnet).await?;
    assert_eq!(
        user.holdings(&pair)?,
        Holdings {
            collateral: USER_SHIELD_COLLATERAL - SWAP_COLLATERAL + offer.quote.amount_out,
            shares: shares_bought - WITHDRAW_SHARES,
        }
    );

    let unregistered = Pair::new(Address::new_from_array([42; 32]), pair.token_mint);
    assert!(matches!(
        maker_error(
            market_maker
                .update_config(ConfigUpdate {
                    add_pairs: vec![PairConfig::new(unregistered)],
                    ..ConfigUpdate::default()
                })
                .await
        )?,
        MakerError::AssetNotRegistered { mint } if mint == unregistered.shares_mint
    ));
    readd_after_retirement(&market_maker, &pair).await?;
    market_maker
        .quote(&pair, Direction::Withdrawal, WITHDRAW_SHARES)
        .await?;
    market_maker.shutdown().await;
    Ok(())
}

async fn readd_after_retirement(market_maker: &MarketMaker, pair: &Pair) -> Result<()> {
    let deadline = Instant::now() + RETIRE_TIMEOUT;
    loop {
        let readded = market_maker
            .update_config(ConfigUpdate {
                add_pairs: vec![PairConfig::new(*pair)],
                ..ConfigUpdate::default()
            })
            .await;
        match maker_error(readded) {
            Err(_) => return Ok(()),
            Ok(MakerError::PairExists { .. }) if Instant::now() < deadline => {
                tokio::time::sleep(POLL).await;
            }
            Ok(error) => return Err(anyhow!("pair was not retired: {error}")),
        }
    }
}

async fn wait_for_rebalance(market_maker: &MarketMaker) -> Result<Signature> {
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
    offer: &Offer,
) -> Result<()> {
    let order = user.order(localnet, pair, offer).await?;
    let fill = market_maker.fill(pair, &order.request).await?;
    user.verify_quote(localnet, pair, &order, &fill.fill.message)
        .await?;
    let user_signature = user.sign(&fill.fill.message)?;
    let signature = market_maker.settle(&fill.fill, user_signature).await?;
    blocking(|| localnet.client.confirm_private_transaction_sync(signature))
        .map_err(|e| anyhow!("index swap {signature}: {e:?}"))?;
    user.sync(localnet).await?;
    market_maker.sync().await?;
    Ok(())
}
