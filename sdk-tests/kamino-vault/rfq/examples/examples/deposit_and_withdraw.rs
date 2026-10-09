use anyhow::{anyhow, Result};
use zolana_program_test::localnet::FixtureLocalnet;

use kamino_vault_market_maker::MarketMaker;
use kamino_vault_rfq_sdk::{
    kvault::VaultAccounts,
    swap::{Direction, Holdings, Quote},
};

use kamino_vault_rfq_example::{
    setup::{blocking, setup, TestEnv, USER_SHIELD_USDC},
    user::User,
};

const MARKET_MAKER_SHARES_USDC: u64 = 200_000_000;
const MARKET_MAKER_COLLATERAL: u64 = 50_000_000;
const DEPOSIT_USDC: u64 = 40_000_000;
const WITHDRAW_SHARES: u64 = 15_000_000;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        vault,
        ..
    } = setup(12).await?;

    // Market maker setup: deposit USDC into kVault and keep the shares and some
    // USDC in its private balance, so it can serve both directions.
    market_maker
        .bootstrap(
            &localnet,
            &vault,
            MARKET_MAKER_SHARES_USDC,
            MARKET_MAKER_COLLATERAL,
        )
        .await?;

    // Deposit: the user swaps private USDC for kVault shares.
    let deposit = swap(
        &localnet,
        &vault,
        &mut user,
        &market_maker,
        Direction::Deposit,
        DEPOSIT_USDC,
    )
    .await?;
    assert_eq!(
        user.holdings(&vault)?,
        Holdings {
            usdc: USER_SHIELD_USDC - DEPOSIT_USDC,
            shares: deposit.amount_out,
        }
    );

    // Withdrawal: the user swaps part of its shares back for USDC.
    let withdrawal = swap(
        &localnet,
        &vault,
        &mut user,
        &market_maker,
        Direction::Withdrawal,
        WITHDRAW_SHARES,
    )
    .await?;
    assert_eq!(
        user.holdings(&vault)?,
        Holdings {
            usdc: USER_SHIELD_USDC - DEPOSIT_USDC + withdrawal.amount_out,
            shares: deposit.amount_out - WITHDRAW_SHARES,
        }
    );

    market_maker.shutdown().await;
    Ok(())
}

async fn swap(
    localnet: &FixtureLocalnet,
    vault: &VaultAccounts,
    user: &mut User,
    market_maker: &MarketMaker,
    direction: Direction,
    amount_in: u64,
) -> Result<Quote> {
    // 1-2. The user requests a quote; the market maker returns `amount_out`
    // at the vault rate minus its fee, and the user's input cap.
    let offer = market_maker
        .quote(localnet, vault, direction, amount_in)
        .await?;
    println!(
        "{direction:?}: {amount_in} in, {} out",
        offer.quote.amount_out
    );

    // 3. The user proves its transfer: its UTXOs in, `amount_in` to the
    // market maker and change back to itself.
    let order = user.order(localnet, vault, &offer, &[]).await?;

    // 4. The market maker checks the user transfer, proves its own transfer
    // paying `amount_out` to the user, and builds the transaction.
    let fill = market_maker.fill(localnet, vault, &order.request).await?;

    // 5. The user checks that the market maker's transfer pays the quoted
    // amount, then signs.
    user.verify_quote(localnet, vault, &order, &fill.message)
        .await?;
    let user_signature = user.sign(&fill.message)?;

    // 6. The market maker adds its signature and sends the transaction.
    let signature = market_maker.settle(fill, user_signature).await?;

    blocking(|| localnet.client.confirm_private_transaction_sync(signature))
        .map_err(|e| anyhow!("index swap {signature}: {e:?}"))?;
    user.sync(localnet).await?;
    market_maker.sync().await?;
    Ok(offer.quote)
}
