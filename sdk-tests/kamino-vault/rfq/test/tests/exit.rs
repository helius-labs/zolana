use anyhow::{anyhow, Result};
use zolana_program_test::localnet::FixtureLocalnet;

use kamino_vault_market_maker::MarketMaker;
use kamino_vault_rfq_sdk::{
    kvault::{VaultAccounts, VaultState},
    swap::{Direction, Holdings, Quote, VaultOperation},
};

use crate::{
    shared::{blocking, setup, TestEnv, USER_SHIELD_USDC},
    user::User,
};

const BOOTSTRAP_USDC: u64 = 200_000_000;
const DEPOSIT_USDC: u64 = 40_000_000;
const EXIT_SHARES: u64 = 15_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_exit_settles_after_the_market_maker_withdraws() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        vault,
        ..
    } = setup(13).await?;
    let rpc = localnet.client.rpc();
    let bootstrap = market_maker
        .bootstrap(&localnet, &vault, BOOTSTRAP_USDC)
        .await?;

    let deposit = swap(
        &localnet,
        &vault,
        &mut user,
        &market_maker,
        Direction::Deposit,
        DEPOSIT_USDC,
    )
    .await?;

    let before_withdraw = blocking(|| VaultState::read(rpc, &vault.vault))?;
    let predicted = before_withdraw.withdraw(EXIT_SHARES)?;
    let withdraw = market_maker
        .rebalance_withdraw(&localnet, &vault, EXIT_SHARES)
        .await?;
    assert_eq!(
        withdraw,
        VaultOperation {
            before: before_withdraw,
            after: predicted.after,
            tokens: predicted.tokens,
            shares: predicted.shares,
            inputs: 1,
        }
    );

    let exit = swap(
        &localnet,
        &vault,
        &mut user,
        &market_maker,
        Direction::Exit,
        EXIT_SHARES,
    )
    .await?;

    assert_eq!(
        user.holdings(&vault)?,
        Holdings {
            usdc: USER_SHIELD_USDC - DEPOSIT_USDC + exit.amount_out,
            shares: deposit.amount_out - EXIT_SHARES,
        }
    );
    assert_eq!(
        market_maker.holdings(&vault),
        Holdings {
            usdc: DEPOSIT_USDC + withdraw.tokens - exit.amount_out,
            shares: bootstrap.shares - deposit.amount_out,
        }
    );
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
    let offer = market_maker
        .quote(localnet, vault, direction, amount_in)
        .await?;
    let order = user.order(localnet, vault, &offer, &[]).await?;
    let fill = market_maker.fill(localnet, vault, &order.request).await?;
    user.verify_quote(localnet, vault, &order, &fill.message)
        .await?;
    let user_signature = user.sign(&fill.message)?;
    let signature = market_maker.settle(fill, user_signature).await?;
    blocking(|| localnet.client.confirm_private_transaction_sync(signature))
        .map_err(|e| anyhow!("index swap {signature}: {e:?}"))?;
    user.sync(localnet).await?;
    market_maker.sync().await?;
    Ok(offer.quote)
}
