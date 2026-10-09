use std::time::Duration;

use anyhow::{anyhow, Result};

use kamino_vault_market_maker::MakerError;
use kamino_vault_rfq_sdk::{
    budget::{smallest_shape, USER_OUTPUTS},
    kvault::VaultState,
    swap::{Direction, Holdings, Offer, Quote, SwapError},
};

use crate::shared::{blocking, setup, TestEnv, FEE_BPS, USER_SHIELD_USDC};

const BOOTSTRAP_USDC: u64 = 200_000_000;
const SWAP_USDC: u64 = 10_000_000;
const TWO_UTXO_USDC: u64 = 60_000_000;
const GREEDY_FEE_BPS: u64 = FEE_BPS + 50;
const QUOTE_TTL: Duration = Duration::from_secs(15);
const RELEASE_GRACE: Duration = Duration::from_secs(5);
const UNTOUCHED: Holdings = Holdings {
    usdc: USER_SHIELD_USDC,
    shares: 0,
};

fn swap_error(result: Result<impl Sized>) -> Result<SwapError> {
    let error = result
        .err()
        .ok_or_else(|| anyhow!("expected a swap error"))?;
    error
        .downcast_ref::<SwapError>()
        .cloned()
        .ok_or_else(|| anyhow!("expected a swap error, got {error:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_quotes_and_fills_leave_the_user_untouched() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        vault,
        ..
    } = setup(14).await?;
    let rpc = localnet.client.rpc();
    market_maker.set_quote_ttl(QUOTE_TTL);

    let offer = market_maker
        .quote(&localnet, &vault, Direction::Deposit, SWAP_USDC)
        .await?;
    let order = user.order(&localnet, &vault, &offer, &[]).await?;
    assert_eq!(
        swap_error(market_maker.fill(&localnet, &vault, &order.request).await)?,
        SwapError::InsufficientInventory {
            asset: vault.shares_mint,
            required: offer.quote.amount_out,
            available: 0,
        }
    );
    user.sync(&localnet).await?;
    assert_eq!(user.holdings(&vault)?, UNTOUCHED);

    market_maker
        .bootstrap(&localnet, &vault, BOOTSTRAP_USDC)
        .await?;
    let lanes_before = market_maker.lanes(&vault.shares_mint);
    market_maker.set_fee_bps(GREEDY_FEE_BPS);
    let greedy = market_maker
        .quote(&localnet, &vault, Direction::Deposit, SWAP_USDC)
        .await?;
    let order = user.order(&localnet, &vault, &greedy, &[]).await?;
    let greedy_fill = market_maker.fill(&localnet, &vault, &order.request).await?;
    let fair = Quote::price(
        &blocking(|| VaultState::read(rpc, &vault.vault))?,
        Direction::Deposit,
        SWAP_USDC,
        FEE_BPS,
    )?;
    assert_eq!(
        swap_error(
            user.verify_quote(&localnet, &vault, &order, &greedy_fill.message)
                .await
        )?,
        SwapError::BelowRate {
            expected: fair.amount_out,
            offered: greedy.quote.amount_out,
        }
    );
    user.sync(&localnet).await?;
    assert_eq!(user.holdings(&vault)?, UNTOUCHED);

    market_maker.set_fee_bps(FEE_BPS);
    let offer = market_maker
        .quote(&localnet, &vault, Direction::Deposit, SWAP_USDC)
        .await?;
    let order = user.order(&localnet, &vault, &offer, &[]).await?;
    let fill = market_maker
        .fill_to(&localnet, &vault, &order.request, market_maker.identity())
        .await?;
    assert_eq!(fill.spent, greedy_fill.spent);
    assert!(fill.expires_at > greedy_fill.expires_at);
    assert_eq!(
        swap_error(
            user.verify_quote(&localnet, &vault, &order, &fill.message)
                .await
        )?,
        SwapError::UnexpectedOutputs { received: 0 }
    );
    user.sync(&localnet).await?;
    assert_eq!(user.holdings(&vault)?, UNTOUCHED);

    let abandoned = fill.step;
    let user_signature = user.sign(&fill.message)?;
    tokio::time::sleep_until((fill.expires_at + RELEASE_GRACE).into()).await;
    assert_eq!(market_maker.lanes(&vault.shares_mint), lanes_before);
    let late = market_maker
        .settle(fill, user_signature)
        .await
        .err()
        .ok_or_else(|| anyhow!("a settle after the deadline succeeded"))?;
    assert!(matches!(
        late.downcast_ref::<MakerError>(),
        Some(MakerError::UnknownFill { step }) if *step == abandoned
    ));

    let max = market_maker.budget().max_user_inputs;
    let wide = smallest_shape(max + 1, USER_OUTPUTS)
        .ok_or_else(|| anyhow!("no shape wider than the user cap of {max}"))?
        .n_inputs();
    let offer = market_maker
        .quote(&localnet, &vault, Direction::Deposit, SWAP_USDC)
        .await?;
    let order = user
        .order_with_width(&localnet, &vault, &offer, &[], Some(wide))
        .await?;
    assert_eq!(
        swap_error(market_maker.fill(&localnet, &vault, &order.request).await)?,
        SwapError::UserLegTooWide { inputs: wide, max }
    );
    assert_eq!(market_maker.lanes(&vault.shares_mint), lanes_before);

    let offer = market_maker
        .quote(&localnet, &vault, Direction::Deposit, TWO_UTXO_USDC)
        .await?;
    let capped = Offer {
        max_user_inputs: 1,
        ..offer
    };
    assert_eq!(
        swap_error(user.order(&localnet, &vault, &capped, &[]).await)?,
        SwapError::TooManyInputs { needed: 2, max: 1 }
    );
    user.sync(&localnet).await?;
    assert_eq!(user.holdings(&vault)?, UNTOUCHED);
    Ok(())
}
