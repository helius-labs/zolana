use std::time::Duration;

use anyhow::{anyhow, Result};
use zolana_client::Rpc;

use kamino_vault_market_maker::MakerError;
use kamino_vault_rfq_sdk::{
    budget::{smallest_shape, USER_OUTPUTS},
    kvault::VaultState,
    swap::{swap_message, Direction, Holdings, Offer, Quote, SwapError},
    user::Transfer,
};

use kamino_vault_rfq_example::setup::{
    blocking, setup_with, SetupConfig, TestEnv, FEE_BPS, USER_SHIELD_COLLATERAL,
};

const SEED_DEPOSIT: u64 = 200_000_000;
const SWAP_COLLATERAL: u64 = 10_000_000;
const TWO_UTXO_COLLATERAL: u64 = 60_000_000;
const GREEDY_FEE_BPS: u64 = FEE_BPS + 50;
const QUOTE_TTL: Duration = Duration::from_secs(15);
const RELEASE_GRACE: Duration = Duration::from_secs(5);
const UNTOUCHED: Holdings = Holdings {
    collateral: USER_SHIELD_COLLATERAL,
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
        pair,
        ..
    } = setup_with(SetupConfig {
        quote_ttl: QUOTE_TTL,
        ..SetupConfig::new(14)
    })
    .await?;
    let rpc = localnet.client.rpc();

    let unfunded = Quote::price(
        &blocking(|| VaultState::read(rpc, &pair.vault))?,
        Direction::Deposit,
        SWAP_COLLATERAL,
        FEE_BPS,
    )?;
    assert_eq!(
        swap_error(
            market_maker
                .quote(&localnet, &pair, Direction::Deposit, SWAP_COLLATERAL)
                .await
        )?,
        SwapError::InsufficientInventory {
            asset: pair.shares_mint,
            required: unfunded.amount_out,
            available: 0,
        }
    );
    user.sync(&localnet).await?;
    assert_eq!(user.holdings(&pair)?, UNTOUCHED);

    market_maker
        .seed_inventory(&localnet, &pair, SEED_DEPOSIT, 0)
        .await?;
    let lanes_before = market_maker.lanes(&pair.shares_mint);
    let fair_offer = market_maker
        .quote(&localnet, &pair, Direction::Deposit, SWAP_COLLATERAL)
        .await?;
    let greedy = Offer {
        quote: Quote::price(
            &blocking(|| VaultState::read(rpc, &pair.vault))?,
            Direction::Deposit,
            SWAP_COLLATERAL,
            GREEDY_FEE_BPS,
        )?,
        ..fair_offer
    };
    let order = user.order(&localnet, &pair, &greedy).await?;
    let greedy_fill = market_maker.fill(&localnet, &pair, &order.request).await?;
    let fair = Quote::price(
        &blocking(|| VaultState::read(rpc, &pair.vault))?,
        Direction::Deposit,
        SWAP_COLLATERAL,
        FEE_BPS,
    )?;
    assert_eq!(
        swap_error(
            user.verify_quote(&localnet, &pair, &order, &greedy_fill.message)
                .await
        )?,
        SwapError::BelowRate {
            expected: fair.amount_out,
            offered: greedy.quote.amount_out,
        }
    );
    user.sync(&localnet).await?;
    assert_eq!(user.holdings(&pair)?, UNTOUCHED);

    let offer = market_maker
        .quote(&localnet, &pair, Direction::Deposit, SWAP_COLLATERAL)
        .await?;
    let order = user.order(&localnet, &pair, &offer).await?;
    let maker_address = market_maker.address();
    let maker_identity = market_maker.identity();
    let misdirected = market_maker
        .with_wallet(|wallet, keypair| -> Result<_> {
            let inputs: Vec<_> = wallet
                .balance(pair.shares_mint, None)?
                .utxos
                .into_iter()
                .max_by_key(|utxo| utxo.utxo.amount)
                .into_iter()
                .collect();
            Transfer {
                width: inputs.len(),
                inputs,
                amount: offer.quote.amount_out,
                recipient: maker_identity,
                payer: maker_address,
                tree: localnet.tree,
                tree_id: localnet.tree_id,
            }
            .prove(&localnet.client, keypair)
        })
        .await?;
    let (blockhash, _) = blocking(|| rpc.get_latest_blockhash())?;
    let message = swap_message(
        &maker_address,
        [order.request.transfer.clone(), misdirected.instruction],
        blockhash,
    )?;
    assert_eq!(
        swap_error(user.verify_quote(&localnet, &pair, &order, &message).await)?,
        SwapError::UnexpectedOutputs { received: 0 }
    );
    user.sync(&localnet).await?;
    assert_eq!(user.holdings(&pair)?, UNTOUCHED);

    let abandoned = greedy_fill.step;
    let user_signature = user.sign(&greedy_fill.message)?;
    tokio::time::sleep_until((greedy_fill.expires_at + RELEASE_GRACE).into()).await;
    assert_eq!(market_maker.lanes(&pair.shares_mint), lanes_before);
    let late = market_maker
        .settle(greedy_fill, user_signature)
        .await
        .err()
        .ok_or_else(|| anyhow!("a settle after the deadline succeeded"))?;
    assert!(matches!(
        late.downcast_ref::<MakerError>(),
        Some(MakerError::UnknownFill { step }) if *step == abandoned
    ));

    let max = market_maker.max_user_inputs();
    let wide = smallest_shape(max + 1, USER_OUTPUTS)
        .ok_or_else(|| anyhow!("no shape wider than the user cap of {max}"))?
        .n_inputs();
    let offer = market_maker
        .quote(&localnet, &pair, Direction::Deposit, SWAP_COLLATERAL)
        .await?;
    let order = user
        .order_with_width(&localnet, &pair, &offer, Some(wide))
        .await?;
    assert_eq!(
        swap_error(market_maker.fill(&localnet, &pair, &order.request).await)?,
        SwapError::UserTransferTooWide { inputs: wide, max }
    );
    assert_eq!(market_maker.lanes(&pair.shares_mint), lanes_before);

    let offer = market_maker
        .quote(&localnet, &pair, Direction::Deposit, TWO_UTXO_COLLATERAL)
        .await?;
    let capped = Offer {
        max_user_inputs: 1,
        ..offer
    };
    assert_eq!(
        swap_error(user.order(&localnet, &pair, &capped).await)?,
        SwapError::TooManyInputs { needed: 2, max: 1 }
    );
    user.sync(&localnet).await?;
    assert_eq!(user.holdings(&pair)?, UNTOUCHED);
    market_maker.shutdown().await;
    Ok(())
}
