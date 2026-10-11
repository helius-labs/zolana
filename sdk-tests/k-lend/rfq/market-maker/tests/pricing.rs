use anyhow::{anyhow, Result};
use zolana_client::Rpc;

use k_lend_market_maker::{swap_message, Holdings};
use k_lend_rfq_sdk::{
    pair::VaultState,
    swap::{Direction, Quote, SwapError},
    transfer::{Receiver, Transfer},
    user::QuoteCheck,
};
use k_lend_rfq_test_utils::{
    chain::blocking,
    setup::{setup, TestEnv, FEE_BPS, USER_SHIELD_COLLATERAL},
};

const SEED_SHARES: u64 = 200_000_000;
const SEED_COLLATERAL: u64 = 50_000_000;

fn swap_error(result: Result<impl Sized>) -> Result<SwapError> {
    let error = result
        .err()
        .ok_or_else(|| anyhow!("expected a swap error"))?;
    error
        .downcast::<SwapError>()
        .map_err(|error| anyhow!("expected a swap error, got {error:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fill_rejects_forged_prices_in_both_directions() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        pair,
        ..
    } = setup(49).await?;
    market_maker
        .seed_inventory(&pair, SEED_SHARES, SEED_COLLATERAL)
        .await?;

    for (direction, amount_in) in [
        (Direction::Deposit, 1_000_000),
        (Direction::Withdrawal, 500_000),
    ] {
        let offer = market_maker.quote(&pair, direction, amount_in).await?;
        let mut order = user.order(&localnet, &pair, &offer).await?;
        let user_before = user.holdings(&pair)?;
        let maker_before = market_maker.holdings(&pair);
        let (_, asset_out) = direction.assets(&pair);
        let inventory_before = market_maker.inventory_utxos(&asset_out);
        for amount_out in [
            100_000_000,
            offer.quote.amount_out.saturating_sub(1),
            offer.quote.amount_out.saturating_add(1),
        ] {
            order.request.quote.amount_out = amount_out;
            assert_eq!(
                swap_error(market_maker.fill(&pair, &order.request).await)?,
                SwapError::QuoteMismatch {
                    expected: offer.quote.amount_out,
                    requested: amount_out,
                }
            );
            assert_eq!(market_maker.inventory_utxos(&asset_out), inventory_before);
            assert_eq!(market_maker.holdings(&pair), maker_before);
            user.sync(&localnet).await?;
            assert_eq!(user.holdings(&pair)?, user_before);
        }

        order.request.quote = offer.quote;
        let fill = market_maker.fill(&pair, &order.request).await?;
        user.verify_quote(&localnet, &pair, &order, &fill.fill.message)
            .await?;
        let signature = market_maker
            .settle(&fill.fill, user.sign(&fill.fill.message)?)
            .await?;
        blocking(|| localnet.client.confirm_private_transaction_sync(signature))
            .map_err(|error| anyhow!("index swap: {error:?}"))?;
        user.sync(&localnet).await?;
        market_maker.sync().await?;
    }
    assert_eq!(
        user.holdings(&pair)?,
        Holdings {
            collateral: USER_SHIELD_COLLATERAL - 1_000_000 + 498_500,
            shares: 997_000 - 500_000,
        }
    );
    assert_eq!(
        market_maker.holdings(&pair),
        Holdings {
            collateral: SEED_COLLATERAL + 1_000_000 - 498_500,
            shares: SEED_SHARES - 997_000 + 500_000,
        }
    );
    market_maker.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quote_check_enforces_the_agreed_payout_after_a_rate_drop() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        pair,
        ..
    } = setup(50).await?;
    market_maker
        .seed_inventory(&pair, SEED_SHARES, SEED_COLLATERAL)
        .await?;
    let deposit = market_maker
        .quote(&pair, Direction::Deposit, 10_000_000)
        .await?;
    let deposit_order = user.order(&localnet, &pair, &deposit).await?;
    let fill = market_maker.fill(&pair, &deposit_order.request).await?;
    user.verify_quote(&localnet, &pair, &deposit_order, &fill.fill.message)
        .await?;
    let signature = market_maker
        .settle(&fill.fill, user.sign(&fill.fill.message)?)
        .await?;
    blocking(|| localnet.client.confirm_private_transaction_sync(signature))
        .map_err(|error| anyhow!("index deposit: {error:?}"))?;
    user.sync(&localnet).await?;
    market_maker.sync().await?;

    let offer = market_maker
        .quote(&pair, Direction::Withdrawal, 1_000_000)
        .await?;
    let mut order = user.order(&localnet, &pair, &offer).await?;
    let rate = blocking(|| VaultState::read(localnet.client.rpc(), &pair.vault))?;
    let discounted_rate = VaultState {
        token_available: rate.token_available / 2,
        ..rate
    };
    let discounted = Quote::price(
        &discounted_rate,
        offer.quote.direction,
        offer.quote.amount_in,
        FEE_BPS,
    )?;
    let receiver = Receiver {
        keypair: &user.wallet().keypair,
        registry: &user.wallet().registry,
        tree_id: localnet.tree_id,
    };
    for amount_out in [900_000, offer.quote.amount_out] {
        assert!(amount_out >= discounted.amount_out);
        let inputs: Vec<_> = market_maker
            .wallet_utxos(&pair.token_mint)
            .into_iter()
            .max_by_key(|utxo| utxo.utxo.amount)
            .into_iter()
            .collect();
        // Build a maker payout independently so fill's price guard cannot mask QuoteCheck.
        let transfer = blocking(|| {
            Transfer {
                width: inputs.len(),
                inputs,
                amount: amount_out,
                recipient: user.identity(),
                payer: market_maker.address(),
                tree: localnet.tree,
                tree_id: localnet.tree_id,
                expiry_unix_ts: u64::MAX,
            }
            .prove(&localnet.client, market_maker.keypair())
        })?;
        let (blockhash, _) = blocking(|| localnet.client.rpc().get_latest_blockhash())?;
        let message = swap_message(
            &market_maker.address(),
            [order.request.transfer.clone(), transfer.instruction],
            blockhash,
        )?;
        order.offer = offer;
        let result = QuoteCheck {
            order: &order,
            message: &message,
            pair: &pair,
        }
        .verify(&receiver);
        if amount_out < offer.quote.amount_out {
            assert_eq!(
                swap_error(result)?,
                SwapError::BelowQuote {
                    expected: offer.quote.amount_out,
                    offered: amount_out,
                }
            );
        } else {
            result?;
        }
        // Exercise the exact boundary and a payout above the accepted amount.
        for agreed in [amount_out, amount_out.saturating_sub(1)] {
            order.offer.quote.amount_out = agreed;
            QuoteCheck {
                order: &order,
                message: &message,
                pair: &pair,
            }
            .verify(&receiver)?;
        }
        order.offer.quote.amount_out = amount_out.saturating_add(1);
        assert_eq!(
            swap_error(
                QuoteCheck {
                    order: &order,
                    message: &message,
                    pair: &pair,
                }
                .verify(&receiver)
            )?,
            SwapError::BelowQuote {
                expected: amount_out + 1,
                offered: amount_out,
            }
        );
    }
    market_maker.shutdown().await;
    Ok(())
}
