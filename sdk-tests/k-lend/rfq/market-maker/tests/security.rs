use std::time::Duration;

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_signature::Signature;
use zolana_program_test::localnet::LocalnetPorts;

use k_lend_market_maker::{
    instructions, ConcurrencyConfig, ConfigUpdate, ConnectionConfig, Holdings, IdentityConfig,
    InventoryProfile, MakerError, MarketMaker, MarketMakerConfig, PairConfig, QuoteConfig,
};
use k_lend_rfq_sdk::{
    pair::Pair,
    swap::{Direction, SwapError, SwapRequest},
};
use k_lend_rfq_test_utils::{
    chain::blocking,
    setup::{setup, setup_with, SetupConfig, TestEnv, USER_SHIELD_COLLATERAL},
};

fn swap_error(error: anyhow::Error) -> Result<SwapError> {
    error
        .downcast::<SwapError>()
        .map_err(|error| anyhow!("expected swap error, got {error:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maker_transfer_reuse_is_rejected_before_inventory_reservation() -> Result<()> {
    let TestEnv {
        localnet,
        user,
        market_maker,
        pair,
        ..
    } = setup(51).await?;
    market_maker
        .seed_inventory(&pair, 20_000_000, 50_000_000)
        .await?;
    let offer = market_maker
        .quote(&pair, Direction::Deposit, 10_000_000)
        .await?;
    let smaller = market_maker
        .quote(&pair, Direction::Deposit, 5_000_000)
        .await?;
    let smaller_order = user.order(&localnet, &pair, &smaller).await?;
    let underpaid = SwapRequest {
        quote: offer.quote,
        user: user.identity(),
        transfer: smaller_order.request.transfer.clone(),
    };
    assert_eq!(
        swap_error(
            market_maker
                .fill(&pair, &underpaid)
                .await
                .err()
                .ok_or_else(|| anyhow!("underpaid transfer accepted"))?
        )?,
        SwapError::Underpaid {
            expected: 10_000_000,
            received: 5_000_000
        }
    );
    let wrong_asset = SwapRequest {
        quote: market_maker
            .quote(&pair, Direction::Withdrawal, 5_000_000)
            .await?
            .quote,
        user: user.identity(),
        transfer: smaller_order.request.transfer,
    };
    assert_eq!(
        swap_error(
            market_maker
                .fill(&pair, &wrong_asset)
                .await
                .err()
                .ok_or_else(|| anyhow!("wrong input asset accepted"))?
        )?,
        SwapError::Underpaid {
            expected: 5_000_000,
            received: 0
        }
    );
    let order = user.order(&localnet, &pair, &offer).await?;
    let fill = market_maker.fill(&pair, &order.request).await?;
    let transfer = instructions(&fill.fill.message)?
        .into_iter()
        .nth(1)
        .ok_or_else(|| anyhow!("missing maker transfer"))?;
    let change = fill.change.iter().map(|utxo| utxo.utxo.amount).sum();
    let withdrawal = market_maker
        .quote(&pair, Direction::Withdrawal, change)
        .await?;
    let before = market_maker.inventory_utxos(&pair.token_mint);
    let request = SwapRequest {
        quote: withdrawal.quote,
        user: user.identity(),
        transfer,
    };
    let error = market_maker
        .fill(&pair, &request)
        .await
        .err()
        .ok_or_else(|| anyhow!("maker transfer was accepted"))?;
    assert_eq!(
        swap_error(error)?,
        SwapError::UserTransferSigner {
            expected: Address::new_from_array(user.identity().signing_pubkey.as_ed25519()?),
        }
    );
    assert_eq!(market_maker.inventory_utxos(&pair.token_mint), before);
    assert_eq!(
        user.holdings(&pair)?,
        Holdings {
            collateral: USER_SHIELD_COLLATERAL,
            shares: 0
        }
    );
    market_maker.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_retries_foreign_signatures_and_double_settlement_are_guarded() -> Result<()> {
    let TestEnv {
        localnet,
        user,
        market_maker,
        pair,
        ..
    } = setup_with(SetupConfig {
        concurrency: ConcurrencyConfig {
            profile: InventoryProfile::equal(4, 1_000_000),
            ..ConcurrencyConfig::default()
        },
        ..SetupConfig::new(53)
    })
    .await?;
    market_maker
        .seed_inventory(&pair, 40_000_000, 10_000_000)
        .await?;
    let offer = market_maker
        .quote(&pair, Direction::Deposit, 1_000_000)
        .await?;
    let order = user.order(&localnet, &pair, &offer).await?;
    let results =
        futures::future::join_all((0..4).map(|_| market_maker.fill(&pair, &order.request))).await;
    let mut fills = Vec::new();
    let mut rejected = 0;
    for result in results {
        match result {
            Ok(fill) => fills.push(fill),
            Err(error) => {
                assert!(matches!(
                    swap_error(error)?,
                    SwapError::DuplicateFill { .. }
                ));
                rejected += 1;
            }
        }
    }
    assert_eq!((fills.len(), rejected), (1, 3));
    let fill = fills.pop().ok_or_else(|| anyhow!("no fill"))?;
    let retry = user.order(&localnet, &pair, &offer).await?;
    assert_ne!(retry.request.transfer, order.request.transfer);
    assert!(matches!(
        swap_error(
            market_maker
                .fill(&pair, &retry.request)
                .await
                .err()
                .ok_or_else(|| anyhow!("overlapping transfer accepted"))?
        )?,
        SwapError::DuplicateFill { .. }
    ));
    let bad = market_maker
        .settle(&fill.fill, Signature::default())
        .await
        .err()
        .ok_or_else(|| anyhow!("foreign signature accepted"))?;
    assert!(matches!(
        bad.downcast_ref::<MakerError>(),
        Some(MakerError::InvalidUserSignature { .. })
    ));
    let wrong_pair = Pair::new(Address::new_from_array([42; 32]), pair.token_mint);
    assert_eq!(
        swap_error(
            user.verify_quote(&localnet, &wrong_pair, &order, &fill.fill.message)
                .await
                .err()
                .ok_or_else(|| anyhow!("wrong pair accepted"))?
        )?,
        SwapError::WrongPair
    );
    let signature = user.sign(&fill.fill.message)?;
    let (first, second) = tokio::join!(
        market_maker.settle(&fill.fill, signature),
        market_maker.settle(&fill.fill, signature)
    );
    let (landed, duplicate) = match (first, second) {
        (Ok(signature), Err(error)) | (Err(error), Ok(signature)) => (signature, error),
        _ => return Err(anyhow!("expected exactly one successful settlement")),
    };
    assert!(matches!(
        duplicate.downcast_ref::<MakerError>(),
        Some(MakerError::AlreadySettling { .. })
    ));
    // Confirmation inserts the user's payment before waiting for Photon to index it.
    assert_eq!(
        market_maker.holdings(&pair),
        Holdings {
            collateral: 11_000_000,
            shares: 40_000_000 - offer.quote.amount_out
        }
    );
    blocking(|| localnet.client.confirm_private_transaction_sync(landed))
        .map_err(|error| anyhow!("index: {error:?}"))?;
    assert!(matches!(
        swap_error(
            market_maker
                .fill(&pair, &order.request)
                .await
                .err()
                .ok_or_else(|| anyhow!("spent transfer accepted"))?
        )?,
        SwapError::UserInputSpent { .. }
    ));
    market_maker.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_releases_unsigned_fills_and_restart_recovers_inventory() -> Result<()> {
    let TestEnv {
        localnet,
        user,
        market_maker,
        pair,
        ..
    } = setup(54).await?;
    market_maker.seed_inventory(&pair, 20_000_000, 0).await?;
    let offer = market_maker
        .quote(&pair, Direction::Deposit, 1_000_000)
        .await?;
    let order = user.order(&localnet, &pair, &offer).await?;
    let fill = market_maker.fill(&pair, &order.request).await?;
    assert!(market_maker
        .inventory_utxos(&pair.shares_mint)
        .iter()
        .any(|utxo| utxo.reserved));
    market_maker.shutdown().await;
    let error = market_maker
        .settle(&fill.fill, user.sign(&fill.fill.message)?)
        .await
        .err()
        .ok_or_else(|| anyhow!("settled after shutdown"))?;
    assert!(matches!(
        error.downcast_ref::<MakerError>(),
        Some(MakerError::ShuttingDown)
    ));
    assert!(market_maker
        .inventory_utxos(&pair.shares_mint)
        .iter()
        .all(|utxo| !utxo.reserved));
    let ports = LocalnetPorts::for_test(54)?;
    let restarted = MarketMaker::start(MarketMakerConfig {
        connection: ConnectionConfig {
            rpc_url: ports.rpc_url(),
            photon_url: ports.photon_url(),
            prover_url: None,
            tree: localnet.tree,
            tree_id: localnet.tree_id,
        },
        identity: IdentityConfig {
            keypair: market_maker.keypair().clone(),
        },
        pairs: vec![PairConfig::new(pair)],
        concurrency: ConcurrencyConfig::default(),
        quotes: QuoteConfig::default(),
    })
    .await?;
    assert_eq!(
        restarted.holdings(&pair),
        Holdings {
            collateral: 0,
            shares: 20_000_000
        }
    );
    restarted.fill(&pair, &order.request).await?;
    restarted.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offers_capture_fees_and_settlement_keeps_the_accepted_terms() -> Result<()> {
    let TestEnv {
        localnet,
        user,
        market_maker,
        pair,
        ..
    } = setup(55).await?;
    market_maker.seed_inventory(&pair, 20_000_000, 0).await?;
    for fee_bps in [10_000, 10_001, u64::MAX] {
        let error = market_maker
            .update_config(ConfigUpdate {
                fee_bps: Some(fee_bps),
                ..ConfigUpdate::default()
            })
            .await
            .err()
            .ok_or_else(|| anyhow!("invalid fee accepted"))?;
        assert!(
            matches!(error.downcast_ref::<MakerError>(), Some(MakerError::Swap(SwapError::InvalidFee { fee_bps: rejected })) if *rejected == fee_bps)
        );
    }
    market_maker
        .update_config(ConfigUpdate {
            fee_bps: Some(80),
            ..ConfigUpdate::default()
        })
        .await?;
    let offer = market_maker
        .quote(&pair, Direction::Deposit, 1_000_000)
        .await?;
    assert_eq!(offer.fee_bps, 80);
    let order = user.order(&localnet, &pair, &offer).await?;
    let fill = market_maker.fill(&pair, &order.request).await?;
    market_maker
        .update_config(ConfigUpdate {
            fee_bps: Some(30),
            ..ConfigUpdate::default()
        })
        .await?;
    user.verify_quote(&localnet, &pair, &order, &fill.fill.message)
        .await?;
    market_maker
        .settle(&fill.fill, user.sign(&fill.fill.message)?)
        .await?;
    market_maker.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_fills_release_user_inputs_for_a_retry() -> Result<()> {
    let TestEnv {
        localnet,
        user,
        market_maker,
        pair,
        ..
    } = setup_with(SetupConfig {
        quote_ttl: Duration::from_secs(2),
        ..SetupConfig::new(52)
    })
    .await?;
    market_maker.seed_inventory(&pair, 20_000_000, 0).await?;
    let offer = market_maker
        .quote(&pair, Direction::Deposit, 1_000_000)
        .await?;
    let order = user.order(&localnet, &pair, &offer).await?;
    let fill = market_maker.fill(&pair, &order.request).await?;
    tokio::time::sleep_until((fill.fill.expires_at + Duration::from_secs(2)).into()).await;
    market_maker.fill(&pair, &order.request).await?;
    market_maker.shutdown().await;
    Ok(())
}
