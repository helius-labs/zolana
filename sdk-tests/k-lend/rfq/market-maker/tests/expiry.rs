use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use solana_instruction::{error::InstructionError, Instruction};
use solana_transaction_error::TransactionError;
use zolana_client::{sign_transaction, ClientError, Rpc};
use zolana_interface::{error::ShieldedPoolError, instruction::tag};
use zolana_program_test::localnet::FixtureLocalnet;

use k_lend_market_maker::{instructions, swap_message, transfers, Holdings, MarketMaker};
use k_lend_rfq_sdk::{swap::Direction, user::UserOrder};
use k_lend_rfq_test_utils::{
    chain::blocking,
    setup::{setup_with, SetupConfig, TestEnv, USER_SHIELD_COLLATERAL},
    user::User,
};

const SEED_DEPOSIT: u64 = 200_000_000;
const SWAP_COLLATERAL: u64 = 1_000_000;
const USER_TRANSFER_TTL: Duration = Duration::from_secs(90);

fn reject_swap(
    localnet: &FixtureLocalnet,
    user: &User,
    maker: &MarketMaker,
    user_transfer: Instruction,
    maker_transfer: Instruction,
) -> Result<TransactionError> {
    blocking(|| {
        let rpc = localnet.client.rpc();
        let (blockhash, _) = rpc.get_latest_blockhash()?;
        let message = swap_message(&maker.address(), [user_transfer, maker_transfer], blockhash)?;
        let error = rpc
            .process_transaction(sign_transaction(
                message,
                &[maker.keypair(), &user.wallet().keypair],
            )?)
            .err()
            .ok_or_else(|| anyhow!("invalid user transfer was accepted"))?;
        match error {
            ClientError::SolanaRpcTransaction { source, .. } => source
                .get_transaction_error()
                .ok_or_else(|| anyhow!("expected a transaction rejection, got {source}")),
            other => Err(anyhow!("expected a transaction rejection, got {other}")),
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_transfer_expiry_is_configured_bound_and_enforced_on_chain() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        pair,
        ..
    } = setup_with(SetupConfig {
        user_transfer_ttl: USER_TRANSFER_TTL,
        quote_ttl: Duration::from_secs(120),
        ..SetupConfig::new(48)
    })
    .await?;
    market_maker.seed_inventory(&pair, SEED_DEPOSIT, 0).await?;
    let offer = market_maker
        .quote(&pair, Direction::Deposit, SWAP_COLLATERAL)
        .await?;
    let earliest = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .checked_add(USER_TRANSFER_TTL)
        .ok_or_else(|| anyhow!("expiry overflow"))?
        .as_secs();
    let order = user.order(&localnet, &pair, &offer).await?;
    let latest = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .checked_add(USER_TRANSFER_TTL)
        .ok_or_else(|| anyhow!("expiry overflow"))?
        .as_secs();
    let user_before = user.holdings(&pair)?;
    let maker_before = market_maker.holdings(&pair);
    let fill = market_maker.fill(&pair, &order.request).await?;
    let mut user_data = transfers(&fill.fill.message)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("fill has no user transfer"))?;
    assert!((earliest..=latest).contains(&user_data.expiry_unix_ts));
    let maker_transfer = instructions(&fill.fill.message)?
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow!("fill has no maker transfer"))?;

    // Extending the deadline after proving must invalidate the existing proof.
    user_data.expiry_unix_ts = u64::MAX;
    let mut extended = order.request.transfer.clone();
    extended.data = std::iter::once(tag::TRANSACT)
        .chain(user_data.serialize()?)
        .collect();
    assert_eq!(
        reject_swap(
            &localnet,
            &user,
            &market_maker,
            extended,
            maker_transfer.clone()
        )?,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(ShieldedPoolError::TransactProofVerificationFailed as u32),
        )
    );

    // A deadline committed before proving must still be checked at execution.
    let expired = blocking(|| {
        UserOrder {
            offer,
            inputs: order.inputs.clone(),
            width: None,
            tree: localnet.tree,
            tree_id: localnet.tree_id,
            expiry_unix_ts: 0,
        }
        .prove(&localnet.client, &user.wallet().keypair)
    })?;
    assert_eq!(
        reject_swap(
            &localnet,
            &user,
            &market_maker,
            expired.request.transfer,
            maker_transfer,
        )?,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(ShieldedPoolError::ExpiredTransaction as u32),
        )
    );
    user.sync(&localnet).await?;
    market_maker.sync().await?;
    assert_eq!(user.holdings(&pair)?, user_before);
    assert_eq!(market_maker.holdings(&pair), maker_before);

    // The original proof and deadline still allow the intended swap to settle.
    user.verify_quote(&localnet, &pair, &order, &fill.fill.message)
        .await?;
    let signature = market_maker
        .settle(&fill.fill, user.sign(&fill.fill.message)?)
        .await?;
    blocking(|| localnet.client.confirm_private_transaction_sync(signature))?;
    user.sync(&localnet).await?;
    assert_eq!(
        user.holdings(&pair)?,
        Holdings {
            collateral: USER_SHIELD_COLLATERAL - SWAP_COLLATERAL,
            shares: offer.quote.amount_out,
        }
    );
    market_maker.shutdown().await;
    Ok(())
}
