use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

use anyhow::{anyhow, Result};
use solana_signature::Signature;
use tokio::{sync::Barrier, task::JoinSet};
use zolana_program_test::localnet::FixtureLocalnet;

use kamino_vault_market_maker::{ConsolidateReceipt, MarketMaker};
use kamino_vault_rfq_sdk::{
    kvault::{VaultAccounts, VaultState},
    swap::{Direction, Holdings, Quote, VaultOperation},
};

use crate::{
    shared::{blocking, compute_units, setup_with, SetupConfig, TestEnv},
    user::User,
};

const TEST_NUMBER: u16 = 16;
const LANES: usize = 4;
const EXTRA_USERS: u8 = 7;
const USERS: usize = 8;
const BOOTSTRAP_USDC: u64 = 400_000_000;
const DEPOSIT_USDC: u64 = 10_000_000;
const USER_USDC: u64 = 40_000_000;

struct Settled {
    user: User,
    quote: Quote,
    signature: Signature,
    change_outputs: usize,
    proved: Instant,
    confirmed: Instant,
}

struct Gate {
    tickets: AtomicUsize,
    first_lanes: Barrier,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn serves_many_rfqs_at_once() -> Result<()> {
    let TestEnv {
        localnet,
        user,
        users,
        market_maker,
        vault,
        ..
    } = setup_with(SetupConfig {
        test: TEST_NUMBER,
        extra_users: EXTRA_USERS,
        lanes: LANES,
        websocket: true,
        user_usdc: USER_USDC,
    })
    .await?;
    let bootstrap = market_maker
        .bootstrap(&localnet, &vault, BOOTSTRAP_USDC)
        .await?;
    assert_eq!(market_maker.lanes(&vault.shares_mint).len(), LANES);

    let localnet = Arc::new(localnet);
    let gate = Arc::new(Gate {
        tickets: AtomicUsize::new(0),
        first_lanes: Barrier::new(LANES),
    });
    let ordered = Arc::new(Barrier::new(USERS));
    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for user in std::iter::once(user).chain(users) {
        tasks.spawn(deposit(
            localnet.clone(),
            vault,
            market_maker.clone(),
            user,
            ordered.clone(),
            gate.clone(),
        ));
    }
    let mut settled = Vec::with_capacity(USERS);
    while let Some(joined) = tasks.join_next().await {
        settled.push(joined??);
    }
    let elapsed = started.elapsed();
    assert_eq!(settled.len(), USERS);

    let first_confirmed = settled
        .iter()
        .map(|fill| fill.confirmed)
        .min()
        .ok_or_else(|| anyhow!("no fill confirmed"))?;
    let proved_before_first_confirmation = settled
        .iter()
        .filter(|fill| fill.proved < first_confirmed)
        .count();
    assert!(proved_before_first_confirmation >= LANES);
    let change_outputs: usize = settled.iter().map(|fill| fill.change_outputs).sum();
    assert!(change_outputs > USERS);
    println!(
        "{USERS} concurrent deposits on {LANES} lanes in {elapsed:?}: \
         {proved_before_first_confirmation} proved before the first confirmed, \
         {change_outputs} change outputs"
    );

    for fill in &settled {
        let signature = fill.signature;
        blocking(|| localnet.client.confirm_private_transaction_sync(signature))
            .map_err(|e| anyhow!("index swap {signature}: {e:?}"))?;
    }
    let mut shares_paid = 0;
    for fill in &mut settled {
        fill.user.sync(&localnet).await?;
        assert_eq!(
            fill.user.holdings(&vault)?,
            Holdings {
                usdc: USER_USDC - DEPOSIT_USDC,
                shares: fill.quote.amount_out,
            }
        );
        shares_paid += fill.quote.amount_out;
    }
    market_maker.sync().await?;
    let usdc_received = DEPOSIT_USDC * u64::try_from(USERS)?;
    assert_eq!(
        market_maker.holdings(&vault),
        Holdings {
            usdc: usdc_received,
            shares: bootstrap.shares - shares_paid,
        }
    );
    assert_eq!(
        market_maker.lanes(&vault.shares_mint).len(),
        LANES + change_outputs - USERS
    );
    assert_eq!(market_maker.lanes(&vault.token_mint).len(), USERS);

    let grown = market_maker.lanes(&vault.shares_mint).len();
    let consolidation = market_maker.consolidate(vault.shares_mint).await?;
    assert_eq!(
        consolidation,
        ConsolidateReceipt {
            signature: consolidation.signature,
            inputs: grown,
            outputs: LANES,
        }
    );
    market_maker.sync().await?;
    assert_eq!(market_maker.lanes(&vault.shares_mint).len(), LANES);
    assert_eq!(
        market_maker.holdings(&vault),
        Holdings {
            usdc: usdc_received,
            shares: bootstrap.shares - shares_paid,
        }
    );

    let rpc = localnet.client.rpc();
    let before_rebalance = blocking(|| VaultState::read(rpc, &vault.vault))?;
    let predicted = before_rebalance.deposit(usdc_received)?;
    let rebalance = market_maker
        .rebalance_deposit(&localnet, &vault, usdc_received)
        .await?;
    assert_eq!(
        rebalance,
        VaultOperation {
            before: before_rebalance,
            after: predicted.after,
            tokens: usdc_received,
            shares: predicted.shares,
            inputs: USERS,
            signature: rebalance.signature,
        }
    );
    assert_eq!(
        market_maker.holdings(&vault),
        Holdings {
            usdc: 0,
            shares: bootstrap.shares - shares_paid + rebalance.shares,
        }
    );
    assert_eq!(market_maker.lanes(&vault.token_mint), Vec::new());
    println!(
        "rebalance deposit of {} inputs: {} CU",
        rebalance.inputs,
        blocking(|| compute_units(rpc, &rebalance.signature))?
    );
    Ok(())
}

async fn deposit(
    localnet: Arc<FixtureLocalnet>,
    vault: VaultAccounts,
    market_maker: MarketMaker,
    user: User,
    ordered: Arc<Barrier>,
    gate: Arc<Gate>,
) -> Result<Settled> {
    let offer = market_maker
        .quote(&localnet, &vault, Direction::Deposit, DEPOSIT_USDC)
        .await?;
    let order = user.order(&localnet, &vault, &offer, &[]).await?;
    ordered.wait().await;
    let fill = market_maker.fill(&localnet, &vault, &order.request).await?;
    let proved = Instant::now();
    if gate.tickets.fetch_add(1, Ordering::SeqCst) < LANES {
        gate.first_lanes.wait().await;
    }
    user.verify_quote(&localnet, &vault, &order, &fill.message)
        .await?;
    let user_signature = user.sign(&fill.message)?;
    let change_outputs = fill.change.len();
    let signature = market_maker.settle(fill, user_signature).await?;
    Ok(Settled {
        user,
        quote: offer.quote,
        signature,
        change_outputs,
        proved,
        confirmed: Instant::now(),
    })
}
