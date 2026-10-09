use anyhow::{anyhow, Result};
use solana_message::v1;
use zolana_client::transaction_size;
use zolana_interface::{pda, PROGRAM_ID_PUBKEY};

use kamino_vault_rfq_sdk::{
    kvault::{self, token_balance, VaultState},
    swap::{
        instructions, legs, Direction, Holdings, Spend, VaultOperation, MAKER_CACHE_SLOT,
        SWAP_COMPUTE_BUDGET,
    },
};

use crate::shared::{
    blocking, compute_units, landed, public_balances, setup, Landed, TestEnv, USER_SHIELD_USDC,
};

const BOOTSTRAP_USDC: u64 = 200_000_000;
const SWAPS: [u64; 2] = [20_000_000, 30_000_000];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_deposits_settle_through_the_market_maker() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        usdc_mint,
        vault,
        ..
    } = setup(12).await?;
    let rpc = localnet.client.rpc();

    let before_bootstrap = blocking(|| VaultState::read(rpc, &vault.vault))?;
    let predicted = before_bootstrap.deposit(BOOTSTRAP_USDC)?;
    let bootstrap = market_maker
        .bootstrap(&localnet, &vault, BOOTSTRAP_USDC)
        .await?;
    assert_eq!(
        bootstrap,
        VaultOperation {
            before: before_bootstrap,
            after: predicted.after,
            tokens: predicted.tokens,
            shares: predicted.shares,
            inputs: 0,
            signature: bootstrap.signature,
        }
    );
    let bootstrap_shares = market_maker
        .lanes(&vault.shares_mint)
        .first()
        .map(|lane| lane.nullifier)
        .ok_or_else(|| anyhow!("bootstrap shares missing"))?;

    let custody = [
        pda::spl_interface(&usdc_mint),
        pda::spl_interface(&vault.shares_mint),
    ];
    let custody_balances = || -> Result<Vec<u64>> {
        blocking(|| {
            custody
                .iter()
                .map(|account| token_balance(rpc, account))
                .collect()
        })
    };
    let mut pending = Vec::new();
    let mut spends = Vec::new();
    let mut changes = Vec::new();
    let mut signatures = Vec::new();
    let mut shares_received = 0;
    for amount_in in SWAPS {
        let offer = market_maker
            .quote(&localnet, &vault, Direction::Deposit, amount_in)
            .await?;
        let order = user.order(&localnet, &vault, &offer, &pending).await?;
        let fill = market_maker.fill(&localnet, &vault, &order.request).await?;
        user.verify_quote(&localnet, &vault, &order, &fill.message)
            .await?;
        assert_eq!(
            legs(&fill.message)?
                .into_iter()
                .map(|leg| leg.interface_transfers)
                .collect::<Vec<_>>(),
            vec![Vec::new(), Vec::new()]
        );
        let size = transaction_size(
            &market_maker.address(),
            &instructions(&fill.message)?,
            SWAP_COMPUTE_BUDGET,
        )?;
        assert!(size.bytes <= v1::MAX_TRANSACTION_SIZE);
        assert!(size.addresses <= usize::from(v1::MAX_ADDRESSES));
        println!(
            "swap transaction: {} of {} bytes, {} of {} addresses, user leg cap {} inputs",
            size.bytes,
            v1::MAX_TRANSACTION_SIZE,
            size.addresses,
            v1::MAX_ADDRESSES,
            offer.max_user_inputs
        );
        let user_signature = user.sign(&fill.message)?;
        spends.extend(fill.spent.iter().copied());
        changes.push(
            fill.change
                .first()
                .map(|change| change.nullifier)
                .ok_or_else(|| anyhow!("fill without change"))?,
        );

        let custody_before = custody_balances()?;
        let signature = market_maker.settle(fill, user_signature).await?;
        assert_eq!(custody_balances()?, custody_before);
        println!(
            "swap of {amount_in} USDC for {} shares: {} CU",
            offer.quote.amount_out,
            blocking(|| compute_units(rpc, &signature))?
        );

        pending.extend(order.inputs.iter().map(|input| input.nullifier));
        signatures.push(signature);
        shares_received += offer.quote.amount_out;
    }
    assert_eq!(
        spends,
        vec![
            Spend {
                nullifier: bootstrap_shares,
                cache_slot: None,
            },
            Spend {
                nullifier: *changes.first().ok_or_else(|| anyhow!("no first fill"))?,
                cache_slot: Some(MAKER_CACHE_SLOT),
            },
        ]
    );

    for signature in signatures {
        blocking(|| localnet.client.confirm_private_transaction_sync(signature))
            .map_err(|e| anyhow!("index swap {signature}: {e:?}"))?;
    }
    user.sync(&localnet).await?;
    market_maker.sync().await?;

    let usdc_received: u64 = SWAPS.iter().sum();
    assert_eq!(
        user.holdings(&vault)?,
        Holdings {
            usdc: USER_SHIELD_USDC - usdc_received,
            shares: shares_received,
        }
    );
    assert_eq!(
        market_maker.holdings(&vault),
        Holdings {
            usdc: usdc_received,
            shares: bootstrap.shares - shares_received,
        }
    );

    let maker = market_maker.address();
    let public_before = blocking(|| public_balances(rpc, &maker, &vault))?;
    let before_rebalance = blocking(|| VaultState::read(rpc, &vault.vault))?;
    let predicted = before_rebalance.deposit(usdc_received)?;
    let rebalance = market_maker
        .rebalance_deposit(&localnet, &vault, usdc_received)
        .await?;
    assert_eq!(
        blocking(|| public_balances(rpc, &maker, &vault))?,
        public_before
    );
    assert_eq!(
        blocking(|| landed(rpc, &rebalance.signature))?,
        Landed {
            signatures: 1,
            programs: vec![PROGRAM_ID_PUBKEY, kvault::PROGRAM_ID, PROGRAM_ID_PUBKEY],
        }
    );
    println!(
        "rebalance deposit of {} inputs: {} CU",
        rebalance.inputs,
        blocking(|| compute_units(rpc, &rebalance.signature))?
    );
    assert_eq!(
        rebalance,
        VaultOperation {
            before: before_rebalance,
            after: predicted.after,
            tokens: usdc_received,
            shares: predicted.shares,
            inputs: SWAPS.len(),
            signature: rebalance.signature,
        }
    );
    assert_eq!(
        market_maker.holdings(&vault),
        Holdings {
            usdc: 0,
            shares: bootstrap.shares - shares_received + rebalance.shares,
        }
    );
    Ok(())
}
