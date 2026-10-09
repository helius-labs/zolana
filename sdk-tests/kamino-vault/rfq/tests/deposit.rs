use anyhow::Result;
use zolana_interface::pda;

use crate::{
    kvault::{token_balance, VaultState},
    market_maker::{Direction, VaultOperation},
    shared::{compute_units, setup, Holdings, TestEnv, FEE_BPS, USER_SHIELD_USDC},
};

const BOOTSTRAP_USDC: u64 = 200_000_000;
const SWAPS: [u64; 2] = [20_000_000, 30_000_000];

#[test]
fn private_deposits_settle_through_the_market_maker() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        mut market_maker,
        usdc_mint,
        vault,
    } = setup(12)?;
    let rpc = localnet.client.rpc();

    let before_bootstrap = VaultState::read(rpc, &vault.vault)?;
    let predicted = before_bootstrap.deposit(BOOTSTRAP_USDC)?;
    let bootstrap = market_maker.bootstrap(&localnet, &vault, BOOTSTRAP_USDC)?;
    assert_eq!(
        bootstrap,
        VaultOperation {
            before: before_bootstrap,
            after: predicted.after,
            tokens: predicted.tokens,
            shares: predicted.shares,
        }
    );

    let custody = [
        pda::spl_interface(&usdc_mint),
        pda::spl_interface(&vault.shares_mint),
    ];
    let custody_balances = || -> Result<Vec<u64>> {
        custody
            .iter()
            .map(|account| token_balance(rpc, account))
            .collect()
    };
    let mut shares_received = 0;
    for amount_in in SWAPS {
        let quote = market_maker.quote(&localnet, &vault, Direction::Deposit, amount_in)?;
        let order = user.order(&vault, quote)?;
        let fill = market_maker.fill(&localnet, &vault, &order, &user.keypair.nullifier_key)?;
        user.verify_quote(&localnet, &vault, &order, &fill, FEE_BPS)?;
        assert_eq!(fill.data.interface_transfers, Vec::new());

        let custody_before = custody_balances()?;
        let signature = market_maker.settle(&localnet, fill, &user.keypair)?;
        assert_eq!(custody_balances()?, custody_before);
        println!(
            "swap of {amount_in} USDC for {} shares: {} CU",
            quote.amount_out,
            compute_units(rpc, &signature)?
        );

        shares_received += quote.amount_out;
        user.sync(&localnet)?;
        market_maker.trader.sync(&localnet)?;
    }

    let usdc_received: u64 = SWAPS.iter().sum();
    assert_eq!(
        user.holdings(&vault)?,
        Holdings {
            usdc: USER_SHIELD_USDC - usdc_received,
            shares: shares_received,
        }
    );
    assert_eq!(
        market_maker.trader.holdings(&vault)?,
        Holdings {
            usdc: usdc_received,
            shares: bootstrap.shares - shares_received,
        }
    );

    let before_rebalance = VaultState::read(rpc, &vault.vault)?;
    let predicted = before_rebalance.deposit(usdc_received)?;
    let rebalance = market_maker.rebalance_deposit(&localnet, &vault, usdc_received)?;
    assert_eq!(
        rebalance,
        VaultOperation {
            before: before_rebalance,
            after: predicted.after,
            tokens: usdc_received,
            shares: predicted.shares,
        }
    );
    assert_eq!(
        market_maker.trader.holdings(&vault)?,
        Holdings {
            usdc: 0,
            shares: bootstrap.shares - shares_received + rebalance.shares,
        }
    );
    Ok(())
}
