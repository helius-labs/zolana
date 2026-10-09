use anyhow::Result;

use crate::{
    kvault::VaultState,
    market_maker::{Direction, VaultOperation},
    shared::{setup, Holdings, TestEnv, FEE_BPS, USER_SHIELD_USDC},
};

const BOOTSTRAP_USDC: u64 = 200_000_000;
const DEPOSIT_USDC: u64 = 40_000_000;
const EXIT_SHARES: u64 = 15_000_000;

#[test]
fn delayed_exit_settles_after_the_market_maker_withdraws() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        mut market_maker,
        vault,
        ..
    } = setup(13)?;
    let rpc = localnet.client.rpc();
    let bootstrap = market_maker.bootstrap(&localnet, &vault, BOOTSTRAP_USDC)?;

    let deposit = market_maker.quote(&localnet, &vault, Direction::Deposit, DEPOSIT_USDC)?;
    let order = user.order(&vault, deposit)?;
    let fill = market_maker.fill(&localnet, &vault, &order, &user.keypair.nullifier_key)?;
    user.verify_quote(&localnet, &vault, &order, &fill, FEE_BPS)?;
    market_maker.settle(&localnet, fill, &user.keypair)?;
    user.sync(&localnet)?;
    market_maker.trader.sync(&localnet)?;

    let before_withdraw = VaultState::read(rpc, &vault.vault)?;
    let predicted = before_withdraw.withdraw(EXIT_SHARES)?;
    let withdraw = market_maker.rebalance_withdraw(&localnet, &vault, EXIT_SHARES)?;
    assert_eq!(
        withdraw,
        VaultOperation {
            before: before_withdraw,
            after: predicted.after,
            tokens: predicted.tokens,
            shares: predicted.shares,
        }
    );

    let exit = market_maker.quote(&localnet, &vault, Direction::Exit, EXIT_SHARES)?;
    let order = user.order(&vault, exit)?;
    let fill = market_maker.fill(&localnet, &vault, &order, &user.keypair.nullifier_key)?;
    user.verify_quote(&localnet, &vault, &order, &fill, FEE_BPS)?;
    market_maker.settle(&localnet, fill, &user.keypair)?;
    user.sync(&localnet)?;
    market_maker.trader.sync(&localnet)?;

    assert_eq!(
        user.holdings(&vault)?,
        Holdings {
            usdc: USER_SHIELD_USDC - DEPOSIT_USDC + exit.amount_out,
            shares: deposit.amount_out - EXIT_SHARES,
        }
    );
    assert_eq!(
        market_maker.trader.holdings(&vault)?,
        Holdings {
            usdc: DEPOSIT_USDC + withdraw.tokens - exit.amount_out,
            shares: bootstrap.shares - deposit.amount_out,
        }
    );
    Ok(())
}
