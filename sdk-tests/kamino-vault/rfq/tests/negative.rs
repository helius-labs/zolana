use anyhow::{anyhow, Result};

use crate::{
    kvault::VaultState,
    market_maker::{Direction, Quote, SwapError},
    shared::{setup, Holdings, TestEnv, FEE_BPS, USER_SHIELD_USDC},
};

const BOOTSTRAP_USDC: u64 = 200_000_000;
const SWAP_USDC: u64 = 10_000_000;
const GREEDY_FEE_BPS: u64 = FEE_BPS + 50;

fn swap_error(result: Result<impl Sized>) -> Result<SwapError> {
    let error = result
        .err()
        .ok_or_else(|| anyhow!("expected a swap error"))?;
    error
        .downcast_ref::<SwapError>()
        .cloned()
        .ok_or_else(|| anyhow!("expected a swap error, got {error:?}"))
}

#[test]
fn rejected_quotes_and_fills_leave_the_user_untouched() -> Result<()> {
    let TestEnv {
        localnet,
        user,
        mut market_maker,
        vault,
        ..
    } = setup(14)?;
    let rpc = localnet.client.rpc();

    let quote = market_maker.quote(&localnet, &vault, Direction::Deposit, SWAP_USDC)?;
    let order = user.order(&vault, quote)?;
    assert_eq!(
        swap_error(market_maker.fill(&localnet, &vault, &order, &user.keypair.nullifier_key))?,
        SwapError::InsufficientInventory {
            asset: vault.shares_mint,
            required: quote.amount_out,
            available: 0,
        }
    );

    market_maker.bootstrap(&localnet, &vault, BOOTSTRAP_USDC)?;
    market_maker.fee_bps = GREEDY_FEE_BPS;
    let greedy = market_maker.quote(&localnet, &vault, Direction::Deposit, SWAP_USDC)?;
    let order = user.order(&vault, greedy)?;
    let fill = market_maker.fill(&localnet, &vault, &order, &user.keypair.nullifier_key)?;
    let fair = Quote::price(
        &VaultState::read(rpc, &vault.vault)?,
        Direction::Deposit,
        SWAP_USDC,
        FEE_BPS,
    )?;
    assert_eq!(
        swap_error(user.verify_quote(&localnet, &vault, &order, &fill, FEE_BPS))?,
        SwapError::BelowRate {
            expected: fair.amount_out,
            offered: greedy.amount_out,
        }
    );

    assert_eq!(
        user.holdings(&vault)?,
        Holdings {
            usdc: USER_SHIELD_USDC,
            shares: 0,
        }
    );
    Ok(())
}
