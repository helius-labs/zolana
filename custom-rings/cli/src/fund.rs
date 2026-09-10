//! Localnet mints what a step needs. Devnet cannot, so an underfunded
//! authority pauses at the faucet instead of dying mid-pipeline.

use solana_address::Address;
use thiserror::Error;
use zolana_client::{ClientError, Rpc};

use crate::{
    line,
    ui::{self, Ask, AskError},
};

/// Fees and the rent of the config, the ring registration and one reader.
pub const MIN_AUTHORITY_BALANCE: u64 = 50_000_000;

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
/// `solana airdrop` shares this quota and is rate limited to refusing.
const FAUCET: &str = "https://faucet.solana.com";

#[derive(Debug, Error)]
pub enum FundError {
    #[error(
        "authority {authority} holds {} SOL, the step needs {}, airdrop it at {FAUCET}",
        sol(*holds),
        sol(*required)
    )]
    Underfunded {
        authority: Address,
        holds: u64,
        required: u64,
    },
    #[error(transparent)]
    Ask(#[from] AskError),
    #[error(transparent)]
    Client(Box<ClientError>),
}

/// Rechecks as long as the operator answers, without a terminal it fails
/// instead of hanging.
pub fn wait_for_balance<R: Rpc>(
    rpc: &R,
    ask: &mut dyn Ask,
    authority: Address,
    required: u64,
) -> Result<(), FundError> {
    let mut asked = false;
    loop {
        let holds = rpc.get_balance(authority)?;
        if holds >= required {
            if asked {
                line(
                    "authority",
                    format_args!("holds {} SOL, continuing", sol(holds)),
                );
            }
            return Ok(());
        }
        let underfunded = || FundError::Underfunded {
            authority,
            holds,
            required,
        };
        if !ask.interactive() {
            return Err(underfunded());
        }
        if asked {
            ui::warn(format!("still short {} SOL", sol(required - holds)));
        } else {
            println!();
            ui::warn(format!(
                "the step needs {} SOL, the authority holds {} SOL",
                sol(required),
                sol(holds)
            ));
            ui::warn(format!("airdrop {} SOL at {FAUCET}", sol(required - holds)));
            line("address", authority);
        }
        if !ask.confirm("check the balance again?", true)? {
            return Err(underfunded());
        }
        asked = true;
    }
}

/// Lamports read as the faucet writes them, `1_500_000_000` as `1.5`.
fn sol(lamports: u64) -> String {
    let fraction = lamports % LAMPORTS_PER_SOL;
    let whole = lamports / LAMPORTS_PER_SOL;
    if fraction == 0 {
        return whole.to_string();
    }
    let mut digits = format!("{fraction:09}");
    while digits.ends_with('0') {
        digits.pop();
    }
    format!("{whole}.{digits}")
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::ui::{Answer, Defaults, Scripted};

    /// Grows by three lamports per read.
    struct Balance(Cell<u64>);

    impl Rpc for Balance {
        fn get_balance(&self, _address: Address) -> Result<u64, ClientError> {
            let holds = self.0.get();
            self.0.set(holds + 3);
            Ok(holds)
        }
    }

    #[test]
    fn lamports_print_as_sol() {
        assert_eq!(sol(0), "0");
        assert_eq!(sol(LAMPORTS_PER_SOL), "1");
        assert_eq!(sol(1_500_000_000), "1.5");
        assert_eq!(sol(6_314_880_000), "6.31488");
        assert_eq!(sol(1), "0.000000001");
    }

    #[test]
    fn a_covered_balance_never_asks() {
        let mut ask = Scripted::new([]);
        wait_for_balance(&Balance(Cell::new(9)), &mut ask, Address::default(), 9).expect("covered");
    }

    #[test]
    fn a_shortfall_without_a_terminal_is_an_error() {
        assert!(matches!(
            wait_for_balance(&Balance(Cell::new(3)), &mut Defaults, Address::default(), 9),
            Err(FundError::Underfunded {
                holds: 3,
                required: 9,
                ..
            })
        ));
    }

    #[test]
    fn a_shortfall_is_rechecked_while_the_operator_says_yes() {
        let mut ask = Scripted::new([Answer::Yes(true), Answer::Yes(true)]);
        wait_for_balance(&Balance(Cell::new(3)), &mut ask, Address::default(), 9)
            .expect("covered after two rechecks");
        assert!(ask.is_drained());
        let mut ask = Scripted::new([Answer::Yes(false)]);
        assert!(matches!(
            wait_for_balance(&Balance(Cell::new(3)), &mut ask, Address::default(), 9),
            Err(FundError::Underfunded { holds: 3, .. })
        ));
    }
}
