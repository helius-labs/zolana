//! Localnet mints what a step needs. Devnet cannot, so an underfunded
//! authority pauses at the faucet instead of dying mid-pipeline.

use std::io::{self, BufRead, IsTerminal, Write};

use solana_address::Address;
use thiserror::Error;
use zolana_client::{ClientError, Rpc};

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
    #[error("cannot read the answer")]
    Prompt(#[source] io::Error),
    #[error(transparent)]
    Client(Box<ClientError>),
}

/// Rechecks as long as the operator answers, without a terminal it fails
/// instead of hanging.
pub fn wait_for_balance<R: Rpc>(
    rpc: &R,
    authority: Address,
    required: u64,
) -> Result<(), FundError> {
    let mut asked = false;
    loop {
        let holds = rpc.get_balance(authority)?;
        if holds >= required {
            if asked {
                println!("authority holds {} SOL, continuing", sol(holds));
            }
            return Ok(());
        }
        if !io::stdin().is_terminal() {
            return Err(FundError::Underfunded {
                authority,
                holds,
                required,
            });
        }
        if !asked {
            println!();
            println!(
                "the step needs {} SOL, the authority holds {} SOL",
                sol(required),
                sol(holds)
            );
            println!("airdrop {} SOL at {FAUCET}", sol(required - holds));
            println!("  address  {authority}");
        } else {
            println!("still short {} SOL", sol(required - holds));
        }
        print!("press enter to check the balance again, ctrl-c to stop: ");
        io::stdout().flush().map_err(FundError::Prompt)?;
        let mut answer = String::new();
        if io::stdin()
            .lock()
            .read_line(&mut answer)
            .map_err(FundError::Prompt)?
            == 0
        {
            return Err(FundError::Underfunded {
                authority,
                holds,
                required,
            });
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
    use super::*;

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
        struct Rich;
        impl Rpc for Rich {
            fn get_balance(&self, _address: Address) -> Result<u64, ClientError> {
                Ok(9)
            }
        }
        // Reaching a prompt would read the harness's stdin and hang.
        wait_for_balance(&Rich, Address::default(), 9).expect("covered");
    }
}
