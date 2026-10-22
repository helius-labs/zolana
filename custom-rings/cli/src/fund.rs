//! Localnet mints what a step needs. Devnet cannot, so an underfunded
//! authority pauses at the faucet instead of dying mid-pipeline.

use anyhow::{bail, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::Rpc;

use crate::{
    ui::{self, line, Ask},
    Context,
};

/// Fees and the rent of every account `init` creates and of one reader.
pub const MIN_AUTHORITY_BALANCE: u64 = 50_000_000;

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
/// `solana airdrop` shares this quota and is rate limited to refusing.
const FAUCET: &str = "https://faucet.solana.com";

#[must_use]
pub(crate) struct TopUp<'a> {
    pub funder: &'a Keypair,
    pub who: Address,
    pub lamports: u64,
}

impl TopUp<'_> {
    /// Sends only what `who` lacks of `lamports`.
    pub(crate) fn send(self, ctx: &Context) -> Result<()> {
        let short = self
            .lamports
            .saturating_sub(ctx.rpc().get_balance(self.who)?);
        if short == 0 {
            return Ok(());
        }
        let transfer =
            solana_system_interface::instruction::transfer(&self.funder.pubkey(), &self.who, short);
        ctx.send(&[self.funder], &[transfer]).map(drop)
    }
}

/// Rechecks as long as the operator answers, without a terminal it fails instead of hanging.
pub fn wait_for_balance<R: Rpc>(
    rpc: &R,
    ask: &mut dyn Ask,
    authority: Address,
    required: u64,
) -> Result<()> {
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
        if asked {
            ui::warn(format!("still short {} SOL", sol(required - holds)));
        } else if ask.interactive() {
            println!();
            ui::warn(format!(
                "the step needs {} SOL, the authority holds {} SOL",
                sol(required),
                sol(holds)
            ));
            ui::warn(format!("airdrop {} SOL at {FAUCET}", sol(required - holds)));
            line("address", authority);
        }
        if !ask.interactive() || !ask.confirm("check the balance again?", true)? {
            bail!(
                "authority {authority} holds {} SOL, the step needs {}, airdrop it at {FAUCET}",
                sol(holds),
                sol(required)
            );
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
    let digits = format!("{fraction:09}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use zolana_client::ClientError;

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

    fn underfunded(result: Result<()>) -> bool {
        result.is_err_and(|error| error.to_string().contains("holds 0.000000003 SOL"))
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
        assert!(underfunded(wait_for_balance(
            &Balance(Cell::new(3)),
            &mut Defaults,
            Address::default(),
            9
        )));
    }

    #[test]
    fn a_shortfall_is_rechecked_while_the_operator_says_yes() {
        let mut ask = Scripted::new([Answer::Yes(true), Answer::Yes(true)]);
        wait_for_balance(&Balance(Cell::new(3)), &mut ask, Address::default(), 9)
            .expect("covered after two rechecks");
        assert!(ask.is_drained());
        let mut ask = Scripted::new([Answer::Yes(false)]);
        assert!(underfunded(wait_for_balance(
            &Balance(Cell::new(3)),
            &mut ask,
            Address::default(),
            9
        )));
    }
}
