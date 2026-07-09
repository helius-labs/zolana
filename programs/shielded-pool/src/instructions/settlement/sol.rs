use light_program_profiler::profile;
use pinocchio::{
    cpi::{Seed, Signer},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use rings_interface::{DEFAULT_SOL_INTERFACE_INDEX_SEED, SOL_INTERFACE_PDA_SEED};

use super::account::SettlementAccountsSol;

#[inline(never)]
#[profile]
pub fn settle_sol(
    settlement: &SettlementAccountsSol<'_>,
    amount: u64,
    is_deposit: bool,
) -> ProgramResult {
    if is_deposit {
        Transfer {
            from: settlement.recipient,
            to: settlement.sol_interface,
            lamports: amount,
        }
        .invoke()
    } else {
        let bump = [settlement.sol_interface_bump];
        let seeds = [
            Seed::from(SOL_INTERFACE_PDA_SEED),
            Seed::from(DEFAULT_SOL_INTERFACE_INDEX_SEED),
            Seed::from(&bump),
        ];
        let signer = Signer::from(&seeds);
        Transfer {
            from: settlement.sol_interface,
            to: settlement.recipient,
            lamports: amount,
        }
        .invoke_signed(core::slice::from_ref(&signer))
    }
}
