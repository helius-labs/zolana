use pinocchio::{
    cpi::{Seed, Signer},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use zolana_interface::{SHIELDED_POOL_CPI_AUTHORITY_BUMP, SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED};

use super::account::SettlementAccountsSol;

#[inline(never)]
pub fn settle_sol(settlement: &SettlementAccountsSol<'_>, amount: u64) -> ProgramResult {
    match settlement.cpi_authority {
        Some(cpi_authority) => {
            let bump = [SHIELDED_POOL_CPI_AUTHORITY_BUMP];
            let seeds = [
                Seed::from(SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED),
                Seed::from(&bump),
            ];
            let signer = Signer::from(&seeds);
            Transfer {
                from: cpi_authority,
                to: settlement.recipient,
                lamports: amount,
            }
            .invoke_signed(core::slice::from_ref(&signer))
        }
        None => Transfer {
            from: settlement.recipient,
            to: settlement.interface,
            lamports: amount,
        }
        .invoke(),
    }
}
