use pinocchio::ProgramResult;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{
        InterfaceTransfer, ResolvedInterfaceTransfer, TransactIxDataRef,
    },
};

use crate::instructions::settlement::Settlement;

/// Applies public settlement only after the proof that authorizes it has
/// verified, so invalid proofs cannot trigger CPIs or mask verification errors.
pub(crate) fn settle_interface_transfers(
    interface_transfers: &[InterfaceTransfer],
    settlements: &[Settlement<'_>],
) -> ProgramResult {
    for (transfer, settlement) in interface_transfers.iter().zip(settlements.iter()) {
        if transfer.is_deposit() != settlement.is_deposit() {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        settlement.settle(transfer.amount())?;
    }

    Ok(())
}

pub(crate) fn resolve_interface_transfers(
    ix: &TransactIxDataRef<'_>,
    settlements: &[Settlement<'_>],
) -> Vec<ResolvedInterfaceTransfer> {
    let mut resolved = Vec::with_capacity(ix.interface_transfers.len());
    for (transfer, settlement) in ix.interface_transfers.iter().zip(settlements.iter()) {
        let amount = transfer.amount();
        let resolved_transfer = match settlement {
            Settlement::SolDeposit(sol) => ResolvedInterfaceTransfer::SolDeposit {
                amount,
                recipient: sol.recipient_account.address().to_bytes(),
            },
            Settlement::SolWithdrawal(sol) => ResolvedInterfaceTransfer::SolWithdrawal {
                amount,
                recipient: sol.recipient_account.address().to_bytes(),
            },
            Settlement::SplDeposit(spl) => ResolvedInterfaceTransfer::SplDeposit {
                amount,
                user_token_account: spl.user_token_account.address().to_bytes(),
                spl_interface: spl.spl_interface_account.address().to_bytes(),
            },
            Settlement::SplWithdrawal(spl) => ResolvedInterfaceTransfer::SplWithdrawal {
                amount,
                user_token_account: spl.user_token_account.address().to_bytes(),
                spl_interface: spl.spl_interface_account.address().to_bytes(),
            },
        };
        resolved.push(resolved_transfer);
    }
    resolved
}

#[cfg(test)]
mod tests {
    use zolana_account_checks::account_info::test_account_info::get_account_view;

    use super::*;
    use crate::instructions::settlement::SettlementAccountsSol;
    use crate::instructions::transact::verify::TransactProofInputs;
    use zolana_interface::SOL_ASSET_FIELD;

    fn sol_settlement(account: &pinocchio::AccountView, is_deposit: bool) -> Settlement<'_> {
        let accounts = SettlementAccountsSol {
            sol_interface_account: account,
            sol_interface_bump: 0,
            recipient_account: account,
        };
        if is_deposit {
            Settlement::SolDeposit(accounts)
        } else {
            Settlement::SolWithdrawal(accounts)
        }
    }

    #[test]
    fn intermediate_zero_net_is_order_independent() {
        let account = get_account_view([1; 32], [0; 32], false, true, false, vec![]);
        let transfers = [
            InterfaceTransfer::SolDeposit { amount: 5 },
            InterfaceTransfer::SolWithdrawal { amount: 5 },
            InterfaceTransfer::SolDeposit { amount: 3 },
        ];
        let settlements = [
            sol_settlement(&account, true),
            sol_settlement(&account, false),
            sol_settlement(&account, true),
        ];
        let mut proof_inputs = TransactProofInputs::new_for_tests();

        proof_inputs
            .assign_public_amounts_and_assets(&transfers, &settlements, 1)
            .unwrap();

        assert_eq!(proof_inputs.public_slot_assets[0], SOL_ASSET_FIELD);
        assert_eq!(proof_inputs.public_slot_amounts[0], 3);
    }

    #[test]
    fn final_zero_net_is_rejected() {
        let account = get_account_view([1; 32], [0; 32], false, true, false, vec![]);
        let transfers = [
            InterfaceTransfer::SolDeposit { amount: 5 },
            InterfaceTransfer::SolWithdrawal { amount: 5 },
        ];
        let settlements = [
            sol_settlement(&account, true),
            sol_settlement(&account, false),
        ];
        let mut proof_inputs = TransactProofInputs::new_for_tests();

        assert_eq!(
            proof_inputs.assign_public_amounts_and_assets(&transfers, &settlements, 1),
            Err(ShieldedPoolError::ZeroNetInterfaceTransferAmount.into())
        );
    }
}
