//! Public-slot aggregation unit tests, moved out of the program crate
//! (`transact/interface_transfer.rs`): order-independent intermediate zero
//! nets and the final zero-net rejection (error 7045).

use pinocchio::error::ProgramError;
use shielded_pool_program::testing::{Settlement, SettlementAccountsSol, TransactProofInputs};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{CircuitId, InterfaceTransfer},
    SOL_ASSET_FIELD,
};

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
    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));

    proof_inputs
        .assign_public_amounts_and_assets(
            transfers
                .into_iter()
                .zip(settlements)
                .map(Ok::<_, ProgramError>),
            1,
        )
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
    let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));

    assert_eq!(
        proof_inputs.assign_public_amounts_and_assets(
            transfers
                .into_iter()
                .zip(settlements)
                .map(Ok::<_, ProgramError>),
            1,
        ),
        Err(ShieldedPoolError::ZeroNetInterfaceTransferAmount.into())
    );
}
