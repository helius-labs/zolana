pub mod squads_deposit;
pub mod squads_withdrawal;

pub use squads_deposit::{assert_squads_deposit, SquadsDepositAssertArgs, SquadsDepositSettlement};
pub use squads_withdrawal::{
    assert_squads_withdrawal, SquadsWithdrawalAssertArgs, SquadsWithdrawalSettlement,
};
