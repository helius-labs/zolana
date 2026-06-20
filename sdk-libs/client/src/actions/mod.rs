//! Build-and-send actions for shielded-pool operations over [`Rpc`].
//!
//! [`Rpc`]: crate::rpc::Rpc

pub mod deposit;
pub mod transaction;

pub use deposit::{create_deposit, deposit, Deposit};
pub use transaction::{
    create_transfer, create_withdrawal, AddressResolver, CreateTransfer, CreatedTransfer,
    CreatedWithdrawal, ResolvedAddress,
};
