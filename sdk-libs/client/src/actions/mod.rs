//! Build-and-send actions for shielded-pool operations over [`Rpc`].
//!
//! [`Rpc`]: crate::rpc::Rpc

pub mod deposit;

pub use deposit::{deposit, Deposit};
