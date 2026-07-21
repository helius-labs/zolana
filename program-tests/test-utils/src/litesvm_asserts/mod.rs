//! Per-instruction assert helpers.

pub mod create_spl_interface;
pub mod deposit;
pub mod error;
pub mod protocol_config;
pub mod spl_deposit;
pub mod zone_deposit;

pub use create_spl_interface::litesvm_assert_create_spl_interface;
pub use deposit::{litesvm_assert_deposit, DepositAssertArgs};
pub use error::{
    assert_custom, assert_instruction_error, assert_instruction_error_at, assert_pool_error,
    assert_pool_error_at,
};
pub use protocol_config::litesvm_assert_protocol_config;
pub use spl_deposit::{litesvm_assert_spl_deposit, SplDepositAssertArgs};
pub use zone_deposit::{litesvm_assert_zone_deposit, ZoneDepositAssertArgs};
