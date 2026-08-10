//! Instruction processors for the Squads ring. Account-family folders
//! ([`ring_config`], [`viewing_key_account`], [`proposal`],
//! [`key_update_proposal`]) own their loader and the instructions that touch
//! that account. Standalone instructions ([`transact`], [`fold_transact`],
//! [`deposit`], [`merge_transact`], [`full_withdrawal`]) live in their own
//! modules.

pub mod deposit;
pub mod fold_transact;
pub mod full_withdrawal;
pub mod key_update_proposal;
pub mod merge_transact;
pub mod proposal;
pub mod ring_config;
pub mod transact;
pub mod viewing_key_account;

pub use deposit::process_deposit_ix;
pub use fold_transact::process_fold_transact_ix;
pub use full_withdrawal::process_full_withdrawal_ix;
pub use key_update_proposal::{
    process_cancel_key_update_ix, process_execute_key_update_ix, process_fill_key_update_ix,
    process_update_viewing_key_account_ix,
};
pub use merge_transact::process_merge_transact_ix;
pub use proposal::{
    process_cancel_proposal_ix, process_create_proposal_ix, process_execute_proposal_ix,
};
pub use ring_config::{
    process_create_ring_config_ix, process_init_spp_ring_config_ix, process_update_ring_config_ix,
};
pub use transact::process_transact_ix;
pub use viewing_key_account::{
    process_close_viewing_key_account_ix, process_create_viewing_key_account_ix,
    process_toggle_viewing_key_account_ix,
};
