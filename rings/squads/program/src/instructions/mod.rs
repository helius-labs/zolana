//! Instruction processors for the Squads ring, organized by account family and
//! per-instruction module (mirrors the shielded-pool layout):
//!
//! Account-family folders own their loader and the instructions that read or
//! write that account:
//! - [`ring_config`]: the singleton ring config PDA (`create_ring_config`,
//!   `update_ring_config`).
//! - [`viewing_key_account`]: the per-owner viewing key account
//!   (`create_viewing_key_account`, `close_viewing_key_account`,
//!   `toggle_viewing_key_account`).
//! - [`proposal`]: the async proposal PDA (`create_proposal`, `cancel_proposal`,
//!   `execute_proposal`).
//! - [`key_update_proposal`]: the key-rotation proposal PDA
//!   (`update_viewing_key_account` proposes, `fill_key_update`,
//!   `execute_key_update`, `cancel_key_update`).
//!
//! Standalone instructions live in single files or a per-instruction folder:
//! - [`transact`]: ring-proof-gated synchronous transfer/withdrawal.
//! - [`deposit`]: fully public deposit, no proof.
//! - [`merge_transact`]: merge-authority UTXO consolidation.
//! - [`full_withdrawal`]: escape-hatch public exit.

pub mod deposit;
pub mod full_withdrawal;
pub mod key_update_proposal;
pub mod merge_transact;
pub mod proposal;
pub mod ring_config;
pub mod transact;
pub mod viewing_key_account;

pub use deposit::process_deposit_ix;
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
