//! Viewing key account family: the per-owner viewing key account PDA, its
//! loader, and the create/close/toggle instructions. The key-update proposal
//! lifecycle (rotation) lives in the sibling `key_update_proposal` family.

pub mod close;
pub mod create;
pub mod loader;
pub mod toggle;

pub use close::process_close_viewing_key_account_ix;
pub use create::process_create_viewing_key_account_ix;
pub use loader::load_viewing_key_account;
pub use toggle::process_toggle_viewing_key_account_ix;
