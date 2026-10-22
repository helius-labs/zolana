//! Key-update proposal family: the rotation proposal PDA, its loader, and the
//! propose/fill/execute/cancel instructions. `update_viewing_key_account`
//! (tag 6) creates the proposal; the remaining steps fill, execute, and cancel
//! it.

pub mod cancel;
pub mod execute;
pub mod fill;
pub mod loader;
pub mod propose;

pub use cancel::process_cancel_key_update_ix;
pub use execute::process_execute_key_update_ix;
pub use fill::process_fill_key_update_ix;
pub use loader::load_key_update_proposal;
pub use propose::process_update_viewing_key_account_ix;
