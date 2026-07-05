//! Async proposal family: the proposal PDA, its loader, and the
//! create/cancel/execute instructions.

pub mod cancel;
pub mod create;
pub mod execute;
pub mod execute_account;
pub mod loader;

pub use cancel::process_cancel_proposal_ix;
pub use create::process_create_proposal_ix;
pub use execute::process_execute_proposal_ix;
pub use loader::load_proposal;
