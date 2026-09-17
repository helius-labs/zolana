//! Nullifier receipts: a batch non-inclusion proof verified once and stored
//! with the root it was proven against. Receipt-backed merges spend contiguous
//! slices of a verified receipt without proving non-inclusion themselves; the
//! program requires the receipt's root to be the merge's nullifier root, so
//! the merge's pending and queue insertion happen under exactly the freshness
//! rule an in-proof non-inclusion gives. A receipt reserves nothing: it can be
//! created, filled and verified by anyone holding the public nullifier list,
//! and it lapses with root history.
//!
//! Lifecycle: `create_receipt` (sponsor pays rent, binds the tree) →
//! `upload_receipt` (sponsor appends slices) → `verify_receipt` (anyone;
//! checks and stores the root, freezes the account) → `close_receipt`
//! (sponsor, refunds rent).

mod close;
mod create;
mod loader;
mod upload;
mod verify;

pub use close::process_close_receipt;
pub use create::process_create_receipt;
pub(crate) use loader::ReceiptSlice;
pub use upload::process_upload_receipt;
pub use verify::process_verify_receipt;
