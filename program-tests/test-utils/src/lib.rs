//! Internal, test-only assert helpers for the shielded-pool integration tests.
//!
//! Each helper runs *after* an instruction has executed and verifies the
//! resulting on-chain state and any emitted event against the expectations the
//! integration tests already encode. They factor the repeated post-instruction
//! checks out of the test files; they do not introduce new invariants.
//!
//! Helpers are `#[track_caller]` so an assertion failure points at the test
//! that called the helper, not the helper body.

pub mod litesvm_asserts;
pub mod spl;
pub mod test_validator_asserts;
