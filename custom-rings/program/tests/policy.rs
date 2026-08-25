#![cfg(feature = "policy")]
//! Negatives of the policy build. They load the policy artifact, whose transact
//! wire and account prefix differ from the audit-only one.

mod common;

#[path = "policy/create_policy.rs"]
mod create_policy;
#[path = "policy/transact.rs"]
mod transact;
