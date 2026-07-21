pub mod common;

#[path = "common/program.rs"]
pub mod support;

#[path = "dispatch/failing.rs"]
mod failing;
#[path = "dispatch/functional.rs"]
mod functional;
