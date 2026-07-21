pub mod common;

#[path = "common/program.rs"]
pub mod support;

#[path = "spl/failing.rs"]
mod failing;
#[path = "spl/functional.rs"]
mod functional;
