pub mod common;

#[path = "common/mollusk.rs"]
pub mod mollusk;
#[path = "common/program.rs"]
pub mod support;

#[path = "deposit/edge_cases.rs"]
mod edge_cases;
#[path = "deposit/failing.rs"]
mod failing;
#[path = "deposit/functional.rs"]
mod functional;
#[path = "deposit/random.rs"]
mod random;
