//! Expansion logic shared by the zk derives and the zolana program derives.
//! Generated paths start at `::zolana_program`; a crate that depends only on
//! the zk DSL names it with `extern crate zolana_zk_dsl as zolana_program;`.

pub mod circuit_type;
pub mod error_name;
pub mod paths;
pub mod proof_input;
mod serialization;
pub mod shape;
