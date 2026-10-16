#![cfg_attr(not(feature = "external-tools"), allow(dead_code))]
#![allow(clippy::single_range_in_vec_init)]

extern crate zolana_zk_dsl as zolana_program;

mod bool;
mod bytes;
mod circuit_var;
mod fingerprints;
#[path = "../../../test-harness/mod.rs"]
mod harness;
mod ops;
mod uint;
