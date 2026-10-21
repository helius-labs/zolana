#![cfg_attr(not(feature = "external-tools"), allow(dead_code))]
#![allow(clippy::single_range_in_vec_init)]

#[path = "../harness/mod.rs"]
mod harness;
mod protocol;
mod verifier;
