//! A gadget written outside the SDK, through its public API only, checked on
//! its own and proved inside a program circuit.

#![deny(unused_must_use, unused_variables, unused_assignments)]
#![forbid(unsafe_code)]
#![deny(clippy::let_underscore_must_use)]

mod gadgets;
mod program;
#[path = "../shared/mod.rs"]
mod shared;
mod standalone;
