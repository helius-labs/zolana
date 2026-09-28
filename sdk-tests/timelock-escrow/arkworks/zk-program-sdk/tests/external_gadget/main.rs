//! A gadget written outside the SDK, through its public API only, checked on
//! its own and proved inside a program circuit.

mod gadgets;
mod program;
#[path = "../shared/mod.rs"]
mod shared;
mod standalone;
