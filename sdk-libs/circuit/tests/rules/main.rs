//! Native execution of the protocol rules: each refused input fails at its
//! own requirement, which the circuit build lowers to the matching constraint.

mod address;
mod balance;
mod codec;
mod data;
mod owner;
mod support;
mod token;
mod transaction;
