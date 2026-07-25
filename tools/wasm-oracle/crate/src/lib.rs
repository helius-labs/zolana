//! Disposable WebAssembly wrapper that exposes canonical Rust as a differential
//! test oracle for the TypeScript port.
//!
//! Every export takes one JSON request string and returns one JSON outcome
//! string. The wrapper decodes the transport encoding and calls the canonical
//! function; it performs no endianness change, no length coercion, and no
//! default filling, because a repair inside the wrapper is a divergence the
//! oracle can no longer see.
//!
//! Where a Rust signature cannot express a fuzzable input, the wrapper widens
//! the parameter and returns the rejection the signature implies. Each such
//! widening carries an `Oracle`-prefixed rejection code so the TypeScript side
//! can tell a Rust rejection from a boundary rejection.
//!
//! Nothing here is evidence of parity. Counterexamples it finds are promoted
//! into committed fixtures, and the fixtures are the durable record.

pub mod codec;
pub mod hashing;
pub mod merkle;
pub mod outcome;
