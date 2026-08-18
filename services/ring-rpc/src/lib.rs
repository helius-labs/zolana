//! Ring RPC for a custom ring with an auditor.
//!
//! One instance serves one ring. It holds the ring's auditor viewing key, reads
//! ring transactions from a Photon indexer by the auditor view tag, recovers each
//! transaction's viewing key from the auditor message, and returns the opened
//! output slots over JSON-RPC ([`api`]). Decryption happens on read; the key
//! never leaves the process.
//!
//! The scaffold has no request authentication and no per-user scoping. The
//! signed `get_decrypted_*_by_owner` methods of the spec's Ring RPC section
//! build on this service.

pub mod api;
pub mod audit;
pub mod config;
pub mod server;
