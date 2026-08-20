//! Ring RPC for custom rings with an auditor: opens ring transactions with the
//! auditor viewing key ([`audit`]) and serves them over JSON-RPC ([`api`]). See
//! the crate README for the key modes and the operating boundaries.

pub mod api;
pub mod audit;
pub mod config;
pub mod prove;
pub mod server;
pub mod webauthn;
