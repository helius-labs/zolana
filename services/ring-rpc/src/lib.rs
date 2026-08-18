//! Ring RPC for custom rings with an auditor: opens ring transactions with the
//! auditor viewing key ([`audit`]) and serves them over JSON-RPC ([`api`]) and as
//! a server-rendered page ([`page`]). See the crate README for the key modes and
//! the operating boundaries.

pub mod api;
pub mod audit;
pub mod config;
pub mod page;
pub mod server;
