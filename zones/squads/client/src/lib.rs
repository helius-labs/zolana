//! Squads zone backend client: an in-process, CT-style backend that holds the
//! auditor P-256 key, decrypts every account's UTXOs and proposals via each
//! account's shared viewing key, runs the prover, and builds or sends the zone
//! transactions. It wraps the `zolana-client` indexer (`Rpc`) and exposes the
//! four Backend API endpoints from `docs/squads_policy_program.md`:
//! `getBalances`, `getProposals`, `requestCreateViewingKeyAccount`,
//! `requestTransact`.

pub mod backend;
pub mod balances;
pub mod crank;
pub mod error;
pub mod proposals;
pub mod seed;
pub mod tags;
pub mod transact;
pub mod types;
pub mod viewing_key;

pub use backend::{ResolvedAccount, SquadsBackend, SOL_ASSET_ID};
pub use error::SquadsBackendError;
pub use proposals::{OP_TRANSFER, OP_WITHDRAW};
pub use seed::{seed_viewing_key_account, ViewingKeyAccountSeed};
pub use types::*;
