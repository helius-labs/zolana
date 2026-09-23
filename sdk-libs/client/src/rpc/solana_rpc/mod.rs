mod accounts;
mod blocking;
mod nonblocking;
mod transaction;

use std::time::Duration;

/// How often confirmation and transaction lookups are polled unless a client
/// sets its own interval. solana-rpc-client's send-and-confirm polls every
/// 500ms regardless of how fast the cluster confirms.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub use accounts::ProgramAccountsFilter;
pub use blocking::SolanaRpc;
pub use nonblocking::AsyncSolanaRpc;
pub use transaction::{
    transact_output_view_tags_from_instruction_groups, ConfirmedInstructionGroups,
};
