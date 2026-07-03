use clap::{Parser, Subcommand};
use solana_pubkey::Pubkey;

/// Default SPP pool tree the forester maintains (devnet/localnet fixture).
pub const DEFAULT_TREE: Pubkey =
    Pubkey::from_str_const("treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8");

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the forester worker.
    Start,
    /// Print read-only SPP tree, nullifier-queue, and forester status.
    Info {
        /// Pool tree to inspect (defaults to the SPP devnet tree).
        #[arg(long, default_value_t = DEFAULT_TREE)]
        tree: Pubkey,
        /// Emit a machine-readable JSON object instead of the human-readable
        /// report (for monitoring / gating a forester run, e.g. via `jq`).
        #[arg(long)]
        json: bool,
    },
}
