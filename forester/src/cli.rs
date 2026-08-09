use clap::{Parser, Subcommand};
use solana_pubkey::Pubkey;

use crate::run::DEFAULT_PROOF_CONCURRENCY;

/// Default SPP pool tree the forester maintains (devnet/localnet fixture).
pub const DEFAULT_TREE: Pubkey = Pubkey::from_str_const(zolana_interface::DEFAULT_TREE_ADDRESS);

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
    /// Prove and submit ready nullifier-tree zkp-batches. Reads RPC_URL,
    /// PROVER_URL, PHOTON_URL, and PAYER (forester keypair) from the
    /// environment.
    Run {
        /// Pool tree whose nullifier queue to drain.
        #[arg(long, default_value_t = DEFAULT_TREE)]
        tree: Pubkey,
        /// Forester smart-account settings account. The vault at
        /// `--account-index` is the tree's `forester_authority`; the PAYER key
        /// signs as a member of this smart account. Required unless `--dry-run`.
        #[arg(long)]
        settings: Option<Pubkey>,
        /// Vault index within the forester smart-account settings.
        #[arg(long, default_value_t = 0)]
        account_index: u8,
        /// Stop after submitting at most N zkp-batches (default: all ready).
        #[arg(long)]
        max_batches: Option<u64>,
        /// After draining, keep polling for newly-ready batches instead of
        /// exiting.
        #[arg(long)]
        watch: bool,
        /// Seconds between polls in `--watch` mode.
        #[arg(long, default_value_t = 10)]
        poll_secs: u64,
        /// Preflight only: read the tree, fetch queued values from photon,
        /// reconstruct the reference tree, and verify the root matches on-chain
        /// — without proving or submitting.
        #[arg(long)]
        dry_run: bool,
        /// Serve Prometheus metrics on `host:port`, e.g. 0.0.0.0:9999. Omitted
        /// serves nothing. Names come from forester/metrics-contract.json.
        #[arg(long)]
        metrics_address: Option<String>,
        /// Zkp-batch proofs to run at once.
        ///
        /// Each proof clears one zkp-batch of nullifiers and takes about a
        /// minute, so this sets how fast spends can be absorbed. Bounded in
        /// practice by the prover fleet's memory (~15GB per batch proof), not by
        /// the forester.
        #[arg(long, default_value_t = DEFAULT_PROOF_CONCURRENCY)]
        proof_concurrency: usize,
    },
}
