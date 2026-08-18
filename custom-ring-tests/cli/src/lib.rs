//! Operator CLI of a custom ring generated from the template: deploy the
//! program under the authority, create the config with the auditor key, register
//! the ring with SPP, and run an audited transfer end to end. Every command reads
//! `ring.toml`, the answers the wizard recorded.

pub mod config;
pub mod deploy;
pub mod init;
pub mod lookup_table;
pub mod ring_rpc;
pub mod status;
pub mod transfer;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use custom_ring_sdk::PROGRAM_ID;
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{ProverClient, SolanaRpc, ZolanaIndexer};
use zolana_interface::DEFAULT_TREE_ADDRESS;
use zolana_keypair::P256Pubkey;

use crate::{
    config::{expand_tilde, RingConfig, Target, RING_TOML},
    ring_rpc::RingRpc,
    transfer::{wait_for_indexed_transaction, AuditedTransfer},
};

/// Lamports the localnet authority is topped up to before it pays for anything.
const LOCALNET_AUTHORITY_BALANCE: u64 = 100_000_000_000;

#[derive(Debug, Parser)]
#[command(
    name = "custom-ring",
    about = "Operate a custom ring generated from the template"
)]
pub struct Cli {
    /// The wizard's answers.
    #[arg(long, default_value = RING_TOML, global = true)]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Recorded answers and on-chain state.
    Status,
    /// Deploy the program with the authority as upgrade authority.
    Deploy(DeployArgs),
    /// Create the config with the auditor key and register the ring with SPP.
    Init(InitArgs),
    /// Two ring deposits and one audited transfer, read back from the ring RPC.
    Transact(TransactArgs),
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    /// Defaults to `target/deploy/<name>_program.so`.
    #[arg(long)]
    pub program_so: Option<PathBuf>,
    #[arg(long, default_value = "keys/program-keypair.json")]
    pub program_keypair: PathBuf,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// SEC1 compressed auditor public key as hex, as `ring-rpc keygen` writes it.
    #[arg(long, default_value = "keys/auditor.key.pub")]
    pub auditor_pubkey_file: PathBuf,
}

#[derive(Debug, Args)]
pub struct TransactArgs {
    /// Lamports the recipient receives.
    #[arg(long, default_value_t = 1_000_000_000)]
    pub amount: u64,
}

pub fn main() -> Result<()> {
    run(Cli::parse())
}

pub fn run(cli: Cli) -> Result<()> {
    let config = RingConfig::load(&cli.config)?;
    // The builders carry the id this binary was compiled with; a mismatch means
    // every PDA and CPI would target the wrong program.
    if config.program_id != PROGRAM_ID {
        return Err(anyhow!(
            "ring.toml names program {} but this build was compiled for {} (CUSTOM_RING_PROGRAM_ID)",
            config.program_id,
            PROGRAM_ID
        ));
    }
    let mut rpc = SolanaRpc::new(config.urls.rpc.clone());
    match cli.command {
        Command::Status => status::print_status(&config, &rpc),
        Command::Deploy(args) => {
            let authority = config.authority()?;
            fund_on_localnet(&config, &mut rpc, authority.pubkey())?;
            let program_so = args
                .program_so
                .unwrap_or_else(|| default_program_so(&config.name));
            deploy::Deploy {
                rpc_url: &config.urls.rpc,
                authority_keypair: &expand_tilde(&config.authority_keypair)?,
                program_keypair: &args.program_keypair,
                program_so: &program_so,
            }
            .run(&rpc, config.program_id)?;
            println!(
                "deployed {} under {}",
                config.program_id,
                authority.pubkey()
            );
            Ok(())
        }
        Command::Init(args) => {
            let authority = config.authority()?;
            fund_on_localnet(&config, &mut rpc, authority.pubkey())?;
            let auditor_pk = read_auditor_pubkey(&args.auditor_pubkey_file)?;
            let outcome = init::init(&rpc, &authority, auditor_pk)?;
            println!(
                "config      {}",
                if outcome.config_created {
                    "created"
                } else {
                    "already present"
                }
            );
            println!(
                "spp ring    {}",
                if outcome.ring_registered {
                    "registered"
                } else {
                    "already registered"
                }
            );
            Ok(())
        }
        Command::Transact(args) => {
            let authority = config.authority()?;
            fund_on_localnet(&config, &mut rpc, authority.pubkey())?;
            let auditor_pk = P256Pubkey::from_bytes(
                init::read_config(&rpc)?
                    .ok_or_else(|| anyhow!("ring config not created, run `init` first"))?
                    .auditor_pubkey,
            )?;
            let indexer = ZolanaIndexer::new(&config.urls.indexer);
            let prover = ProverClient::new(config.urls.prover.clone());
            let receipt = AuditedTransfer {
                rpc: &rpc,
                indexer: &indexer,
                prover: &prover,
                payer: &authority,
                tree: DEFAULT_TREE_ADDRESS
                    .parse::<Address>()
                    .expect("default tree address is a valid base58 constant"),
                auditor_pk,
                amount: args.amount,
            }
            .run()?;
            for signature in &receipt.deposits {
                println!("deposit     {signature}");
            }
            println!("transact    {}", receipt.transact);
            for line in program_logs(&rpc, &receipt.transact)? {
                println!("  log       {line}");
            }
            wait_for_indexed_transaction(&indexer, receipt.transact)?;

            let ring_rpc = RingRpc::new(&config.urls.ring_rpc);
            let opened = ring_rpc.wait_for_decrypted(receipt.transact)?;
            println!("auditor sees slot {} at {}", opened.slot, receipt.transact);
            for output in &opened.outputs {
                println!(
                    "  slot {}  asset {}  amount {}",
                    output.slot_index, output.asset.0, output.amount
                );
            }
            if !opened.undecryptable_slots.is_empty() {
                println!("  undecryptable slots {:?}", opened.undecryptable_slots);
            }
            Ok(())
        }
    }
}

/// `Program log:` lines of a confirmed transaction, the ring's own output.
fn program_logs(rpc: &SolanaRpc, signature: &solana_signature::Signature) -> Result<Vec<String>> {
    let confirmed = rpc.fetch_confirmed_transaction(signature)?;
    let logs: Option<Vec<String>> = confirmed
        .transaction
        .meta
        .map(|meta| meta.log_messages.into())
        .unwrap_or_default();
    Ok(logs
        .unwrap_or_default()
        .into_iter()
        .filter_map(|line| line.strip_prefix("Program log: ").map(str::to_owned))
        .collect())
}

fn default_program_so(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "target/deploy/{}_program.so",
        name.replace('-', "_")
    ))
}

fn read_auditor_pubkey(path: &Path) -> Result<P256Pubkey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading auditor public key {}", path.display()))?;
    let bytes = hex::decode(text.trim())
        .with_context(|| format!("auditor public key {} is not hex", path.display()))?;
    let bytes: [u8; 33] = bytes
        .try_into()
        .map_err(|_| anyhow!("auditor public key must be 33 bytes"))?;
    Ok(P256Pubkey::from_bytes(bytes)?)
}

/// A local validator hands out SOL for free; devnet and beyond need a funded
/// authority.
fn fund_on_localnet(config: &RingConfig, rpc: &mut SolanaRpc, authority: Address) -> Result<()> {
    if config.target != Target::Localnet {
        return Ok(());
    }
    let balance = rpc.client().get_balance(&authority)?;
    if balance < LOCALNET_AUTHORITY_BALANCE / 2 {
        rpc.airdrop(&authority, LOCALNET_AUTHORITY_BALANCE)?;
    }
    Ok(())
}
