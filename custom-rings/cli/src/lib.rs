//! Operator CLI of a custom ring generated from the template: deploy the
//! program under the authority, create the config with the auditor key, register
//! the ring with SPP, and run an audited transfer end to end. Every command reads
//! `ring.toml`, the answers the wizard recorded.

pub mod authority;
pub mod config;
pub mod deploy;
pub mod init;
pub mod policy;
pub mod ring_rpc;
pub mod status;
pub mod transfer;

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand};
use custom_ring_sdk::PROGRAM_ID;
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{ProverClient, SolanaRpc, ZolanaIndexer};
use zolana_interface::DEFAULT_TREE_ADDRESS;
use zolana_keypair::P256Pubkey;
use zolana_ring_rpc::config::{read_auditor_pubkey, write_auditor_pubkey};

use crate::{
    config::{expand_tilde, RingConfig, Target, RING_TOML},
    ring_rpc::RingRpc,
    transfer::{wait_for_indexed_transaction, DemoTransfer},
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
    /// Deploy the program with the authority as upgrade authority, or upgrade
    /// it in place when it is already deployed.
    Deploy(DeployArgs),
    /// Create the config with the auditor key, write the policy from ring.toml
    /// and register the ring with SPP.
    Init(InitArgs),
    /// Show, re-apply from ring.toml, or change the on-chain policy.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Two ring deposits and one audited transfer, read back from the ring RPC.
    Transact(TransactArgs),
    /// Confirm the ring RPC in `ring.toml` is up and holds this ring's auditor key.
    RpcCheck,
    /// Transfer or renounce the program's upgrade authority.
    #[command(subcommand)]
    Authority(AuthorityCommand),
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// The policy the ring config carries.
    Show,
    /// Write ring.toml's `[policy]` on chain when it differs.
    Apply,
    /// Write the given policy on chain.
    Set(PolicySetArgs),
}

#[derive(Debug, Args)]
pub struct PolicySetArgs {
    /// Mint the ring accepts, repeatable; `SOL` for native SOL. Without any,
    /// every asset is accepted.
    #[arg(long = "allow-asset", value_name = "MINT")]
    pub allow_assets: Vec<String>,
    /// `open` or `blocked`.
    #[arg(long, default_value = "open")]
    pub withdrawals: String,
}

#[derive(Debug, Subcommand)]
pub enum AuthorityCommand {
    /// Hand the program to another key. Update `authority_keypair` in
    /// ring.toml afterwards, `deploy` and a not yet created config follow it.
    Transfer { new_authority: Address },
    /// Make the program immutable. Irreversible.
    Renounce {
        /// Confirms the irreversible step.
        #[arg(long)]
        yes: bool,
    },
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
    /// SEC1 compressed auditor public key as hex, as `ring-rpc keygen` writes
    /// it. When the file is absent the ring RPC in `ring.toml` is asked to
    /// create the key, only the public half comes back and is written here so
    /// the ring repository records the key its config carries.
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
            let outcome = deploy::Deploy {
                rpc_url: &config.urls.rpc,
                authority_keypair: &expand_tilde(&config.authority_keypair)?,
                authority: authority.pubkey(),
                program_keypair: &args.program_keypair,
                program_so: &program_so,
            }
            .run(&rpc, config.program_id)?;
            println!(
                "{} {} under {}",
                match outcome {
                    deploy::DeployOutcome::Deployed => "deployed",
                    deploy::DeployOutcome::Upgraded => "upgraded",
                },
                config.program_id,
                authority.pubkey()
            );
            Ok(())
        }
        Command::Init(args) => {
            let authority = config.authority()?;
            fund_on_localnet(&config, &mut rpc, authority.pubkey())?;
            let auditor_pk = if args.auditor_pubkey_file.exists() {
                read_auditor_pubkey(&args.auditor_pubkey_file)?
            } else {
                let auditor_pk = RingRpc::new(&config.urls.ring_rpc).auditor_pubkey(PROGRAM_ID)?;
                write_auditor_pubkey(&args.auditor_pubkey_file, &auditor_pk)?;
                println!(
                    "auditor pk  {} (from {}, written to {})",
                    hex::encode(auditor_pk.as_bytes()),
                    config.urls.ring_rpc,
                    args.auditor_pubkey_file.display()
                );
                auditor_pk
            };
            let outcome = init::init(&rpc, &authority, auditor_pk)?;
            println!(
                "config      {}",
                if outcome.config_created {
                    "created"
                } else {
                    "already present"
                }
            );
            let wanted = policy::from_config(&config.policy)?;
            println!(
                "policy      {}",
                if policy::apply(&rpc, &authority, &wanted)? {
                    "written"
                } else {
                    "already applied"
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
        Command::RpcCheck => {
            let auditor_pk = configured_auditor_pk(&rpc)?;
            RingRpc::new(&config.urls.ring_rpc).check_serves(PROGRAM_ID, &auditor_pk)?;
            println!("ring rpc    {} serves this ring", config.urls.ring_rpc);
            Ok(())
        }
        Command::Policy(command) => {
            let wanted = match command {
                PolicyCommand::Show => {
                    policy::print(&policy::read_policy(&rpc)?);
                    return Ok(());
                }
                PolicyCommand::Apply => policy::from_config(&config.policy)?,
                PolicyCommand::Set(args) => policy::from_config(&config::PolicyConfig {
                    allowed_assets: (!args.allow_assets.is_empty()).then_some(args.allow_assets),
                    withdrawals: Some(args.withdrawals),
                })?,
            };
            let authority = config.authority()?;
            fund_on_localnet(&config, &mut rpc, authority.pubkey())?;
            println!(
                "policy      {}",
                if policy::apply(&rpc, &authority, &wanted)? {
                    "written"
                } else {
                    "already applied"
                }
            );
            policy::print(&wanted);
            Ok(())
        }
        Command::Authority(command) => {
            let authority = config.authority()?;
            let current = authority::deployed_program_data(&rpc, config.program_id)?;
            let set = authority::SetUpgradeAuthority {
                rpc_url: &config.urls.rpc,
                authority_keypair: &expand_tilde(&config.authority_keypair)?,
                authority: authority.pubkey(),
                program_id: config.program_id,
            };
            match command {
                AuthorityCommand::Transfer { new_authority } => {
                    set.transfer(&current, new_authority)?;
                    println!(
                        "upgrade authority of {} is now {new_authority}, point authority_keypair in {} at its keypair",
                        config.program_id,
                        cli.config.display()
                    );
                }
                AuthorityCommand::Renounce { yes } => {
                    if !yes {
                        return Err(anyhow!(
                            "renouncing is irreversible, pass --yes to make {} immutable",
                            config.program_id
                        ));
                    }
                    set.renounce(&current)?;
                    println!("{} is immutable", config.program_id);
                }
            }
            Ok(())
        }
        Command::Transact(args) => {
            let authority = config.authority()?;
            fund_on_localnet(&config, &mut rpc, authority.pubkey())?;
            let auditor_pk = configured_auditor_pk(&rpc)?;
            // Before proving: an RPC holding another ring's key would leave the
            // readback below waiting for a transaction it can never open.
            let ring_rpc = RingRpc::new(&config.urls.ring_rpc);
            ring_rpc.check_serves(PROGRAM_ID, &auditor_pk)?;
            let indexer = ZolanaIndexer::new(&config.urls.indexer);
            let prover = ProverClient::new(config.urls.prover.clone());
            let receipt = DemoTransfer {
                rpc: &rpc,
                indexer: &indexer,
                prover: &prover,
                payer: &authority,
                tree: Address::from_str_const(DEFAULT_TREE_ADDRESS),
                auditor_pk,
                amount: args.amount,
            }
            .run()?;
            println!(
                "sender      {}  viewing pk {}",
                receipt.sender.pubkey(),
                hex::encode(receipt.sender.viewing_pubkey().as_bytes())
            );
            println!(
                "recipient   {}  viewing pk {}",
                receipt.recipient.pubkey(),
                hex::encode(receipt.recipient.viewing_pubkey().as_bytes())
            );
            for signature in &receipt.deposits {
                println!("deposit     {signature}");
            }
            println!("transact    {}", receipt.transact);
            for line in program_logs(&rpc, &receipt.transact)? {
                println!("  log       {line}");
            }
            println!("waiting for the indexer and the ring rpc to open the transaction");
            wait_for_indexed_transaction(&indexer, receipt.transact)?;
            let opened = ring_rpc.wait_for_decrypted(PROGRAM_ID, receipt.transact)?;
            println!("auditor sees slot {} at {}", opened.slot, receipt.transact);
            println!(
                "  from      {}",
                opened
                    .signers
                    .iter()
                    .map(|signer| signer.0.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            for output in &opened.outputs {
                println!(
                    "  slot {}  to {}  asset {}  amount {}",
                    output.slot_index,
                    hex::encode(&output.recipient_viewing_pk.0),
                    output.asset.0,
                    output.amount
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

/// The auditor key `create_config` recorded on chain.
fn configured_auditor_pk(rpc: &SolanaRpc) -> Result<P256Pubkey> {
    Ok(P256Pubkey::from_bytes(
        init::read_config(rpc)?
            .ok_or_else(|| anyhow!("ring config not created, run `init` first"))?
            .auditor_pubkey,
    )?)
}

fn default_program_so(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "target/deploy/{}_program.so",
        name.replace('-', "_")
    ))
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
