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
use zolana_client::{ProverClient, Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::DEFAULT_TREE_ADDRESS;
use zolana_keypair::P256Pubkey;
use zolana_ring_rpc::{
    api::GetDecryptedTransactionsRequest,
    config::{read_auditor_pubkey, write_auditor_pubkey},
};

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
    /// Approve one proven transact by its `private_tx_hash`, or revoke it.
    Approve(ApproveArgs),
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

/// Each flag changes one part of the on-chain policy. Parts not named stay.
#[derive(Debug, Args)]
pub struct PolicySetArgs {
    /// Replace the allowlist with these mints, repeatable, `SOL` for native SOL.
    /// Listed mints keep their withdrawal rule when they had one.
    #[arg(
        long = "allow-asset",
        value_name = "MINT",
        conflicts_with = "any_asset"
    )]
    pub allow_assets: Vec<String>,
    /// Drop the allowlist, every asset is accepted.
    #[arg(long)]
    pub any_asset: bool,
    /// Default withdrawal rule, `open`, `blocked` or `approval`.
    #[arg(long, value_parser = ["open", "blocked", "approval"])]
    pub withdrawals: Option<String>,
    /// Withdrawal rule of one asset, `<mint>=<rule>`, repeatable.
    #[arg(long = "asset-withdrawals", value_name = "MINT=RULE")]
    pub asset_withdrawals: Vec<String>,
    /// The key that approves withdrawals under an `approval` rule.
    #[arg(long, value_name = "PUBKEY")]
    pub approver: Option<Address>,
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
    /// Accept the ring RPC's auditor key without a pinned service key in
    /// ring.toml. For a local instance only, the key cannot be changed later.
    #[arg(long)]
    pub trust_ring_rpc: bool,
}

#[derive(Debug, Args)]
pub struct TransactArgs {
    /// Lamports the recipient receives.
    #[arg(long, default_value_t = 1_000_000_000)]
    pub amount: u64,
    /// Withdraw this many lamports of the recipient's share publicly.
    #[arg(long, value_name = "LAMPORTS")]
    pub withdraw: Option<u64>,
    /// Who receives the withdrawal, default the authority.
    #[arg(long, value_name = "PUBKEY", requires = "withdraw")]
    pub withdraw_to: Option<Address>,
    /// Signs the approval when the policy asks for one, default the authority.
    #[arg(long, value_name = "KEYPAIR")]
    pub approver_keypair: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// The `private_tx_hash` of the proven transact, hex.
    pub private_tx_hash: String,
    /// The approver, default the authority.
    #[arg(long, value_name = "KEYPAIR")]
    pub approver_keypair: Option<PathBuf>,
    /// Take an unspent approval back instead. Its rent returns to the approver.
    #[arg(long)]
    pub revoke: bool,
}

pub fn main() -> Result<()> {
    run(Cli::parse())
}

pub fn run(cli: Cli) -> Result<()> {
    let config = RingConfig::load(&cli.config)?;
    // The builders carry the id this binary was compiled with. A mismatch means
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
                let pinned = config
                    .urls
                    .ring_rpc_pubkey
                    .as_deref()
                    .map(|key| {
                        key.parse::<Address>().map_err(|error| {
                            anyhow!("ring_rpc_pubkey {key} is not a base58 pubkey: {error}")
                        })
                    })
                    .transpose()?;
                let auditor_pk = RingRpc::new(&config.urls.ring_rpc)
                    .auditor_pubkey(PROGRAM_ID)?
                    .require(pinned, args.trust_ring_rpc)?;
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
                PolicyCommand::Set(args) => {
                    let mut wanted = policy::read_policy(&rpc)?;
                    if args.any_asset {
                        wanted.asset_policy = custom_ring_sdk::AssetPolicy::Any;
                    } else if !args.allow_assets.is_empty() {
                        let mints = args
                            .allow_assets
                            .iter()
                            .map(|asset| policy::parse_asset(asset))
                            .collect::<Result<Vec<_>>>()?;
                        wanted.assets = mints
                            .into_iter()
                            .map(|mint| custom_ring_sdk::AssetRule {
                                withdrawals: wanted.withdrawal_rule(&mint),
                                mint,
                            })
                            .collect();
                        wanted.asset_policy = custom_ring_sdk::AssetPolicy::Allowlist;
                    }
                    if let Some(withdrawals) = args.withdrawals.as_deref() {
                        wanted.withdrawals = policy::parse_rule(withdrawals)?;
                    }
                    for entry in &args.asset_withdrawals {
                        let (mint, rule) = entry
                            .split_once('=')
                            .ok_or_else(|| anyhow!("expected <mint>=<rule>, got {entry}"))?;
                        let mint = policy::parse_asset(mint)?;
                        let rule = policy::parse_rule(rule)?;
                        match wanted.assets.iter_mut().find(|asset| asset.mint == mint) {
                            Some(asset) => asset.withdrawals = rule,
                            None => wanted.assets.push(custom_ring_sdk::AssetRule {
                                mint,
                                withdrawals: rule,
                            }),
                        }
                    }
                    if let Some(approver) = args.approver {
                        wanted.approver = Some(approver);
                    }
                    wanted
                }
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
        Command::Approve(args) => {
            let approver = match &args.approver_keypair {
                Some(path) => solana_keypair::read_keypair_file(expand_tilde(path)?)
                    .map_err(|e| anyhow!("reading approver keypair {}: {e}", path.display()))?,
                None => config.authority()?,
            };
            fund_on_localnet(&config, &mut rpc, approver.pubkey())?;
            let private_tx_hash: [u8; 32] = hex::decode(args.private_tx_hash.trim())?
                .try_into()
                .map_err(|_| anyhow!("private_tx_hash must be 32 bytes of hex"))?;
            let ix = if args.revoke {
                custom_ring_sdk::RevokeApproval {
                    approver: approver.pubkey(),
                    rent_recipient: approver.pubkey(),
                    private_tx_hash,
                }
                .instruction()
            } else {
                custom_ring_sdk::ApproveTransact {
                    approver: approver.pubkey(),
                    payer: approver.pubkey(),
                    private_tx_hash,
                }
                .instruction()
            };
            let signature =
                rpc.create_and_send_transaction(&[ix], approver.pubkey(), &[&approver])?;
            println!(
                "{}    {} at {signature}",
                if args.revoke { "revoked " } else { "approved" },
                custom_ring_sdk::approval_pda(&private_tx_hash)
            );
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
            // Checked before proving. An RPC holding another ring's key would
            // leave the readback below waiting for a transaction it can never open.
            let ring_rpc = RingRpc::new(&config.urls.ring_rpc);
            ring_rpc.check_serves(PROGRAM_ID, &auditor_pk)?;
            let indexer = ZolanaIndexer::new(&config.urls.indexer);
            let prover = ProverClient::new(config.urls.prover.clone());
            let ring_policy = policy::read_policy(&rpc)?;
            let approver = match &args.approver_keypair {
                Some(path) => solana_keypair::read_keypair_file(expand_tilde(path)?)
                    .map_err(|e| anyhow!("reading approver keypair {}: {e}", path.display()))?,
                None => config.authority()?,
            };
            let receipt = DemoTransfer {
                rpc: &rpc,
                indexer: &indexer,
                prover: &prover,
                payer: &authority,
                tree: Address::from_str_const(DEFAULT_TREE_ADDRESS),
                auditor_pk,
                amount: args.amount,
                withdrawal: args
                    .withdraw
                    .map(|lamports| (args.withdraw_to.unwrap_or(authority.pubkey()), lamports)),
                policy: &ring_policy,
                approver: Some(&approver),
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
            if let Some(signature) = &receipt.approval {
                println!("approval    {signature}");
            }
            println!("transact    {}", receipt.transact);
            for line in program_logs(&rpc, &receipt.transact)? {
                println!("  log       {line}");
            }
            println!("waiting for the indexer and the ring rpc to open the transaction");
            wait_for_indexed_transaction(&indexer, receipt.transact)?;
            let opened = ring_rpc.wait_for_decrypted(PROGRAM_ID, &authority, receipt.transact)?;
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
            // The participants' own view, what the ring RPC answers to the keys
            // in the transaction rather than to the authority.
            let sender_view = ring_rpc.first_page(
                GetDecryptedTransactionsRequest::unsigned(PROGRAM_ID, None)
                    .sign_as_sender(&receipt.sender),
            )?;
            println!(
                "sender sees {} transaction(s) it signed",
                sender_view.value.items.len()
            );
            let recipient_view = ring_rpc.first_page(
                GetDecryptedTransactionsRequest::unsigned(PROGRAM_ID, None)
                    .sign_as_recipient(&receipt.recipient.viewing_key)?,
            )?;
            println!(
                "recipient sees {} output(s) encrypted to it",
                recipient_view
                    .value
                    .items
                    .iter()
                    .map(|item| item.outputs.len())
                    .sum::<usize>()
            );
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

/// A local validator hands out SOL for free. Devnet and beyond need a funded
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
