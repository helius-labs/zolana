use std::{path::PathBuf, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::SetTreeFees,
    pda,
    state::{ProtocolConfig, TreeFeeSchedule},
};
use zolana_test_utils::smart_account::execute_sync_ix;
use zolana_tree::TreeAccount;

use crate::{
    init_protocol::{load_keypair, to_address, Cluster},
    tree_fees::{at_cost_for_transaction_size, print_schedule, ForesterClose, TransactionSize},
    update_protocol_config::find_vault_settings,
};

enum FeeSource {
    Explicit(TreeFeeSchedule),
    TransactionSize(TransactionSize),
}

pub struct Options {
    cluster: Cluster,
    rpc_url: Option<String>,
    payer: PathBuf,
    fee_signer: PathBuf,
    tree: Pubkey,
    fees: FeeSource,
    yes: bool,
    dry_run: bool,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut cluster = Cluster::Localnet;
        let mut rpc_url = None;
        let mut payer = None;
        let mut fee_signer = None;
        let mut tree = pda::tree(0);
        let mut fee_per_nullifier = None;
        let mut append_reimbursement = None;
        let mut close_reimbursement = None;
        let mut transaction_size = None;
        let mut yes = false;
        let mut dry_run = false;

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--cluster" => {
                    let value = args
                        .next()
                        .unwrap_or_else(|| usage_and_exit("--cluster missing value"));
                    cluster =
                        Cluster::parse(&value).unwrap_or_else(|e| usage_and_exit(&e.to_string()));
                }
                "--rpc-url" => {
                    rpc_url = Some(
                        args.next()
                            .unwrap_or_else(|| usage_and_exit("--rpc-url missing value")),
                    );
                }
                "--payer" => {
                    payer = Some(PathBuf::from(
                        args.next()
                            .unwrap_or_else(|| usage_and_exit("--payer missing value")),
                    ));
                }
                "--fee-signer" => {
                    fee_signer =
                        Some(PathBuf::from(args.next().unwrap_or_else(|| {
                            usage_and_exit("--fee-signer missing value")
                        })));
                }
                "--tree" => {
                    tree = parse_pubkey(args.next(), "--tree");
                }
                "--fee-per-nullifier" => {
                    fee_per_nullifier = Some(parse_u64(args.next(), "--fee-per-nullifier"));
                }
                "--append-reimbursement" => {
                    append_reimbursement = Some(parse_u64(args.next(), "--append-reimbursement"));
                }
                "--close-reimbursement" => {
                    close_reimbursement = Some(parse_u64(args.next(), "--close-reimbursement"));
                }
                "--transaction-size" => {
                    let value = args
                        .next()
                        .unwrap_or_else(|| usage_and_exit("--transaction-size missing value"));
                    transaction_size = Some(
                        TransactionSize::parse(&value)
                            .unwrap_or_else(|e| usage_and_exit(&e.to_string())),
                    );
                }
                "--yes" => yes = true,
                "--dry-run" => dry_run = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => usage_and_exit(&format!("unexpected arg {other:?}")),
            }
        }

        let payer = payer.unwrap_or_else(|| usage_and_exit("--payer is required"));
        let fee_signer = fee_signer.unwrap_or_else(|| usage_and_exit("--fee-signer is required"));
        let explicit = [fee_per_nullifier, append_reimbursement, close_reimbursement];
        let fees = match (transaction_size, explicit) {
            (Some(_), explicit) if explicit.iter().any(Option::is_some) => usage_and_exit(
                "--transaction-size derives the schedule; do not combine it with lamport flags",
            ),
            (Some(size), _) => FeeSource::TransactionSize(size),
            (
                None,
                [Some(fee_per_nullifier), Some(append_reimbursement), Some(close_reimbursement)],
            ) => FeeSource::Explicit(TreeFeeSchedule {
                fee_per_nullifier,
                append_reimbursement,
                close_reimbursement,
            }),
            (None, _) => usage_and_exit(
                "pass --transaction-size, or all of --fee-per-nullifier, \
                 --append-reimbursement and --close-reimbursement",
            ),
        };

        Self {
            cluster,
            rpc_url,
            payer,
            fee_signer,
            tree,
            fees,
            yes,
            dry_run,
        }
    }

    fn url(&self) -> String {
        self.rpc_url
            .clone()
            .unwrap_or_else(|| self.cluster.default_url().to_string())
    }
}

struct OnChainTreeFees {
    zkp_batch_size: u64,
    fees: TreeFeeSchedule,
    fee_balance: u64,
    lamports: u64,
}

fn read_tree_fees(rpc: &SolanaRpc, tree: &Pubkey) -> Result<OnChainTreeFees> {
    let mut account = rpc
        .get_account(to_address(tree))
        .context("fetching tree")?
        .ok_or_else(|| anyhow!("tree {tree} does not exist on this cluster"))?;
    let mut tree_account = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())
        .map_err(|e| anyhow!("tree {tree} has invalid data: {e:?}"))?;
    Ok(OnChainTreeFees {
        zkp_batch_size: tree_account.nullifier_tree().zkp_batch_size,
        fees: tree_account.fees(),
        fee_balance: tree_account.fee_balance(),
        lamports: account.lamports,
    })
}

fn read_protocol_config(rpc: &SolanaRpc) -> Result<ProtocolConfig> {
    let config_pda = pda::protocol_config();
    let account = rpc
        .get_account(to_address(&config_pda))
        .context("fetching protocol_config")?
        .ok_or_else(|| anyhow!("protocol config {config_pda} does not exist on this cluster"))?;
    ProtocolConfig::from_account_bytes(&account.data)
        .map_err(|e| anyhow!("protocol config {config_pda} has invalid data: {e:?}"))
        .copied()
}

fn resolve_fees(
    rpc: &SolanaRpc,
    options: &Options,
    config: &ProtocolConfig,
    member: Pubkey,
    zkp_batch_size: u64,
) -> Result<TreeFeeSchedule> {
    match options.fees {
        FeeSource::Explicit(fees) => Ok(fees),
        FeeSource::TransactionSize(size) => {
            let forester_authority = Pubkey::new_from_array(config.forester_authority.to_bytes());
            let settings = find_vault_settings(rpc, &forester_authority)?;
            let forester_close = ForesterClose {
                settings,
                member,
                tree: options.tree,
            };
            let closes_per_transaction = forester_close.closes_per_transaction(size)?;
            let fees = at_cost_for_transaction_size(zkp_batch_size, closes_per_transaction)?;
            print_schedule(size, closes_per_transaction, &fees);
            Ok(fees)
        }
    }
}

fn print_fees(label: &str, state: &OnChainTreeFees) {
    println!("{label}:");
    println!("  lamports={}", state.lamports);
    println!("  zkp_batch_size={}", state.zkp_batch_size);
    println!("  fee_per_nullifier={}", state.fees.fee_per_nullifier);
    println!("  append_reimbursement={}", state.fees.append_reimbursement);
    println!("  close_reimbursement={}", state.fees.close_reimbursement);
    println!("  fee_balance={}", state.fee_balance);
}

pub fn run(options: Options) -> Result<()> {
    let payer = load_keypair(&options.payer, "payer")?;
    let fee_signer = load_keypair(&options.fee_signer, "fee-signer")?;
    if options.cluster == Cluster::Mainnet && !options.dry_run && !options.yes {
        bail!("refusing to send mainnet transactions without --yes");
    }

    let url = options.url();
    let rpc = SolanaRpc::new(url.clone());

    let current = read_tree_fees(&rpc, &options.tree)?;
    let config = read_protocol_config(&rpc)?;
    let fee_authority = Pubkey::new_from_array(config.fee_authority.to_bytes());
    let fees = resolve_fees(
        &rpc,
        &options,
        &config,
        payer.pubkey(),
        current.zkp_batch_size,
    )?;
    println!("cluster={}", options.cluster.name());
    println!("rpc_url={url}");
    println!("dry_run={}", options.dry_run);
    println!("payer={}", payer.pubkey());
    println!("fee_signer={}", fee_signer.pubkey());
    println!("fee_authority={fee_authority}");
    println!("tree={}", options.tree);
    print_fees("current fees", &current);
    println!(
        "requested: fee_per_nullifier={} append_reimbursement={} close_reimbursement={}",
        fees.fee_per_nullifier, fees.append_reimbursement, fees.close_reimbursement
    );

    let settings = find_vault_settings(&rpc, &fee_authority)?;
    println!("fee_settings={settings}");

    let inner = SetTreeFees {
        authority: fee_authority,
        tree: options.tree,
        fees,
    }
    .instruction();
    let instruction = execute_sync_ix(&settings, 0, &[fee_signer.pubkey()], &[inner]);

    if options.dry_run {
        println!("dry_run: no transactions sent");
        return Ok(());
    }

    let signature = rpc
        .create_and_send_transaction(
            &[instruction],
            to_address(&payer.pubkey()),
            &[&payer, &fee_signer],
        )
        .map_err(|e| anyhow!("set_tree_fees failed: {e}"))?;
    println!("set_tree_fees sig={signature}");

    let updated = read_tree_fees(&rpc, &options.tree)?;
    print_fees("updated fees", &updated);
    Ok(())
}

fn parse_u64(value: Option<String>, flag: &str) -> u64 {
    value
        .as_deref()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| usage_and_exit(&format!("{flag} expects a lamport amount")))
}

fn parse_pubkey(value: Option<String>, flag: &str) -> Pubkey {
    value
        .as_deref()
        .and_then(|value| Pubkey::from_str(value).ok())
        .unwrap_or_else(|| usage_and_exit(&format!("{flag} expects a base58 pubkey")))
}

fn usage_and_exit(message: &str) -> ! {
    eprintln!("error: {message}");
    print_help();
    std::process::exit(2);
}

fn print_help() {
    println!("xtask set-tree-fees [flags]");
    println!();
    println!("Set a pool tree's forester fee schedule. The instruction is wrapped in a");
    println!("Squads execute_sync signed by one member of the fee authority smart account.");
    println!();
    println!("Flags:");
    println!("  --cluster <localnet|devnet|mainnet>   default: localnet");
    println!("  --rpc-url <URL>                       override the cluster default RPC URL");
    println!("  --payer <KEYPAIR_PATH>                outer fee payer (required)");
    println!("  --fee-signer <KEYPAIR_PATH>           a member of the fee authority (required)");
    println!("  --tree <PUBKEY>                       tree account (default: tree 0)");
    println!("  --transaction-size <v0|v1>            derive the at-cost schedule from the size");
    println!("                                        limit of the forester's close transactions");
    println!(
        "                                        (1232 or 4096 bytes) and the tree's batch size"
    );
    println!("  --fee-per-nullifier <LAMPORTS>        charged per queued nullifier");
    println!("  --append-reimbursement <LAMPORTS>     paid per applied ZKP batch");
    println!("  --close-reimbursement <LAMPORTS>      paid per closed nullifier PDA");
    println!(
        "                                        (all three required without --transaction-size)"
    );
    println!("  --yes                                 confirm mainnet sends");
    println!("  --dry-run                             print current state, send nothing");
    println!("  -h | --help                           print this help");
}
