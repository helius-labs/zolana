use clap::{ArgAction, Args, Parser, Subcommand};

use crate::config::{
    DEFAULT_GOSSIP_HOST, DEFAULT_LIMIT_LEDGER_SIZE, DEFAULT_LOG_DIR, DEFAULT_PHOTON_PORT,
    DEFAULT_PROVER_PORT, DEFAULT_RPC_PORT,
};

#[derive(Debug, Parser)]
#[command(name = "zolana", about = "Local Zolana developer tooling")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CliCommand {
    #[command(name = "config", about = "Show or update CLI configuration")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    #[command(name = "wallet", about = "Private wallet commands")]
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },

    #[command(name = "dev", about = "Local development environment commands")]
    Dev {
        #[command(subcommand)]
        command: DevCommand,
    },

    #[command(
        name = "test-env",
        about = "Start the local Zolana test validator (alias for `dev start`)"
    )]
    TestEnv(Box<TestValidatorOptions>),

    #[command(
        name = "sync",
        about = "Sync private wallet state. Transfers run sync automatically."
    )]
    Sync(SyncOptions),

    #[command(name = "balance", about = "Show private wallet balances")]
    Balance(BalanceOptions),

    #[command(name = "utxos", about = "List spendable private notes")]
    Utxos(UtxosOptions),

    #[command(name = "deposit", about = "Deposit into private wallet")]
    Deposit(DepositOptions),

    #[command(name = "transfer", about = "Send a private transfer")]
    Transfer(TransferOptions),

    #[command(name = "withdraw", about = "Withdraw to public address")]
    Withdraw(WithdrawOptions),

    #[command(
        name = "split",
        about = "Split a private note into equal self-owned notes"
    )]
    Split(SplitOptions),

    #[command(
        name = "merge",
        about = "Consolidate several private notes into one (up to 8 in, 1 out)"
    )]
    Merge(MergeOptions),

    #[command(
        name = "set-merging",
        about = "Enable or disable the merge service for this wallet"
    )]
    SetMerging(SetMergingOptions),
}

#[derive(Debug, Subcommand)]
pub(crate) enum DevCommand {
    #[command(name = "start", about = "Start the local Zolana test validator")]
    Start(Box<TestValidatorOptions>),

    #[command(name = "prover", about = "Local prover server commands")]
    Prover {
        #[command(subcommand)]
        command: DevProverCommand,
    },

    #[command(name = "pool", about = "Local pool setup commands")]
    Pool {
        #[command(subcommand)]
        command: DevPoolCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum DevProverCommand {
    #[command(name = "start", about = "Start the local prover server")]
    Start(StartProverOptions),
}

#[derive(Debug, Subcommand, Clone)]
pub(crate) enum DevPoolCommand {
    #[command(
        name = "create-tree",
        about = "Initialize protocol config and a pool tree on the configured RPC"
    )]
    CreateTree(CreateTreeOptions),

    #[command(
        name = "test-mint",
        about = "Create a local SPL test mint, fund the wallet, and store its asset mapping"
    )]
    TestMint(TestMintOptions),
}

#[derive(Debug, Subcommand, Clone)]
pub(crate) enum ConfigCommand {
    #[command(name = "get", about = "Show the CLI configuration file")]
    Get,

    #[command(name = "set", about = "Update the CLI configuration file")]
    Set(ConfigSetOptions),

    #[command(name = "asset", about = "Manage the local SPL asset registry")]
    Asset {
        #[command(subcommand)]
        command: ConfigAssetCommand,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub(crate) enum ConfigAssetCommand {
    #[command(name = "list", about = "Show locally configured assets")]
    List,

    #[command(name = "add", about = "Add or update a local SPL asset mapping")]
    Add(ConfigAddAssetOptions),

    #[command(name = "path", about = "Print the CLI config file path")]
    Path,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ConfigSetOptions {
    #[arg(
        long = "keypair",
        help = "Default wallet file path",
        value_name = "PATH"
    )]
    pub(crate) keypair: Option<String>,

    #[arg(long = "rpc-url", help = "Default Solana RPC URL")]
    pub(crate) rpc_url: Option<String>,

    #[arg(long = "indexer-url", help = "Default Photon indexer URL")]
    pub(crate) indexer_url: Option<String>,

    #[arg(long = "prover-url", help = "Default prover server URL")]
    pub(crate) prover_url: Option<String>,

    #[arg(long, help = "Default shielded-pool tree account")]
    pub(crate) tree: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct ConfigAddAssetOptions {
    #[arg(long, help = "SPL mint pubkey")]
    pub(crate) mint: String,

    #[arg(long = "asset-id", help = "Shielded-pool asset id assigned on-chain")]
    pub(crate) asset_id: u64,

    #[arg(
        long = "token-account",
        help = "Optional local token account for this mint"
    )]
    pub(crate) token_account: Option<String>,
}

#[derive(Debug, Subcommand, Clone)]
pub(crate) enum WalletCommand {
    #[command(
        name = "new",
        about = "Create a local ed25519 wallet keypair and register it on-chain"
    )]
    New(NewWalletOptions),

    #[command(
        name = "address",
        about = "Print the selected wallet's shielded owner hash (or its funding pubkey)"
    )]
    Address(AddressOptions),

    #[command(
        name = "register",
        about = "Publish the wallet's shielded keys on-chain so its Solana pubkey is payable"
    )]
    Register(RegisterOptions),
}

#[derive(Debug)]
pub(crate) struct ProgramSpec {
    pub(crate) address: String,
    pub(crate) path: String,
}

#[derive(Debug)]
pub(crate) struct UpgradeableProgramSpec {
    pub(crate) address: String,
    pub(crate) path: String,
    pub(crate) upgrade_authority: String,
}

#[derive(Args, Debug)]
pub(crate) struct TestValidatorOptions {
    #[arg(long, help = "Do not start the prover server")]
    pub(crate) skip_prover: bool,

    #[arg(long, help = "Start a local Photon indexer")]
    pub(crate) with_photon: bool,

    #[arg(
        long,
        help = "Use locally built artifacts instead of the pinned release"
    )]
    pub(crate) local: bool,

    #[arg(long, help = "Stop the local validator environment")]
    pub(crate) stop: bool,

    #[arg(
        long = "use-surfpool",
        conflicts_with = "no_use_surfpool",
        help = "Use surfpool as the validator backend (default)"
    )]
    pub(crate) use_surfpool: bool,

    #[arg(
        long = "no-use-surfpool",
        conflicts_with = "use_surfpool",
        help = "Use solana-test-validator directly"
    )]
    pub(crate) no_use_surfpool: bool,

    #[arg(long, help = "Reuse the existing validator ledger")]
    pub(crate) skip_reset: bool,

    #[arg(long, default_value_t = DEFAULT_RPC_PORT, help = "Validator RPC port")]
    pub(crate) rpc_port: u16,

    #[arg(
        long,
        help = "Faucet port for solana-test-validator",
        value_name = "PORT"
    )]
    pub(crate) faucet_port: Option<u16>,

    #[arg(
        long,
        default_value_t = DEFAULT_PROVER_PORT,
        help = "Prover server port"
    )]
    pub(crate) prover_port: u16,

    #[arg(
        long = "prover-auto-download",
        env = "ZOLANA_PROVER_AUTO_DOWNLOAD",
        default_value_t = true,
        action = ArgAction::Set,
        value_parser = clap::builder::FalseyValueParser::new(),
        help = "Allow the prover to download missing proving keys"
    )]
    pub(crate) prover_auto_download: bool,

    #[arg(
        long,
        default_value_t = DEFAULT_PHOTON_PORT,
        help = "Photon indexer API port"
    )]
    pub(crate) photon_port: u16,

    #[arg(
        long,
        help = "Photon database URL; omit for Photon's temporary SQLite database"
    )]
    pub(crate) photon_db_url: Option<String>,

    #[arg(
        long,
        default_value = "latest",
        help = "Photon start slot, such as `latest` or an explicit slot"
    )]
    pub(crate) photon_start_slot: String,

    #[arg(
        long,
        default_value = DEFAULT_GOSSIP_HOST,
        help = "Validator host or bind address"
    )]
    pub(crate) gossip_host: String,

    #[arg(
        long,
        default_value_t = DEFAULT_LIMIT_LEDGER_SIZE,
        help = "solana-test-validator ledger retention"
    )]
    pub(crate) limit_ledger_size: u64,

    #[arg(
        long,
        help = "Ledger path for solana-test-validator",
        value_name = "PATH"
    )]
    pub(crate) ledger: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_DIR, help = "Service log directory")]
    pub(crate) log_dir: String,

    #[arg(
        long = "sbf-program",
        num_args = 2,
        value_names = ["ADDRESS", "PATH"],
        help = "Load an immutable SBF program"
    )]
    pub(crate) sbf_programs: Vec<String>,

    #[arg(
        long = "upgradeable-program",
        num_args = 3,
        value_names = ["ADDRESS", "PATH", "AUTHORITY"],
        help = "Load an upgradeable SBF program"
    )]
    pub(crate) upgradeable_programs: Vec<String>,

    #[arg(
        long = "account-dir",
        help = "Additional account directory",
        value_name = "PATH"
    )]
    pub(crate) account_dirs: Vec<String>,

    #[arg(
        long = "validator-args",
        help = "Forward a whitespace-separated argument string to the validator",
        value_name = "ARGS"
    )]
    pub(crate) validator_arg_groups: Vec<String>,

    #[arg(last = true, allow_hyphen_values = true, value_name = "VALIDATOR_ARG")]
    pub(crate) trailing_validator_args: Vec<String>,

    #[arg(
        long,
        help = "solana-test-validator geyser config",
        value_name = "PATH"
    )]
    pub(crate) geyser_config: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct StartProverOptions {
    #[arg(
        long = "prover-port",
        alias = "port",
        visible_alias = "port",
        default_value_t = DEFAULT_PROVER_PORT,
        help = "Prover server port"
    )]
    pub(crate) prover_port: u16,

    #[arg(
        long = "redis-url",
        alias = "redisUrl",
        visible_alias = "redisUrl",
        help = "Redis URL for prover state"
    )]
    pub(crate) redis_url: Option<String>,

    #[arg(
        long = "auto-download",
        env = "ZOLANA_PROVER_AUTO_DOWNLOAD",
        default_value_t = true,
        action = ArgAction::Set,
        value_parser = clap::builder::FalseyValueParser::new(),
        help = "Allow the prover to download missing proving keys"
    )]
    pub(crate) auto_download: bool,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct WalletKeypairOptions {
    #[arg(
        long = "keypair",
        help = "Path to private keypair file (default: ~/.config/zolana/pid.json)",
        value_name = "PATH"
    )]
    pub(crate) keypair: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct NewWalletOptions {
    #[arg(
        long = "outfile",
        help = "Output wallet file (default: configured keypair path or ~/.config/zolana/pid.json)",
        value_name = "PATH"
    )]
    pub(crate) outfile: Option<String>,

    #[arg(
        long = "funding-keypair",
        help = "Use an existing Solana keypair file (e.g. ~/.config/solana/id.json) as the wallet identity and fee payer instead of generating a new one",
        value_name = "PATH"
    )]
    pub(crate) funding_keypair: Option<String>,

    #[arg(
        long = "rpc-url",
        help = "Solana RPC URL used to register the wallet (default: configured value or http://127.0.0.1:8899)"
    )]
    pub(crate) rpc_url: Option<String>,

    #[arg(
        long = "airdrop-lamports",
        help = "Request a localnet airdrop for the wallet funding key before registering"
    )]
    pub(crate) airdrop_lamports: Option<u64>,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct AddressOptions {
    #[command(flatten)]
    pub(crate) keypair: WalletKeypairOptions,

    #[arg(
        long,
        help = "Print the wallet's public funding/fee-payer pubkey instead"
    )]
    pub(crate) funding: bool,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct RegisterOptions {
    #[command(flatten)]
    pub(crate) wallet: RpcWalletOptions,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct RpcWalletOptions {
    #[command(flatten)]
    pub(crate) keypair: WalletKeypairOptions,

    #[arg(
        long = "rpc-url",
        help = "Solana RPC URL (default: configured value or http://127.0.0.1:8899)"
    )]
    pub(crate) rpc_url: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct SyncOptions {
    #[command(flatten)]
    pub(crate) keypair: WalletKeypairOptions,

    #[arg(
        long = "rpc-url",
        help = "Solana RPC URL (default: configured value or http://127.0.0.1:8899)"
    )]
    pub(crate) rpc_url: Option<String>,

    #[arg(
        long = "indexer-url",
        help = "Photon indexer URL (default: configured value or http://127.0.0.1:8784)"
    )]
    pub(crate) indexer_url: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct NetworkWalletOptions {
    #[command(flatten)]
    pub(crate) sync: SyncOptions,

    #[arg(
        long,
        help = "Shielded-pool tree account (default: configured tree from `zolana config`)"
    )]
    pub(crate) tree: Option<String>,

    #[arg(
        long = "prover-url",
        help = "Prover server URL (default: configured value or http://127.0.0.1:3001)"
    )]
    pub(crate) prover_url: Option<String>,

    #[arg(
        long = "airdrop-lamports",
        help = "Request a localnet airdrop for the wallet funding key before submitting"
    )]
    pub(crate) airdrop_lamports: Option<u64>,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct CreateTreeOptions {
    #[command(flatten)]
    pub(crate) sync: SyncOptions,

    #[arg(long, help = "Tree keypair path to create or reuse")]
    pub(crate) tree_keypair: String,

    #[arg(
        long = "airdrop-lamports",
        default_value_t = 20_000_000_000,
        help = "Localnet airdrop amount for the wallet funding key"
    )]
    pub(crate) airdrop_lamports: u64,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct TestMintOptions {
    #[command(flatten)]
    pub(crate) sync: SyncOptions,

    #[arg(long, help = "Raw token units to mint to the wallet owner")]
    pub(crate) amount: u64,

    #[arg(
        long = "authority-path",
        help = "Wallet file whose funding key is protocol and mint authority (default: --keypair wallet)",
        value_name = "PATH"
    )]
    pub(crate) authority_path: Option<String>,

    #[arg(
        long = "airdrop-lamports",
        help = "Request a localnet airdrop for the authority before creating accounts"
    )]
    pub(crate) airdrop_lamports: Option<u64>,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct DepositOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(
        long,
        help = "Optional registered recipient Solana pubkey (defaults to the --keypair wallet owner)"
    )]
    pub(crate) to: Option<String>,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,

    #[arg(long, help = "Amount to deposit")]
    pub(crate) amount: u64,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct TransferOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(
        long = "to",
        help = "Recipient Solana pubkey; registered recipients receive a shielded transfer, unregistered recipients receive a public SOL withdrawal",
        value_name = "PUBKEY"
    )]
    pub(crate) to: String,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,

    #[arg(long, help = "Amount to transfer")]
    pub(crate) amount: u64,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct WithdrawOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(long, help = "Destination public address")]
    pub(crate) to: String,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,

    #[arg(long, help = "Amount to withdraw")]
    pub(crate) amount: u64,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct SplitOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,

    #[arg(
        long,
        value_parser = clap::value_parser!(u8).range(2..=8),
        help = "Number of equal output notes to produce (2-8)"
    )]
    pub(crate) parts: u8,

    #[arg(
        long,
        help = "Optional input note commitment hash (hex); defaults to the largest plain note"
    )]
    pub(crate) input: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct BalanceOptions {
    #[command(flatten)]
    pub(crate) sync: SyncOptions,

    #[arg(long, help = "Optional mint filter (address or SOL)")]
    pub(crate) mint: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct UtxosOptions {
    #[command(flatten)]
    pub(crate) sync: SyncOptions,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub(crate) struct MergeOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,

    #[arg(
        long = "input",
        help = "Input note commitment hash (hex); repeat to name each note. Omit to auto-sweep the smallest plain notes.",
        value_name = "HASH"
    )]
    pub(crate) input: Vec<String>,
}

#[derive(Args, Debug, Clone, PartialEq)]
#[command(group(
    clap::ArgGroup::new("merge_toggle")
        .required(true)
        .args(["enable", "disable"])
))]
pub(crate) struct SetMergingOptions {
    #[command(flatten)]
    pub(crate) sync: SyncOptions,

    #[arg(
        long,
        action = ArgAction::SetTrue,
        help = "Enable the merge service for this wallet"
    )]
    pub(crate) enable: bool,

    #[arg(
        long,
        action = ArgAction::SetTrue,
        help = "Disable the merge service for this wallet"
    )]
    pub(crate) disable: bool,
}

impl TestValidatorOptions {
    pub(crate) fn use_surfpool_backend(&self) -> bool {
        self.use_surfpool || !self.no_use_surfpool
    }

    /// Fetch programs, account snapshots, and helper binaries from the pinned
    /// release unless the user opted into local builds or passed explicit
    /// programs (in which case those local artifacts take precedence).
    pub(crate) fn use_release(&self) -> bool {
        !self.local && self.sbf_programs.is_empty() && self.upgradeable_programs.is_empty()
    }

    pub(crate) fn sbf_program_specs(&self) -> Vec<ProgramSpec> {
        self.sbf_programs
            .chunks_exact(2)
            .filter_map(|chunk| match chunk {
                [address, path] => Some(ProgramSpec {
                    address: address.clone(),
                    path: path.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn upgradeable_program_specs(&self) -> Vec<UpgradeableProgramSpec> {
        self.upgradeable_programs
            .chunks_exact(3)
            .filter_map(|chunk| match chunk {
                [address, path, upgrade_authority] => Some(UpgradeableProgramSpec {
                    address: address.clone(),
                    path: path.clone(),
                    upgrade_authority: upgrade_authority.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn validator_args(&self) -> Vec<String> {
        let mut args = self
            .validator_arg_groups
            .iter()
            .flat_map(|group| group.split_whitespace().map(str::to_string))
            .collect::<Vec<_>>();
        args.extend(self.trailing_validator_args.iter().cloned());
        args
    }
}

#[cfg(test)]
pub(crate) fn parse_cli(values: &[&str]) -> Cli {
    Cli::try_parse_from(std::iter::once("zolana").chain(values.iter().copied())).expect("parse cli")
}

#[cfg(test)]
pub(crate) fn parse_validator(values: &[&str]) -> TestValidatorOptions {
    match parse_cli(
        &std::iter::once("dev")
            .chain(std::iter::once("start"))
            .chain(values.iter().copied())
            .collect::<Vec<_>>(),
    )
    .command
    .expect("command")
    {
        CliCommand::Dev {
            command: DevCommand::Start(opts),
        } => *opts,
        _ => panic!("expected dev start command"),
    }
}

#[cfg(test)]
pub(crate) fn parse_dev_pool(values: &[&str]) -> DevPoolCommand {
    match parse_cli(
        &["dev", "pool"]
            .into_iter()
            .chain(values.iter().copied())
            .collect::<Vec<_>>(),
    )
    .command
    .expect("command")
    {
        CliCommand::Dev {
            command: DevCommand::Pool { command },
        } => command,
        _ => panic!("expected dev pool command"),
    }
}

#[cfg(test)]
pub(crate) fn parse_wallet(values: &[&str]) -> WalletCommand {
    match parse_cli(
        &std::iter::once("wallet")
            .chain(values.iter().copied())
            .collect::<Vec<_>>(),
    )
    .command
    .expect("command")
    {
        CliCommand::Wallet { command } => command,
        _ => panic!("expected wallet command"),
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn dev_start_help_documents_localnet_flags() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("dev")
            .expect("dev subcommand")
            .find_subcommand_mut("start")
            .expect("dev start subcommand")
            .render_long_help()
            .to_string();

        for flag in [
            "--faucet-port <PORT>",
            "--ledger <PATH>",
            "--log-dir <LOG_DIR>",
            "--photon-port <PHOTON_PORT>",
            "--sbf-program <ADDRESS> <PATH>",
        ] {
            assert!(help.contains(flag), "missing help entry for {flag}");
        }
    }

    #[test]
    fn clap_accepts_top_level_and_command_help() {
        for args in [
            ["zolana", "--help"].as_slice(),
            ["zolana", "dev", "--help"].as_slice(),
            ["zolana", "dev", "start", "--help"].as_slice(),
            ["zolana", "dev", "prover", "--help"].as_slice(),
            ["zolana", "dev", "prover", "start", "--help"].as_slice(),
            ["zolana", "dev", "pool", "--help"].as_slice(),
            ["zolana", "dev", "pool", "create-tree", "--help"].as_slice(),
            ["zolana", "dev", "pool", "test-mint", "--help"].as_slice(),
            ["zolana", "test-env", "--help"].as_slice(),
            ["zolana", "config", "--help"].as_slice(),
            ["zolana", "config", "asset", "--help"].as_slice(),
            ["zolana", "config", "asset", "list", "--help"].as_slice(),
            ["zolana", "config", "asset", "add", "--help"].as_slice(),
            ["zolana", "config", "asset", "path", "--help"].as_slice(),
            ["zolana", "wallet", "--help"].as_slice(),
            ["zolana", "wallet", "new", "--help"].as_slice(),
            ["zolana", "wallet", "address", "--help"].as_slice(),
            ["zolana", "wallet", "register", "--help"].as_slice(),
            ["zolana", "sync", "--help"].as_slice(),
            ["zolana", "balance", "--help"].as_slice(),
            ["zolana", "utxos", "--help"].as_slice(),
            ["zolana", "deposit", "--help"].as_slice(),
            ["zolana", "transfer", "--help"].as_slice(),
            ["zolana", "withdraw", "--help"].as_slice(),
            ["zolana", "split", "--help"].as_slice(),
            ["zolana", "merge", "--help"].as_slice(),
            ["zolana", "set-merging", "--help"].as_slice(),
        ] {
            let error = Cli::try_parse_from(args).expect_err("help exits early");
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        }
    }

    #[test]
    fn parses_local_validator_flags() {
        let opts = parse_validator(&[
            "--no-use-surfpool",
            "--skip-prover",
            "--rpc-port",
            "8901",
            "--faucet-port",
            "9901",
            "--with-photon",
            "--photon-port",
            "8785",
            "--photon-db-url",
            "sqlite:///tmp/zolana-photon-test.db",
            "--photon-start-slot",
            "latest",
            "--ledger",
            "target/localnet/ledger",
            "--log-dir",
            "target/localnet/logs",
            "--sbf-program",
            "Pool111111111111111111111111111111111111111",
            "target/deploy/pool.so",
            "--sbf-program",
            "Zone111111111111111111111111111111111111111",
            "target/deploy/zone.so",
        ]);

        assert!(!opts.use_surfpool_backend());
        assert!(opts.skip_prover);
        assert!(opts.with_photon);
        assert_eq!(opts.rpc_port, 8901);
        assert_eq!(opts.faucet_port, Some(9901));
        assert_eq!(opts.photon_port, 8785);
        assert_eq!(
            opts.photon_db_url.as_deref(),
            Some("sqlite:///tmp/zolana-photon-test.db")
        );
        assert_eq!(opts.photon_start_slot, "latest");
        assert_eq!(opts.ledger.as_deref(), Some("target/localnet/ledger"));
        assert_eq!(opts.log_dir, "target/localnet/logs");
        let programs = opts.sbf_program_specs();
        assert_eq!(programs.len(), 2);
        let mut programs = programs.iter();
        let Some(pool_program) = programs.next() else {
            panic!("expected pool program");
        };
        assert_eq!(
            pool_program.address,
            "Pool111111111111111111111111111111111111111"
        );
        assert_eq!(pool_program.path, "target/deploy/pool.so");
        let Some(zone_program) = programs.next() else {
            panic!("expected zone program");
        };
        assert_eq!(
            zone_program.address,
            "Zone111111111111111111111111111111111111111"
        );
        assert_eq!(zone_program.path, "target/deploy/zone.so");
        assert!(programs.next().is_none());
    }

    #[test]
    fn use_release_reflects_local_flag_and_explicit_programs() {
        let default = parse_validator(&[]);
        assert!(default.use_release());
        assert!(!default.local);

        let local = parse_validator(&["--local"]);
        assert!(local.local);
        assert!(!local.use_release());

        let explicit_program = parse_validator(&[
            "--sbf-program",
            "Pool111111111111111111111111111111111111111",
            "target/deploy/pool.so",
        ]);
        assert!(!explicit_program.use_release());
    }

    #[test]
    fn parses_test_env_alias_options() {
        let Some(CliCommand::TestEnv(opts)) = parse_cli(&[
            "test-env",
            "--skip-prover",
            "--skip-reset",
            "--rpc-port",
            "8901",
        ])
        .command
        else {
            panic!("expected test-env command");
        };

        assert!(opts.skip_prover);
        assert!(opts.skip_reset);
        assert_eq!(opts.rpc_port, 8901);
    }

    #[test]
    fn parses_dev_prover_start_options() {
        let command = parse_cli(&[
            "dev",
            "prover",
            "start",
            "--port",
            "3002",
            "--redis-url",
            "redis://localhost:6379/15",
        ])
        .command
        .expect("command");
        let CliCommand::Dev {
            command:
                DevCommand::Prover {
                    command: DevProverCommand::Start(opts),
                },
        } = command
        else {
            panic!("expected dev prover start command");
        };

        assert_eq!(opts.prover_port, 3002);
        assert_eq!(opts.redis_url.as_deref(), Some("redis://localhost:6379/15"));
    }

    #[test]
    fn parses_dev_prover_start_auto_download_option() {
        let command = parse_cli(&["dev", "prover", "start", "--auto-download", "off"])
            .command
            .expect("command");
        let CliCommand::Dev {
            command:
                DevCommand::Prover {
                    command: DevProverCommand::Start(opts),
                },
        } = command
        else {
            panic!("expected dev prover start command");
        };

        assert!(!opts.auto_download);
    }

    #[test]
    fn parses_test_validator_prover_auto_download_option() {
        let opts = parse_validator(&["--prover-auto-download", "off"]);

        assert!(!opts.prover_auto_download);
    }

    #[test]
    fn parses_wallet_new_options() {
        let WalletCommand::New(opts) = parse_wallet(&[
            "new",
            "--outfile",
            "/tmp/alice.pid.json",
            "--funding-keypair",
            "/tmp/solana.json",
            "--rpc-url",
            "http://127.0.0.1:8900",
            "--airdrop-lamports",
            "1000000000",
        ]) else {
            panic!("expected wallet new command");
        };
        let expected = NewWalletOptions {
            outfile: Some("/tmp/alice.pid.json".to_string()),
            funding_keypair: Some("/tmp/solana.json".to_string()),
            rpc_url: Some("http://127.0.0.1:8900".to_string()),
            airdrop_lamports: Some(1_000_000_000),
        };
        assert_eq!(opts, expected);
    }

    #[test]
    fn parses_wallet_address_options() {
        let WalletCommand::Address(opts) =
            parse_wallet(&["address", "--keypair", "/tmp/alice.pid.json", "--funding"])
        else {
            panic!("expected wallet address command");
        };
        assert_eq!(opts.keypair.keypair.as_deref(), Some("/tmp/alice.pid.json"));
        assert!(opts.funding);
    }

    #[test]
    fn parses_wallet_register_options() {
        let WalletCommand::Register(opts) = parse_wallet(&[
            "register",
            "--keypair",
            "/tmp/alice.pid.json",
            "--rpc-url",
            "http://127.0.0.1:8900",
        ]) else {
            panic!("expected wallet register command");
        };
        assert_eq!(
            opts.wallet.keypair.keypair.as_deref(),
            Some("/tmp/alice.pid.json")
        );
        assert_eq!(
            opts.wallet.rpc_url.as_deref(),
            Some("http://127.0.0.1:8900")
        );
    }

    #[test]
    fn parses_dev_pool_create_tree_options() {
        let DevPoolCommand::CreateTree(opts) = parse_dev_pool(&[
            "create-tree",
            "--keypair",
            "/tmp/alice.pid.json",
            "--tree-keypair",
            "/tmp/tree.json",
            "--rpc-url",
            "http://127.0.0.1:8900",
            "--indexer-url",
            "http://127.0.0.1:8785",
            "--airdrop-lamports",
            "1000000000",
        ]) else {
            panic!("expected dev pool create-tree command");
        };
        let expected = CreateTreeOptions {
            sync: SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some("/tmp/alice.pid.json".to_string()),
                },
                rpc_url: Some("http://127.0.0.1:8900".to_string()),
                indexer_url: Some("http://127.0.0.1:8785".to_string()),
            },
            tree_keypair: "/tmp/tree.json".to_string(),
            airdrop_lamports: 1_000_000_000,
        };
        assert_eq!(opts, expected);
    }

    #[test]
    fn parses_config_asset_commands() {
        let Some(CliCommand::Config { command }) = parse_cli(&[
            "config",
            "asset",
            "add",
            "--mint",
            "Mint111111111111111111111111111111111111111",
            "--asset-id",
            "2",
            "--token-account",
            "Token11111111111111111111111111111111111111",
        ])
        .command
        else {
            panic!("expected config command");
        };
        let ConfigCommand::Asset {
            command: ConfigAssetCommand::Add(opts),
        } = command
        else {
            panic!("expected config asset add command");
        };
        let expected = ConfigAddAssetOptions {
            mint: "Mint111111111111111111111111111111111111111".to_string(),
            asset_id: 2,
            token_account: Some("Token11111111111111111111111111111111111111".to_string()),
        };
        assert_eq!(opts, expected);
    }

    #[test]
    fn parses_config_asset_list_and_path() {
        let Some(CliCommand::Config {
            command:
                ConfigCommand::Asset {
                    command: ConfigAssetCommand::List,
                },
        }) = parse_cli(&["config", "asset", "list"]).command
        else {
            panic!("expected config asset list command");
        };

        let Some(CliCommand::Config {
            command:
                ConfigCommand::Asset {
                    command: ConfigAssetCommand::Path,
                },
        }) = parse_cli(&["config", "asset", "path"]).command
        else {
            panic!("expected config asset path command");
        };
    }

    #[test]
    fn parses_dev_pool_test_mint_options() {
        let DevPoolCommand::TestMint(opts) = parse_dev_pool(&[
            "test-mint",
            "--keypair",
            "/tmp/alice.pid.json",
            "--amount",
            "1000000",
            "--authority-path",
            "/tmp/admin.pid.json",
            "--airdrop-lamports",
            "1000000000",
        ]) else {
            panic!("expected dev pool test-mint command");
        };
        let expected = TestMintOptions {
            sync: SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some("/tmp/alice.pid.json".to_string()),
                },
                rpc_url: None,
                indexer_url: None,
            },
            amount: 1_000_000,
            authority_path: Some("/tmp/admin.pid.json".to_string()),
            airdrop_lamports: Some(1_000_000_000),
        };
        assert_eq!(opts, expected);
    }

    #[test]
    fn parses_sync_and_balance_options() {
        let Some(CliCommand::Sync(sync)) = parse_cli(&[
            "sync",
            "--keypair",
            "/tmp/alice.pid.json",
            "--rpc-url",
            "http://127.0.0.1:8900",
            "--indexer-url",
            "http://127.0.0.1:8785",
        ])
        .command
        else {
            panic!("expected sync command");
        };
        let expected = SyncOptions {
            keypair: WalletKeypairOptions {
                keypair: Some("/tmp/alice.pid.json".to_string()),
            },
            rpc_url: Some("http://127.0.0.1:8900".to_string()),
            indexer_url: Some("http://127.0.0.1:8785".to_string()),
        };
        assert_eq!(sync, expected);

        let Some(CliCommand::Balance(balance)) = parse_cli(&[
            "balance",
            "--keypair",
            "/tmp/alice.pid.json",
            "--mint",
            "SOL",
        ])
        .command
        else {
            panic!("expected balance command");
        };
        let expected = BalanceOptions {
            sync: SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some("/tmp/alice.pid.json".to_string()),
                },
                rpc_url: None,
                indexer_url: None,
            },
            mint: Some("SOL".to_string()),
        };
        assert_eq!(balance, expected);
    }

    #[test]
    fn parses_merge_options() {
        let Some(CliCommand::Merge(opts)) = parse_cli(&[
            "merge",
            "--keypair",
            "/tmp/alice.pid.json",
            "--tree",
            "Tree111111111111111111111111111111111111111",
            "--mint",
            "SOL",
            "--input",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--input",
            "0202020202020202020202020202020202020202020202020202020202020202",
        ])
        .command
        else {
            panic!("expected merge command");
        };

        let expected = MergeOptions {
            network: NetworkWalletOptions {
                sync: SyncOptions {
                    keypair: WalletKeypairOptions {
                        keypair: Some("/tmp/alice.pid.json".to_string()),
                    },
                    rpc_url: None,
                    indexer_url: None,
                },
                tree: Some("Tree111111111111111111111111111111111111111".to_string()),
                prover_url: None,
                airdrop_lamports: None,
            },
            mint: "SOL".to_string(),
            input: vec![
                "0101010101010101010101010101010101010101010101010101010101010101".to_string(),
                "0202020202020202020202020202020202020202020202020202020202020202".to_string(),
            ],
        };
        assert_eq!(opts, expected);

        // Auto-sweep: no --input.
        let Some(CliCommand::Merge(opts)) =
            parse_cli(&["merge", "--keypair", "/tmp/alice.pid.json"]).command
        else {
            panic!("expected merge command");
        };
        assert!(opts.input.is_empty());
    }

    #[test]
    fn parses_set_merging_options() {
        let Some(CliCommand::SetMerging(opts)) = parse_cli(&[
            "set-merging",
            "--keypair",
            "/tmp/alice.pid.json",
            "--rpc-url",
            "http://127.0.0.1:8900",
            "--indexer-url",
            "http://127.0.0.1:8785",
            "--enable",
        ])
        .command
        else {
            panic!("expected set-merging command");
        };

        let expected = SetMergingOptions {
            sync: SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some("/tmp/alice.pid.json".to_string()),
                },
                rpc_url: Some("http://127.0.0.1:8900".to_string()),
                indexer_url: Some("http://127.0.0.1:8785".to_string()),
            },
            enable: true,
            disable: false,
        };
        assert_eq!(opts, expected);

        let Some(CliCommand::SetMerging(opts)) = parse_cli(&[
            "set-merging",
            "--keypair",
            "/tmp/alice.pid.json",
            "--disable",
        ])
        .command
        else {
            panic!("expected set-merging command");
        };

        let expected = SetMergingOptions {
            sync: SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some("/tmp/alice.pid.json".to_string()),
                },
                rpc_url: None,
                indexer_url: None,
            },
            enable: false,
            disable: true,
        };
        assert_eq!(opts, expected);
    }

    #[test]
    fn parses_split_options() {
        let Some(CliCommand::Split(split)) = parse_cli(&[
            "split",
            "--keypair",
            "/tmp/alice.pid.json",
            "--tree",
            "Tree111111111111111111111111111111111111111",
            "--mint",
            "SOL",
            "--parts",
            "4",
            "--input",
            "0101010101010101010101010101010101010101010101010101010101010101",
        ])
        .command
        else {
            panic!("expected split command");
        };
        let expected = SplitOptions {
            network: NetworkWalletOptions {
                sync: SyncOptions {
                    keypair: WalletKeypairOptions {
                        keypair: Some("/tmp/alice.pid.json".to_string()),
                    },
                    rpc_url: None,
                    indexer_url: None,
                },
                tree: Some("Tree111111111111111111111111111111111111111".to_string()),
                prover_url: None,
                airdrop_lamports: None,
            },
            mint: "SOL".to_string(),
            parts: 4,
            input: Some(
                "0101010101010101010101010101010101010101010101010101010101010101".to_string(),
            ),
        };
        assert_eq!(split, expected);
    }

    #[test]
    fn split_part_count_is_range_limited() {
        for parts in ["1", "9"] {
            assert!(Cli::try_parse_from([
                "zolana",
                "split",
                "--keypair",
                "/tmp/alice.pid.json",
                "--parts",
                parts,
            ])
            .is_err());
        }
    }

    #[test]
    fn parses_deposit_transfer_and_withdraw_options() {
        let Some(CliCommand::Deposit(deposit)) = parse_cli(&[
            "deposit",
            "--keypair",
            "/tmp/alice.pid.json",
            "--tree",
            "Tree111111111111111111111111111111111111111",
            "--to",
            "Recipient1111111111111111111111111111111111",
            "--amount",
            "1000000000",
            "--mint",
            "SOL",
            "--rpc-url",
            "http://127.0.0.1:8900",
            "--indexer-url",
            "http://127.0.0.1:8785",
            "--airdrop-lamports",
            "2000000000",
        ])
        .command
        else {
            panic!("expected deposit command");
        };
        let expected = DepositOptions {
            network: NetworkWalletOptions {
                sync: SyncOptions {
                    keypair: WalletKeypairOptions {
                        keypair: Some("/tmp/alice.pid.json".to_string()),
                    },
                    rpc_url: Some("http://127.0.0.1:8900".to_string()),
                    indexer_url: Some("http://127.0.0.1:8785".to_string()),
                },
                tree: Some("Tree111111111111111111111111111111111111111".to_string()),
                prover_url: None,
                airdrop_lamports: Some(2_000_000_000),
            },
            to: Some("Recipient1111111111111111111111111111111111".to_string()),
            mint: "SOL".to_string(),
            amount: 1_000_000_000,
        };
        assert_eq!(deposit, expected);

        let Some(CliCommand::Deposit(self_deposit)) = parse_cli(&[
            "deposit",
            "--keypair",
            "/tmp/alice.pid.json",
            "--tree",
            "Tree111111111111111111111111111111111111111",
            "--amount",
            "1000000000",
        ])
        .command
        else {
            panic!("expected self-deposit command");
        };
        let expected = DepositOptions {
            network: NetworkWalletOptions {
                sync: SyncOptions {
                    keypair: WalletKeypairOptions {
                        keypair: Some("/tmp/alice.pid.json".to_string()),
                    },
                    rpc_url: None,
                    indexer_url: None,
                },
                tree: Some("Tree111111111111111111111111111111111111111".to_string()),
                prover_url: None,
                airdrop_lamports: None,
            },
            to: None,
            mint: "SOL".to_string(),
            amount: 1_000_000_000,
        };
        assert_eq!(self_deposit, expected);

        let Some(CliCommand::Transfer(transfer)) = parse_cli(&[
            "transfer",
            "--keypair",
            "/tmp/bob.pid.json",
            "--tree",
            "Tree111111111111111111111111111111111111111",
            "--to",
            "Recipient1111111111111111111111111111111111",
            "--amount",
            "400000000",
            "--mint",
            "SOL",
            "--prover-url",
            "http://127.0.0.1:3002",
        ])
        .command
        else {
            panic!("expected transfer command");
        };
        let expected = TransferOptions {
            network: NetworkWalletOptions {
                sync: SyncOptions {
                    keypair: WalletKeypairOptions {
                        keypair: Some("/tmp/bob.pid.json".to_string()),
                    },
                    rpc_url: None,
                    indexer_url: None,
                },
                tree: Some("Tree111111111111111111111111111111111111111".to_string()),
                prover_url: Some("http://127.0.0.1:3002".to_string()),
                airdrop_lamports: None,
            },
            to: "Recipient1111111111111111111111111111111111".to_string(),
            mint: "SOL".to_string(),
            amount: 400_000_000,
        };
        assert_eq!(transfer, expected);

        let Some(CliCommand::Withdraw(withdraw)) = parse_cli(&[
            "withdraw",
            "--keypair",
            "/tmp/alice.pid.json",
            "--tree",
            "Tree111111111111111111111111111111111111111",
            "--to",
            "Dest1111111111111111111111111111111111111111",
            "--amount",
            "200000000",
            "--mint",
            "SOL",
        ])
        .command
        else {
            panic!("expected withdraw command");
        };
        let expected = WithdrawOptions {
            network: NetworkWalletOptions {
                sync: SyncOptions {
                    keypair: WalletKeypairOptions {
                        keypair: Some("/tmp/alice.pid.json".to_string()),
                    },
                    rpc_url: None,
                    indexer_url: None,
                },
                tree: Some("Tree111111111111111111111111111111111111111".to_string()),
                prover_url: None,
                airdrop_lamports: None,
            },
            to: "Dest1111111111111111111111111111111111111111".to_string(),
            mint: "SOL".to_string(),
            amount: 200_000_000,
        };
        assert_eq!(withdraw, expected);
    }
}
