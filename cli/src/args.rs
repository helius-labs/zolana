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
    #[command(
        name = "test-validator",
        about = "Start the local Zolana test validator"
    )]
    TestValidator(Box<TestValidatorOptions>),

    #[command(name = "start-prover", about = "Start the local prover server")]
    StartProver(StartProverOptions),

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
}

#[derive(Debug, Subcommand, Clone)]
pub(crate) enum ConfigCommand {
    #[command(name = "get", about = "Show the CLI configuration file")]
    Get,

    #[command(name = "set", about = "Update the CLI configuration file")]
    Set(ConfigSetOptions),

    #[command(name = "asset-registry", about = "Show locally configured assets")]
    AssetRegistry,

    #[command(name = "add-asset", about = "Add or update a local SPL asset mapping")]
    AddAsset(ConfigAddAssetOptions),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ConfigSetOptions {
    #[arg(
        long = "wallet",
        help = "Default named wallet (~/.config/zolana/wallets/<NAME>.json)",
        value_name = "NAME"
    )]
    pub(crate) wallet: Option<String>,

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

#[derive(Args, Debug, Clone)]
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
        about = "Create a named wallet (~/.config/zolana/wallets/<NAME>.json), optionally fund and register it"
    )]
    New(NewWalletOptions),

    #[command(name = "address", about = "Print the selected wallet's owner pubkey")]
    Address(WalletKeypairOptions),

    #[command(
        name = "list",
        about = "List named wallets in ~/.config/zolana/wallets"
    )]
    List,

    #[command(
        name = "init",
        about = "Create a filesystem private keypair and register it on-chain"
    )]
    Init(InitOptions),

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

    #[command(
        name = "sync",
        about = "Sync private wallet state. Transfers run sync automatically."
    )]
    Sync(SyncOptions),

    #[command(name = "balance", about = "Show private wallet balances")]
    Balance(BalanceOptions),

    #[command(name = "merge", about = "Enable or disable merging for this wallet")]
    Merge(MergeOptions),

    #[command(
        name = "consolidate",
        about = "Merge several small shielded notes of a mint into one (distinct from `merge`, which toggles the merging flag)"
    )]
    Consolidate(ConsolidateOptions),

    #[command(name = "deposit", about = "Deposit into private wallet")]
    Deposit(DepositOptions),

    #[command(name = "transfer", about = "Send a private transfer")]
    Transfer(TransferOptions),

    #[command(name = "withdraw", about = "Withdraw to public address")]
    Withdraw(WithdrawOptions),

    #[command(
        name = "split",
        about = "Split one shielded note into N equal self-owned notes"
    )]
    Split(SplitOptions),

    #[command(
        name = "utxos",
        about = "List the selected wallet's spendable SOL notes (hash + amount)"
    )]
    Utxos(UtxosOptions),
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

#[derive(Args, Debug, Clone)]
pub(crate) struct WalletKeypairOptions {
    #[arg(
        short = 'w',
        long = "wallet",
        help = "Named wallet to use (~/.config/zolana/wallets/<NAME>.json); defaults to the configured wallet",
        value_name = "NAME"
    )]
    pub(crate) wallet: Option<String>,

    #[arg(
        long = "keypair",
        help = "Path to private keypair file (overrides --wallet; default: ~/.config/zolana/pid.json)",
        value_name = "PATH"
    )]
    pub(crate) keypair: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct NewWalletOptions {
    #[arg(help = "Wallet name (stored at ~/.config/zolana/wallets/<NAME>.json)")]
    pub(crate) name: String,

    #[arg(
        long = "funding-keypair",
        help = "Use an existing Solana keypair file (e.g. ~/.config/solana/id.json) as the wallet's funding/fee-payer key instead of generating a new one",
        value_name = "PATH"
    )]
    pub(crate) funding_keypair: Option<String>,

    #[arg(
        long = "fund-from",
        help = "Solana keypair file to transfer SOL from into the new wallet's funding key (use with --fund-sol)",
        value_name = "PATH"
    )]
    pub(crate) fund_from: Option<String>,

    #[arg(
        long = "fund-sol",
        help = "Amount of SOL to transfer from --fund-from into the new wallet's funding key",
        value_name = "SOL"
    )]
    pub(crate) fund_sol: Option<String>,

    #[arg(
        long = "register",
        help = "Register the new wallet on-chain via the user registry after creating (and optionally funding) it"
    )]
    pub(crate) register: bool,

    #[arg(
        long = "rpc-url",
        help = "Solana RPC URL used for --fund-from and --register (default: configured value or http://127.0.0.1:8899)"
    )]
    pub(crate) rpc_url: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct InitOptions {
    #[arg(
        long = "path",
        help = "Output path for generated keypair (default: ~/.config/zolana/pid.json)",
        value_name = "PATH"
    )]
    pub(crate) path: Option<String>,

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

    #[arg(
        long = "funding-keypair",
        help = "Use an existing Solana keypair file (e.g. ~/.config/solana/id.json) as the wallet's funding/fee-payer key instead of generating a new one",
        value_name = "PATH"
    )]
    pub(crate) funding_keypair: Option<String>,

    #[arg(
        long = "skip-register",
        help = "Skip on-chain user-registry registration (use on networks without the user-registry program; a self-deposit does not need it)"
    )]
    pub(crate) skip_register: bool,
}

#[derive(Args, Debug, Clone)]
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

#[derive(Args, Debug, Clone)]
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

#[derive(Args, Debug, Clone)]
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

#[derive(Args, Debug, Clone)]
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

#[derive(Args, Debug, Clone)]
pub(crate) struct DepositOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(
        help = "Amount to deposit (SOL as a decimal for the SOL mint, raw base units for SPL mints)",
        value_name = "AMOUNT"
    )]
    pub(crate) amount: String,

    #[arg(
        long = "to",
        help = "Optional registered recipient (a local wallet name or Solana pubkey; defaults to this wallet's owner)"
    )]
    pub(crate) to: Option<String>,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct TransferOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(
        help = "Amount to transfer (SOL as a decimal for the SOL mint, raw base units for SPL mints)",
        value_name = "AMOUNT"
    )]
    pub(crate) amount: String,

    #[arg(
        help = "Recipient (a local wallet name or Solana pubkey); registered recipients receive a shielded transfer, unregistered recipients receive a public SOL withdrawal",
        value_name = "TO"
    )]
    pub(crate) to: String,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,

    #[arg(
        long = "input",
        help = "Spend this exact note (its utxo hash, hex from `wallet utxos`), skipping automatic reservation-based selection",
        value_name = "UTXO_HASH"
    )]
    pub(crate) input: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SplitOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(
        help = "Number of equal self-owned notes to split into (2..=8)",
        value_name = "PARTS"
    )]
    pub(crate) parts: u8,

    #[arg(
        long = "part-sol",
        help = "SOL per output note; omit to split the wallet's largest SOL note evenly into <PARTS>",
        value_name = "SOL"
    )]
    pub(crate) part_sol: Option<String>,

    #[arg(
        long = "input",
        help = "Split this exact note (its utxo hash, hex from `wallet utxos`) instead of the largest",
        value_name = "UTXO_HASH"
    )]
    pub(crate) input: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct UtxosOptions {
    #[command(flatten)]
    pub(crate) sync: SyncOptions,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct WithdrawOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(
        help = "Amount to withdraw (SOL as a decimal for the SOL mint, raw base units for SPL mints)",
        value_name = "AMOUNT"
    )]
    pub(crate) amount: String,

    #[arg(
        help = "Destination (a local wallet name or public Solana address)",
        value_name = "TO"
    )]
    pub(crate) to: String,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ConsolidateOptions {
    #[command(flatten)]
    pub(crate) network: NetworkWalletOptions,

    #[arg(long, default_value = "SOL", help = "Mint address or SOL")]
    pub(crate) mint: String,

    #[arg(
        long = "input",
        help = "Consolidate these exact notes (their utxo hashes, hex from `wallet utxos`); repeat the flag per note (2..=8). Omit to auto-select the smallest unspent notes.",
        value_name = "UTXO_HASH"
    )]
    pub(crate) input: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct BalanceOptions {
    #[command(flatten)]
    pub(crate) sync: SyncOptions,

    #[arg(long, help = "Optional mint filter (address or SOL)")]
    pub(crate) mint: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(group(
    clap::ArgGroup::new("merge_toggle")
        .required(true)
        .args(["enable", "disable"])
))]
pub(crate) struct MergeOptions {
    #[command(flatten)]
    pub(crate) sync: SyncOptions,

    #[arg(
        long,
        action = ArgAction::SetTrue,
        help = "Enable merging for this wallet"
    )]
    pub(crate) enable: bool,

    #[arg(
        long,
        action = ArgAction::SetTrue,
        help = "Disable merging for this wallet"
    )]
    pub(crate) disable: bool,
}

impl TestValidatorOptions {
    pub(crate) fn use_surfpool_backend(&self) -> bool {
        self.use_surfpool || !self.no_use_surfpool
    }

    pub(crate) fn sbf_program_specs(&self) -> Vec<ProgramSpec> {
        self.sbf_programs
            .chunks_exact(2)
            .map(|chunk| ProgramSpec {
                address: chunk[0].clone(),
                path: chunk[1].clone(),
            })
            .collect()
    }

    pub(crate) fn upgradeable_program_specs(&self) -> Vec<UpgradeableProgramSpec> {
        self.upgradeable_programs
            .chunks_exact(3)
            .map(|chunk| UpgradeableProgramSpec {
                address: chunk[0].clone(),
                path: chunk[1].clone(),
                upgrade_authority: chunk[2].clone(),
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
        &std::iter::once("test-validator")
            .chain(values.iter().copied())
            .collect::<Vec<_>>(),
    )
    .command
    .expect("command")
    {
        CliCommand::TestValidator(opts) => *opts,
        _ => panic!("expected test-validator command"),
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
    fn test_validator_help_documents_localnet_flags() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("test-validator")
            .expect("test-validator subcommand")
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
            ["zolana", "test-validator", "--help"].as_slice(),
            ["zolana", "start-prover", "--help"].as_slice(),
            ["zolana", "config", "asset-registry", "--help"].as_slice(),
            ["zolana", "config", "add-asset", "--help"].as_slice(),
            ["zolana", "wallet", "--help"].as_slice(),
            ["zolana", "wallet", "new", "--help"].as_slice(),
            ["zolana", "wallet", "address", "--help"].as_slice(),
            ["zolana", "wallet", "list", "--help"].as_slice(),
            ["zolana", "wallet", "init", "--help"].as_slice(),
            ["zolana", "wallet", "create-tree", "--help"].as_slice(),
            ["zolana", "wallet", "test-mint", "--help"].as_slice(),
            ["zolana", "wallet", "sync", "--help"].as_slice(),
            ["zolana", "wallet", "balance", "--help"].as_slice(),
            ["zolana", "wallet", "deposit", "--help"].as_slice(),
            ["zolana", "wallet", "consolidate", "--help"].as_slice(),
            ["zolana", "wallet", "transfer", "--help"].as_slice(),
            ["zolana", "wallet", "withdraw", "--help"].as_slice(),
            ["zolana", "wallet", "split", "--help"].as_slice(),
            ["zolana", "wallet", "utxos", "--help"].as_slice(),
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
        assert_eq!(
            programs[0].address,
            "Pool111111111111111111111111111111111111111"
        );
        assert_eq!(programs[0].path, "target/deploy/pool.so");
        assert_eq!(
            programs[1].address,
            "Zone111111111111111111111111111111111111111"
        );
        assert_eq!(programs[1].path, "target/deploy/zone.so");
    }

    #[test]
    fn parses_start_prover_options() {
        let command = parse_cli(&[
            "start-prover",
            "--port",
            "3002",
            "--redis-url",
            "redis://localhost:6379/15",
        ])
        .command
        .expect("command");
        let CliCommand::StartProver(opts) = command else {
            panic!("expected start-prover command");
        };

        assert_eq!(opts.prover_port, 3002);
        assert_eq!(opts.redis_url.as_deref(), Some("redis://localhost:6379/15"));
    }

    #[test]
    fn parses_start_prover_auto_download_option() {
        let command = parse_cli(&["start-prover", "--auto-download", "off"])
            .command
            .expect("command");
        let CliCommand::StartProver(opts) = command else {
            panic!("expected start-prover command");
        };

        assert!(!opts.auto_download);
    }

    #[test]
    fn parses_test_validator_prover_auto_download_option() {
        let opts = parse_validator(&["--prover-auto-download", "off"]);

        assert!(!opts.prover_auto_download);
    }

    #[test]
    fn parses_wallet_init_options() {
        let WalletCommand::Init(opts) = parse_wallet(&[
            "init",
            "--path",
            "/tmp/alice.pid.json",
            "--rpc-url",
            "http://127.0.0.1:8900",
            "--airdrop-lamports",
            "1000000000",
        ]) else {
            panic!("expected wallet init command");
        };
        assert_eq!(opts.path.as_deref(), Some("/tmp/alice.pid.json"));
        assert_eq!(opts.rpc_url.as_deref(), Some("http://127.0.0.1:8900"));
        assert_eq!(opts.airdrop_lamports, Some(1_000_000_000));
    }

    #[test]
    fn parses_wallet_create_tree_options() {
        let WalletCommand::CreateTree(opts) = parse_wallet(&[
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
            panic!("expected wallet create-tree command");
        };
        assert_eq!(
            opts.sync.keypair.keypair.as_deref(),
            Some("/tmp/alice.pid.json")
        );
        assert_eq!(opts.tree_keypair, "/tmp/tree.json");
        assert_eq!(opts.sync.rpc_url.as_deref(), Some("http://127.0.0.1:8900"));
        assert_eq!(
            opts.sync.indexer_url.as_deref(),
            Some("http://127.0.0.1:8785")
        );
        assert_eq!(opts.airdrop_lamports, 1_000_000_000);
    }

    #[test]
    fn parses_config_asset_commands() {
        let Some(CliCommand::Config { command }) = parse_cli(&[
            "config",
            "add-asset",
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
        let ConfigCommand::AddAsset(opts) = command else {
            panic!("expected add-asset command");
        };
        assert_eq!(opts.asset_id, 2);
        assert_eq!(opts.mint, "Mint111111111111111111111111111111111111111");
        assert_eq!(
            opts.token_account.as_deref(),
            Some("Token11111111111111111111111111111111111111")
        );
    }

    #[test]
    fn parses_wallet_test_mint_options() {
        let WalletCommand::TestMint(opts) = parse_wallet(&[
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
            panic!("expected wallet test-mint command");
        };
        assert_eq!(
            opts.sync.keypair.keypair.as_deref(),
            Some("/tmp/alice.pid.json")
        );
        assert_eq!(opts.amount, 1_000_000);
        assert_eq!(opts.authority_path.as_deref(), Some("/tmp/admin.pid.json"));
        assert_eq!(opts.airdrop_lamports, Some(1_000_000_000));
    }

    #[test]
    fn parses_wallet_sync_and_balance_options() {
        let WalletCommand::Sync(sync) = parse_wallet(&[
            "sync",
            "--keypair",
            "/tmp/alice.pid.json",
            "--rpc-url",
            "http://127.0.0.1:8900",
            "--indexer-url",
            "http://127.0.0.1:8785",
        ]) else {
            panic!("expected wallet sync command");
        };
        assert_eq!(sync.keypair.keypair.as_deref(), Some("/tmp/alice.pid.json"));
        assert_eq!(sync.rpc_url.as_deref(), Some("http://127.0.0.1:8900"));
        assert_eq!(sync.indexer_url.as_deref(), Some("http://127.0.0.1:8785"));

        let WalletCommand::Balance(balance) = parse_wallet(&[
            "balance",
            "--keypair",
            "/tmp/alice.pid.json",
            "--mint",
            "SOL",
        ]) else {
            panic!("expected wallet balance command");
        };
        assert_eq!(balance.mint.as_deref(), Some("SOL"));
    }

    #[test]
    fn parses_wallet_merge_options() {
        let WalletCommand::Merge(opts) = parse_wallet(&[
            "merge",
            "--keypair",
            "/tmp/alice.pid.json",
            "--rpc-url",
            "http://127.0.0.1:8900",
            "--indexer-url",
            "http://127.0.0.1:8785",
            "--enable",
        ]) else {
            panic!("expected wallet merge command");
        };

        assert_eq!(
            opts.sync.keypair.keypair.as_deref(),
            Some("/tmp/alice.pid.json")
        );
        assert_eq!(opts.sync.rpc_url.as_deref(), Some("http://127.0.0.1:8900"));
        assert_eq!(
            opts.sync.indexer_url.as_deref(),
            Some("http://127.0.0.1:8785")
        );
        assert!(opts.enable);
        assert!(!opts.disable);

        let WalletCommand::Merge(opts) =
            parse_wallet(&["merge", "--keypair", "/tmp/alice.pid.json", "--disable"])
        else {
            panic!("expected wallet merge command");
        };

        assert!(!opts.enable);
        assert!(opts.disable);
    }

    #[test]
    fn parses_wallet_consolidate_options() {
        // Default (auto) consolidation: no --input, SOL mint by default.
        let WalletCommand::Consolidate(auto) = parse_wallet(&[
            "consolidate",
            "-w",
            "alice",
            "--tree",
            "Tree111111111111111111111111111111111111111",
        ]) else {
            panic!("expected wallet consolidate command");
        };
        assert_eq!(auto.mint, "SOL");
        assert!(auto.input.is_empty());
        assert_eq!(auto.network.sync.keypair.wallet.as_deref(), Some("alice"));

        // Explicit notes: repeat --input per note.
        let WalletCommand::Consolidate(explicit) = parse_wallet(&[
            "consolidate",
            "--keypair",
            "/tmp/alice.pid.json",
            "--mint",
            "SOL",
            "--input",
            "aa",
            "--input",
            "bb",
        ]) else {
            panic!("expected wallet consolidate command");
        };
        assert_eq!(explicit.input, vec!["aa".to_string(), "bb".to_string()]);
    }

    #[test]
    fn parses_wallet_deposit_transfer_and_withdraw_options() {
        // Amount is positional (first); `--to`/`--mint` remain flags on deposit.
        let WalletCommand::Deposit(deposit) = parse_wallet(&[
            "deposit",
            "0.5",
            "--keypair",
            "/tmp/alice.pid.json",
            "--tree",
            "Tree111111111111111111111111111111111111111",
            "--to",
            "Recipient1111111111111111111111111111111111",
            "--mint",
            "SOL",
            "--rpc-url",
            "http://127.0.0.1:8900",
            "--indexer-url",
            "http://127.0.0.1:8785",
            "--airdrop-lamports",
            "2000000000",
        ]) else {
            panic!("expected wallet deposit command");
        };
        assert_eq!(
            deposit.network.tree.as_deref(),
            Some("Tree111111111111111111111111111111111111111")
        );
        assert_eq!(
            deposit.to.as_deref(),
            Some("Recipient1111111111111111111111111111111111")
        );
        assert_eq!(deposit.amount, "0.5");
        assert_eq!(deposit.network.airdrop_lamports, Some(2_000_000_000));

        let WalletCommand::Deposit(self_deposit) = parse_wallet(&[
            "deposit",
            "1",
            "--keypair",
            "/tmp/alice.pid.json",
            "--tree",
            "Tree111111111111111111111111111111111111111",
        ]) else {
            panic!("expected wallet self-deposit command");
        };
        assert_eq!(self_deposit.to, None);
        assert_eq!(self_deposit.amount, "1");

        // `-w` selects a named wallet, amount and recipient are positional.
        let WalletCommand::Transfer(transfer) = parse_wallet(&[
            "transfer",
            "0.4",
            "Recipient1111111111111111111111111111111111",
            "-w",
            "bob",
            "--tree",
            "Tree111111111111111111111111111111111111111",
            "--mint",
            "SOL",
            "--prover-url",
            "http://127.0.0.1:3002",
        ]) else {
            panic!("expected wallet transfer command");
        };
        assert_eq!(transfer.to, "Recipient1111111111111111111111111111111111");
        assert_eq!(transfer.amount, "0.4");
        assert_eq!(transfer.network.sync.keypair.wallet.as_deref(), Some("bob"));
        assert_eq!(
            transfer.network.prover_url.as_deref(),
            Some("http://127.0.0.1:3002")
        );

        let WalletCommand::Withdraw(withdraw) = parse_wallet(&[
            "withdraw",
            "0.2",
            "Dest1111111111111111111111111111111111111111",
            "--keypair",
            "/tmp/alice.pid.json",
            "--tree",
            "Tree111111111111111111111111111111111111111",
            "--mint",
            "SOL",
        ]) else {
            panic!("expected wallet withdraw command");
        };
        assert_eq!(withdraw.to, "Dest1111111111111111111111111111111111111111");
        assert_eq!(withdraw.amount, "0.2");
    }

    #[test]
    fn parses_wallet_split_and_utxos_options() {
        // `parts` is positional; `--part-sol` and `--input` are optional flags.
        let WalletCommand::Split(split) = parse_wallet(&[
            "split",
            "4",
            "-w",
            "alice",
            "--part-sol",
            "0.25",
            "--tree",
            "Tree111111111111111111111111111111111111111",
        ]) else {
            panic!("expected wallet split command");
        };
        assert_eq!(split.parts, 4);
        assert_eq!(split.part_sol.as_deref(), Some("0.25"));
        assert_eq!(split.input, None);
        assert_eq!(split.network.sync.keypair.wallet.as_deref(), Some("alice"));

        // Default split: only <parts>, splitting the largest note evenly.
        let WalletCommand::Split(split) =
            parse_wallet(&["split", "8", "--keypair", "/tmp/alice.pid.json"])
        else {
            panic!("expected wallet split command");
        };
        assert_eq!(split.parts, 8);
        assert_eq!(split.part_sol, None);

        // Split an explicit note by hash.
        let WalletCommand::Split(split) = parse_wallet(&[
            "split",
            "3",
            "--input",
            "aa",
            "--keypair",
            "/tmp/alice.pid.json",
        ]) else {
            panic!("expected wallet split command");
        };
        assert_eq!(split.input.as_deref(), Some("aa"));

        let WalletCommand::Utxos(utxos) = parse_wallet(&["utxos", "-w", "bob"]) else {
            panic!("expected wallet utxos command");
        };
        assert_eq!(utxos.sync.keypair.wallet.as_deref(), Some("bob"));
    }

    #[test]
    fn parses_wallet_transfer_input_override() {
        let WalletCommand::Transfer(transfer) = parse_wallet(&[
            "transfer",
            "0.4",
            "Recipient1111111111111111111111111111111111",
            "--input",
            "deadbeef",
            "--keypair",
            "/tmp/alice.pid.json",
        ]) else {
            panic!("expected wallet transfer command");
        };
        assert_eq!(transfer.input.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn parses_wallet_new_options() {
        let WalletCommand::New(opts) = parse_wallet(&[
            "new",
            "alice",
            "--funding-keypair",
            "/tmp/id.json",
            "--fund-from",
            "/tmp/payer.json",
            "--fund-sol",
            "1.5",
            "--register",
            "--rpc-url",
            "http://127.0.0.1:8900",
        ]) else {
            panic!("expected wallet new command");
        };
        assert_eq!(opts.name, "alice");
        assert_eq!(opts.funding_keypair.as_deref(), Some("/tmp/id.json"));
        assert_eq!(opts.fund_from.as_deref(), Some("/tmp/payer.json"));
        assert_eq!(opts.fund_sol.as_deref(), Some("1.5"));
        assert!(opts.register);
        assert_eq!(opts.rpc_url.as_deref(), Some("http://127.0.0.1:8900"));
    }

    #[test]
    fn wallet_tree_defaults_when_flag_omitted() {
        let WalletCommand::Deposit(deposit) =
            parse_wallet(&["deposit", "1", "--keypair", "/tmp/alice.pid.json"])
        else {
            panic!("expected wallet deposit command");
        };
        // `--tree` omitted parses to None; the default tree is applied later by
        // `resolve_tree` (see cli_config), not at parse time.
        assert!(deposit.network.tree.is_none());
    }
}
