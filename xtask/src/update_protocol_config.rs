use std::{path::PathBuf, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::{UpdateProtocolConfig, UpdateProtocolConfigData},
    pda,
    state::ProtocolConfig,
};
use zolana_smart_account_client::roles::Role;
use zolana_test_utils::smart_account::{execute_sync_ix, settings_pda, smart_account_pda};

use crate::init_protocol::{
    authorities, load_keypair, load_protocol_signers, read_program_config, to_address, Cluster,
};

pub struct Options {
    cluster: Cluster,
    rpc_url: Option<String>,
    payer: PathBuf,
    protocol_signers: Vec<PathBuf>,
    tree_creation_permissionless: Option<bool>,
    ring_activation_permissionless: Option<bool>,
    spl_interface_creation_permissionless: Option<bool>,
    fee_authority: Option<Address>,
    yes: bool,
    dry_run: bool,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut cluster = Cluster::Localnet;
        let mut rpc_url = None;
        let mut payer = None;
        let mut protocol_signers = Vec::new();
        let mut tree_creation_permissionless = None;
        let mut ring_activation_permissionless = None;
        let mut spl_interface_creation_permissionless = None;
        let mut fee_authority = None;
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
                "--protocol-signer" => {
                    protocol_signers
                        .push(PathBuf::from(args.next().unwrap_or_else(|| {
                            usage_and_exit("--protocol-signer missing value")
                        })));
                }
                "--tree-creation-permissionless" => {
                    tree_creation_permissionless =
                        Some(parse_bool(args.next(), "--tree-creation-permissionless"));
                }
                "--ring-activation-permissionless" => {
                    ring_activation_permissionless =
                        Some(parse_bool(args.next(), "--ring-activation-permissionless"));
                }
                "--spl-interface-creation-permissionless" => {
                    spl_interface_creation_permissionless = Some(parse_bool(
                        args.next(),
                        "--spl-interface-creation-permissionless",
                    ));
                }
                "--fee-authority" => {
                    fee_authority = Some(parse_address(args.next(), "--fee-authority"));
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
        let required_protocol_signers = usize::from(Role::Protocol.threshold());
        if protocol_signers.len() != required_protocol_signers {
            usage_and_exit(&format!(
                "--protocol-signer must be passed {required_protocol_signers} times for the \
                 {}-of-{} protocol policy (received {})",
                Role::Protocol.threshold(),
                authorities::PROTOCOL.len(),
                protocol_signers.len()
            ));
        }
        if tree_creation_permissionless.is_none()
            && ring_activation_permissionless.is_none()
            && spl_interface_creation_permissionless.is_none()
            && fee_authority.is_none()
        {
            usage_and_exit("at least one --*-permissionless flag or --fee-authority is required");
        }

        Self {
            cluster,
            rpc_url,
            payer,
            protocol_signers,
            tree_creation_permissionless,
            ring_activation_permissionless,
            spl_interface_creation_permissionless,
            fee_authority,
            yes,
            dry_run,
        }
    }

    fn url(&self) -> String {
        self.rpc_url
            .clone()
            .unwrap_or_else(|| self.cluster.default_url().to_string())
    }

    fn updates(&self) -> Vec<UpdateProtocolConfigData> {
        let mut updates = Vec::new();
        if let Some(value) = self.tree_creation_permissionless {
            updates.push(UpdateProtocolConfigData::TreeCreationPermissionless(value));
        }
        if let Some(value) = self.ring_activation_permissionless {
            updates.push(UpdateProtocolConfigData::RingActivationPermissionless(
                value,
            ));
        }
        if let Some(value) = self.spl_interface_creation_permissionless {
            updates.push(UpdateProtocolConfigData::SplInterfaceCreationPermissionless(value));
        }
        if let Some(value) = self.fee_authority {
            updates.push(UpdateProtocolConfigData::FeeAuthority(value));
        }
        updates
    }
}

struct OnChainConfig {
    protocol_authority: Pubkey,
    tree_creation_authority: Pubkey,
    forester_authority: Pubkey,
    ring_creation_authority: Pubkey,
    fee_authority: Pubkey,
    tree_creation_is_permissionless: u8,
    ring_activation_is_permissionless: u8,
    spl_interface_creation_is_permissionless: u8,
    lamports: u64,
    len: usize,
}

fn read_protocol_config(rpc: &SolanaRpc) -> Result<OnChainConfig> {
    let config_pda = pda::protocol_config();
    let account = rpc
        .get_account(to_address(&config_pda))
        .context("fetching protocol_config")?
        .ok_or_else(|| anyhow!("protocol config {config_pda} does not exist on this cluster"))?;
    let config = ProtocolConfig::from_account_bytes(&account.data)
        .map_err(|e| anyhow!("protocol config {config_pda} has invalid data: {e:?}"))?;
    Ok(OnChainConfig {
        protocol_authority: Pubkey::new_from_array(config.protocol_authority.to_bytes()),
        tree_creation_authority: Pubkey::new_from_array(config.tree_creation_authority.to_bytes()),
        forester_authority: Pubkey::new_from_array(config.forester_authority.to_bytes()),
        ring_creation_authority: Pubkey::new_from_array(config.ring_creation_authority.to_bytes()),
        fee_authority: Pubkey::new_from_array(config.fee_authority.to_bytes()),
        tree_creation_is_permissionless: config.tree_creation_is_permissionless,
        ring_activation_is_permissionless: config.ring_activation_is_permissionless,
        spl_interface_creation_is_permissionless: config.spl_interface_creation_is_permissionless,
        lamports: account.lamports,
        len: account.data.len(),
    })
}

fn print_config(label: &str, config: &OnChainConfig) {
    println!("{label}:");
    println!("  size={} lamports={}", config.len, config.lamports);
    println!("  protocol_authority={}", config.protocol_authority);
    println!(
        "  tree_creation_authority={}",
        config.tree_creation_authority
    );
    println!("  forester_authority={}", config.forester_authority);
    println!(
        "  ring_creation_authority={}",
        config.ring_creation_authority
    );
    println!("  fee_authority={}", config.fee_authority);
    println!(
        "  tree_creation_is_permissionless={}",
        config.tree_creation_is_permissionless != 0
    );
    println!(
        "  ring_activation_is_permissionless={}",
        config.ring_activation_is_permissionless != 0
    );
    println!(
        "  spl_interface_creation_is_permissionless={}",
        config.spl_interface_creation_is_permissionless != 0
    );
}

/// Each authority is a Squads vault PDA; recover its settings account by
/// scanning every seed the smart-account program has handed out so far.
pub fn find_vault_settings(rpc: &SolanaRpc, vault_authority: &Pubkey) -> Result<Pubkey> {
    let program_config = read_program_config(rpc)?;
    for seed in 1..=program_config.smart_account_index {
        let (settings, _) = settings_pda(seed);
        let (vault, _) = smart_account_pda(&settings, 0);
        if vault == *vault_authority {
            return Ok(settings);
        }
    }
    bail!(
        "no smart-account settings found whose vault matches authority {vault_authority} \
         (scanned seeds 1..={})",
        program_config.smart_account_index
    )
}

pub fn run(options: Options) -> Result<()> {
    let payer = load_keypair(&options.payer, "payer")?;
    let protocol_signers = load_protocol_signers(&options.protocol_signers)?;
    if options.cluster == Cluster::Mainnet && !options.dry_run && !options.yes {
        bail!("refusing to send mainnet transactions without --yes");
    }

    let url = options.url();
    let rpc = SolanaRpc::new(url.clone());

    let config = read_protocol_config(&rpc)?;
    println!("cluster={}", options.cluster.name());
    println!("rpc_url={url}");
    println!("dry_run={}", options.dry_run);
    println!("payer={}", payer.pubkey());
    for (index, signer) in protocol_signers.iter().enumerate() {
        println!("protocol_signer_{}={}", index + 1, signer.pubkey());
    }
    println!("protocol_config={}", pda::protocol_config());
    print_config("current config", &config);

    let settings = find_vault_settings(&rpc, &config.protocol_authority)?;
    println!("protocol_settings={settings}");

    let mut instructions = Vec::new();

    let updates = options.updates();
    for update in &updates {
        println!("update: {update:?}");
    }
    let inner: Vec<_> = updates
        .into_iter()
        .map(|update| {
            UpdateProtocolConfig {
                authority: config.protocol_authority,
                update,
            }
            .instruction()
        })
        .collect();
    let signer_keys: Vec<Pubkey> = protocol_signers.iter().map(Signer::pubkey).collect();
    instructions.push(execute_sync_ix(&settings, 0, &signer_keys, &inner));

    if options.dry_run {
        println!("dry_run: no transactions sent");
        return Ok(());
    }

    let mut transaction_signers: Vec<&dyn Signer> = vec![&payer];
    transaction_signers.extend(protocol_signers.iter().map(|signer| signer as &dyn Signer));
    let signature = rpc
        .create_and_send_transaction(
            &instructions,
            to_address(&payer.pubkey()),
            &transaction_signers,
        )
        .map_err(|e| anyhow!("update_protocol_config failed: {e}"))?;
    println!("update_protocol_config sig={signature}");

    let config = read_protocol_config(&rpc)?;
    print_config("updated config", &config);
    Ok(())
}

fn parse_bool(value: Option<String>, flag: &str) -> bool {
    match value.as_deref() {
        Some("true") => true,
        Some("false") => false,
        _ => usage_and_exit(&format!("{flag} expects true|false")),
    }
}

fn parse_address(value: Option<String>, flag: &str) -> Address {
    value
        .as_deref()
        .and_then(|value| Pubkey::from_str(value).ok())
        .map(|key| to_address(&key))
        .unwrap_or_else(|| usage_and_exit(&format!("{flag} expects a base58 pubkey")))
}

fn usage_and_exit(message: &str) -> ! {
    eprintln!("error: {message}");
    print_help();
    std::process::exit(2);
}

fn print_help() {
    println!("xtask update-protocol-config [flags]");
    println!();
    println!("Update shielded-pool protocol config flags on a cluster. The update is");
    println!("wrapped in a Squads execute_sync signed by two protocol authority members.");
    println!();
    println!("Flags:");
    println!("  --cluster <localnet|devnet|mainnet>              default: localnet");
    println!(
        "  --rpc-url <URL>                                  override the cluster default RPC URL"
    );
    println!("  --payer <KEYPAIR_PATH>                           outer fee payer (required)");
    println!(
        "  --protocol-signer <KEYPAIR_PATH>                 protocol signer; pass exactly twice"
    );
    println!(
        "  --tree-creation-permissionless <true|false>      set tree_creation_is_permissionless"
    );
    println!(
        "  --ring-activation-permissionless <true|false>      set ring_activation_is_permissionless"
    );
    println!("  --spl-interface-creation-permissionless <true|false>");
    println!("                                                   set spl_interface_creation_is_permissionless");
    println!("  --fee-authority <PUBKEY>                         set fee_authority");
    println!("  --yes                                            confirm mainnet sends");
    println!(
        "  --dry-run                                        print current state, send nothing"
    );
    println!("  -h | --help                                      print this help");
}
