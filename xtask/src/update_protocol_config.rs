use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use rings_client::{Rpc, SolanaRpc};
use rings_interface::{
    instruction::{UpdateProtocolConfig, UpdateProtocolConfigData},
    pda,
    state::ProtocolConfig,
};
use rings_test_utils::smart_account::{execute_sync_ix, settings_pda, smart_account_pda};
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::init_protocol::{authorities, load_keypair, read_program_config, to_address, Cluster};

pub struct Options {
    cluster: Cluster,
    rpc_url: Option<String>,
    payer: PathBuf,
    protocol_signer: PathBuf,
    tree_creation_permissionless: Option<bool>,
    zone_creation_permissionless: Option<bool>,
    spl_interface_creation_permissionless: Option<bool>,
    yes: bool,
    dry_run: bool,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut cluster = Cluster::Localnet;
        let mut rpc_url = None;
        let mut payer = None;
        let mut protocol_signer = None;
        let mut tree_creation_permissionless = None;
        let mut zone_creation_permissionless = None;
        let mut spl_interface_creation_permissionless = None;
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
                    protocol_signer =
                        Some(PathBuf::from(args.next().unwrap_or_else(|| {
                            usage_and_exit("--protocol-signer missing value")
                        })));
                }
                "--tree-creation-permissionless" => {
                    tree_creation_permissionless =
                        Some(parse_bool(args.next(), "--tree-creation-permissionless"));
                }
                "--zone-creation-permissionless" => {
                    zone_creation_permissionless =
                        Some(parse_bool(args.next(), "--zone-creation-permissionless"));
                }
                "--spl-interface-creation-permissionless" => {
                    spl_interface_creation_permissionless = Some(parse_bool(
                        args.next(),
                        "--spl-interface-creation-permissionless",
                    ));
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
        let protocol_signer =
            protocol_signer.unwrap_or_else(|| usage_and_exit("--protocol-signer is required"));
        if tree_creation_permissionless.is_none()
            && zone_creation_permissionless.is_none()
            && spl_interface_creation_permissionless.is_none()
        {
            usage_and_exit("at least one --*-permissionless flag is required");
        }

        Self {
            cluster,
            rpc_url,
            payer,
            protocol_signer,
            tree_creation_permissionless,
            zone_creation_permissionless,
            spl_interface_creation_permissionless,
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
        if let Some(value) = self.zone_creation_permissionless {
            updates.push(UpdateProtocolConfigData::ZoneCreationPermissionless(value));
        }
        if let Some(value) = self.spl_interface_creation_permissionless {
            updates.push(UpdateProtocolConfigData::SplInterfaceCreationPermissionless(value));
        }
        updates
    }
}

struct OnChainConfig {
    protocol_authority: Pubkey,
    tree_creation_is_permissionless: u8,
    zone_creation_is_permissionless: u8,
    spl_interface_creation_is_permissionless: u8,
    lamports: u64,
    len: usize,
}

fn field<const N: usize>(data: &[u8], offset: usize, name: &str) -> Result<[u8; N]> {
    data.get(offset..offset + N)
        .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
        .ok_or_else(|| anyhow!("protocol config too small for {name}"))
}

fn read_protocol_config(rpc: &SolanaRpc) -> Result<OnChainConfig> {
    let config_pda = pda::protocol_config();
    let account = rpc
        .get_account(to_address(&config_pda))
        .context("fetching protocol_config")?
        .ok_or_else(|| anyhow!("protocol config {config_pda} does not exist on this cluster"))?;
    let data = &account.data;
    if data.len() != ProtocolConfig::SIZE {
        bail!(
            "protocol config has unexpected size {} (expected {})",
            data.len(),
            ProtocolConfig::SIZE
        );
    }
    Ok(OnChainConfig {
        protocol_authority: Pubkey::new_from_array(field::<32>(data, 1, "protocol_authority")?),
        tree_creation_is_permissionless: field::<1>(data, 129, "tree flag")?[0],
        zone_creation_is_permissionless: field::<1>(data, 130, "zone flag")?[0],
        spl_interface_creation_is_permissionless: field::<1>(data, 131, "spl interface flag")?[0],
        lamports: account.lamports,
        len: data.len(),
    })
}

fn print_config(label: &str, config: &OnChainConfig) {
    println!("{label}:");
    println!("  size={} lamports={}", config.len, config.lamports);
    println!("  protocol_authority={}", config.protocol_authority);
    println!(
        "  tree_creation_is_permissionless={}",
        config.tree_creation_is_permissionless != 0
    );
    println!(
        "  zone_creation_is_permissionless={}",
        config.zone_creation_is_permissionless != 0
    );
    println!(
        "  spl_interface_creation_is_permissionless={}",
        config.spl_interface_creation_is_permissionless != 0
    );
}

/// The protocol authority is a Squads vault PDA; recover its settings account
/// by scanning every seed the smart-account program has handed out so far.
fn find_protocol_settings(rpc: &SolanaRpc, protocol_authority: &Pubkey) -> Result<Pubkey> {
    let program_config = read_program_config(rpc)?;
    for seed in 1..=program_config.smart_account_index {
        let (settings, _) = settings_pda(seed);
        let (vault, _) = smart_account_pda(&settings, 0);
        if vault == *protocol_authority {
            return Ok(settings);
        }
    }
    bail!(
        "no smart-account settings found whose vault matches protocol authority {protocol_authority} \
         (scanned seeds 1..={})",
        program_config.smart_account_index
    )
}

pub fn run(options: Options) -> Result<()> {
    let payer = load_keypair(&options.payer, "payer")?;
    let protocol_signer = load_keypair(&options.protocol_signer, "protocol-signer")?;
    if !options.dry_run && !authorities::PROTOCOL.contains(&protocol_signer.pubkey()) {
        bail!(
            "protocol-signer {} is not one of the hardcoded protocol authorities",
            protocol_signer.pubkey()
        );
    }
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
    println!("protocol_signer={}", protocol_signer.pubkey());
    println!("protocol_config={}", pda::protocol_config());
    print_config("current config", &config);

    let settings = find_protocol_settings(&rpc, &config.protocol_authority)?;
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
    instructions.push(execute_sync_ix(
        &settings,
        0,
        &[protocol_signer.pubkey()],
        &inner,
    ));

    if options.dry_run {
        println!("dry_run: no transactions sent");
        return Ok(());
    }

    let signature = rpc
        .create_and_send_transaction(
            &instructions,
            to_address(&payer.pubkey()),
            &[&payer, &protocol_signer],
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

fn usage_and_exit(message: &str) -> ! {
    eprintln!("error: {message}");
    print_help();
    std::process::exit(2);
}

fn print_help() {
    println!("xtask update-protocol-config [flags]");
    println!();
    println!("Update shielded-pool protocol config flags on a cluster. The update is");
    println!("wrapped in a Squads execute_sync signed by one protocol authority member.");
    println!();
    println!("Flags:");
    println!("  --cluster <localnet|devnet|mainnet>              default: localnet");
    println!(
        "  --rpc-url <URL>                                  override the cluster default RPC URL"
    );
    println!("  --payer <KEYPAIR_PATH>                           outer fee payer (required)");
    println!("  --protocol-signer <KEYPAIR_PATH>                 one of the protocol authorities (required)");
    println!(
        "  --tree-creation-permissionless <true|false>      set tree_creation_is_permissionless"
    );
    println!(
        "  --zone-creation-permissionless <true|false>      set zone_creation_is_permissionless"
    );
    println!("  --spl-interface-creation-permissionless <true|false>");
    println!("                                                   set spl_interface_creation_is_permissionless");
    println!("  --yes                                            confirm mainnet sends");
    println!(
        "  --dry-run                                        print current state, send nothing"
    );
    println!("  -h | --help                                      print this help");
}
