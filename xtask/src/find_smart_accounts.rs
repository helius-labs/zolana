use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use solana_pubkey::Pubkey;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::state::ProtocolConfig;
use zolana_smart_account_client::{
    roles::Role,
    settings::{settings_member_keys, settings_threshold},
};
use zolana_test_utils::smart_account::SMART_ACCOUNT_PROGRAM_ID;

use crate::init_protocol::{expected_role_members, read_program_config, to_address, Cluster};

const SCAN_PROGRESS_STEP: u128 = 100_000;

pub struct Options {
    cluster: Cluster,
    rpc_url: Option<String>,
    vault: Option<Pubkey>,
    protocol_config: Option<Pubkey>,
    max_index: Option<u128>,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut cluster = Cluster::Localnet;
        let mut rpc_url = None;
        let mut vault = None;
        let mut protocol_config = None;
        let mut max_index = None;

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
                "--vault" => {
                    let value = args
                        .next()
                        .unwrap_or_else(|| usage_and_exit("--vault missing value"));
                    vault =
                        Some(Pubkey::from_str(&value).unwrap_or_else(|e| {
                            usage_and_exit(&format!("--vault {value:?}: {e}"))
                        }));
                }
                "--protocol-config" => {
                    let value = args
                        .next()
                        .unwrap_or_else(|| usage_and_exit("--protocol-config missing value"));
                    protocol_config = Some(Pubkey::from_str(&value).unwrap_or_else(|e| {
                        usage_and_exit(&format!("--protocol-config {value:?}: {e}"))
                    }));
                }
                "--max-index" => {
                    let value = args
                        .next()
                        .unwrap_or_else(|| usage_and_exit("--max-index missing value"));
                    max_index = Some(value.parse().unwrap_or_else(|e| {
                        usage_and_exit(&format!("--max-index {value:?}: {e}"))
                    }));
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => usage_and_exit(&format!("unexpected arg {other:?}")),
            }
        }

        if vault.is_some() == protocol_config.is_some() {
            usage_and_exit("pass exactly one of --vault or --protocol-config");
        }

        Self {
            cluster,
            rpc_url,
            vault,
            protocol_config,
            max_index,
        }
    }

    fn url(&self) -> String {
        self.rpc_url
            .clone()
            .unwrap_or_else(|| self.cluster.default_url().to_string())
    }
}

/// The four role vaults a `ProtocolConfig` names. `merge` is governed by a smart
/// account but is not stored in the config, so it is recovered from the seed.
struct ConfigAuthorities {
    protocol: Pubkey,
    tree: Pubkey,
    ring: Pubkey,
    forester: Pubkey,
}

fn read_config_authorities(rpc: &SolanaRpc, config: &Pubkey) -> Result<ConfigAuthorities> {
    let account = rpc
        .get_account(to_address(config))
        .context("fetching protocol_config")?
        .ok_or_else(|| anyhow!("protocol_config {config} not found"))?;
    let parsed = ProtocolConfig::from_account_bytes(&account.data)
        .map_err(|e| anyhow!("parsing protocol_config {config}: {e:?}"))?;
    println!("protocol_config={config} owner={}", account.owner);
    Ok(ConfigAuthorities {
        protocol: Pubkey::new_from_array(parsed.protocol_authority.to_bytes()),
        tree: Pubkey::new_from_array(parsed.tree_creation_authority.to_bytes()),
        ring: Pubkey::new_from_array(parsed.ring_creation_authority.to_bytes()),
        forester: Pubkey::new_from_array(parsed.forester_authority.to_bytes()),
    })
}

/// Recover the base index whose `protocol` role vault is `vault`. The five role
/// accounts sit at consecutive seeds above one base index, so this single number
/// identifies the whole set.
fn scan_for_base_index(vault: &Pubkey, max_index: u128) -> Option<u128> {
    for base_index in 0..=max_index {
        if base_index != 0 && base_index % SCAN_PROGRESS_STEP == 0 {
            println!("scanning base_index={base_index}/{max_index}");
        }
        if Role::Protocol.vault_pda(base_index).0 == *vault {
            return Some(base_index);
        }
    }
    None
}

fn read_policy(rpc: &SolanaRpc, settings: &Pubkey, role: Role) -> Result<(u16, Vec<Pubkey>)> {
    let account = rpc
        .get_account(to_address(settings))
        .with_context(|| format!("fetching {} settings {settings}", role.label()))?
        .filter(|account| account.owner == SMART_ACCOUNT_PROGRAM_ID)
        .ok_or_else(|| {
            anyhow!(
                "{} settings {settings} not found or not owned by {}",
                role.label(),
                SMART_ACCOUNT_PROGRAM_ID
            )
        })?;
    let threshold = settings_threshold(&account.data)
        .with_context(|| format!("decoding {} settings {settings}", role.label()))?;
    let members = settings_member_keys(&account.data)
        .with_context(|| format!("decoding {} settings {settings}", role.label()))?;
    Ok((threshold, members))
}

pub fn run(options: Options) -> Result<()> {
    let url = options.url();
    let rpc = SolanaRpc::new(url.clone());
    println!("cluster={}", options.cluster.name());
    println!("rpc_url={url}");

    let authorities = options
        .protocol_config
        .as_ref()
        .map(|config| read_config_authorities(&rpc, config))
        .transpose()?;
    let vault = match (&options.vault, &authorities) {
        (Some(vault), _) => *vault,
        (None, Some(authorities)) => authorities.protocol,
        (None, None) => bail!("pass exactly one of --vault or --protocol-config"),
    };
    println!("protocol_vault={vault}");

    let max_index = match options.max_index {
        Some(max_index) => max_index,
        None => read_program_config(&rpc)?.smart_account_index,
    };
    println!("scanning base_index=0..={max_index}");

    let base_index = scan_for_base_index(&vault, max_index).ok_or_else(|| {
        anyhow!(
            "no base_index in 0..={max_index} derives protocol vault {vault}; \
             the account may not be a Squads smart-account vault at account index 0"
        )
    })?;
    println!("base_index={base_index}");

    // The config's own tree/ring/forester authorities must be the vaults the
    // recovered base index derives, otherwise the five accounts were not created
    // as one consecutive role set.
    if let Some(authorities) = &authorities {
        for (role, expected) in [
            (Role::Tree, authorities.tree),
            (Role::Ring, authorities.ring),
            (Role::Forester, authorities.forester),
        ] {
            let derived = role.vault_pda(base_index).0;
            if derived != expected {
                bail!(
                    "base_index {base_index} derives {} vault {derived}, but the protocol config \
                     names {expected}",
                    role.label()
                );
            }
        }
        println!("config_authorities_match=true");
    }

    for (role, expected_members) in Role::ALL.into_iter().zip(expected_role_members()) {
        let (settings, _) = role.settings_pda(base_index);
        let (vault, _) = role.vault_pda(base_index);
        let (threshold, member_keys) = read_policy(&rpc, &settings, role)?;
        if threshold != role.threshold() {
            bail!(
                "{} settings {settings} has threshold {threshold}, expected {}",
                role.label(),
                role.threshold()
            );
        }
        let missing: Vec<String> = expected_members
            .iter()
            .filter(|expected| !member_keys.contains(expected))
            .map(|expected| expected.to_string())
            .collect();
        if member_keys.len() != expected_members.len() || !missing.is_empty() {
            bail!(
                "{} settings {settings} does not contain exactly the expected {} members; \
                 found {}, missing [{}]",
                role.label(),
                expected_members.len(),
                member_keys.len(),
                missing.join(", ")
            );
        }
        println!(
            "{}_settings={settings} {}_vault={vault} seed={} threshold={threshold} members={}",
            role.label(),
            role.label(),
            role.seed(base_index),
            member_keys.len()
        );
    }

    println!();
    println!("init-protocol flags:");
    for role in Role::ALL {
        let (settings, _) = role.settings_pda(base_index);
        println!("  --{}-settings {settings} \\", role.label());
    }

    Ok(())
}

fn usage_and_exit(message: &str) -> ! {
    eprintln!("error: {message}");
    print_help();
    std::process::exit(2);
}

fn print_help() {
    println!("xtask find-smart-accounts [flags]");
    println!();
    println!("Recover the five authority smart accounts of an existing deployment and print");
    println!("them as init-protocol --*-settings flags. Give either the protocol vault or a");
    println!("protocol config account that names it (for example the config of a previous");
    println!("program id).");
    println!();
    println!("Flags:");
    println!("  --cluster <localnet|devnet|mainnet>   default: localnet");
    println!("  --rpc-url <URL>                       override the cluster default RPC URL");
    println!("  --vault <PUBKEY>                      the protocol role vault to search for");
    println!("  --protocol-config <PUBKEY>            read the vault from this config account");
    println!("                                        and cross-check tree/ring/forester");
    println!("  --max-index <N>                       scan bound, default: the live Squads");
    println!("                                        smart_account_index");
    println!("  -h | --help                           print this help");
}
