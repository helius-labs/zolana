use std::{path::PathBuf, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use solana_loader_v3_interface_v7::{instruction::upgrade, state::UpgradeableLoaderState};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    pda, state::ProtocolConfig, BPF_LOADER_UPGRADEABLE_PUBKEY, PROGRAM_ID_PUBKEY,
};
use zolana_smart_account_client::roles::Role;
use zolana_test_utils::smart_account::execute_sync_ix;

use crate::{
    init_protocol::{
        load_keypair, load_protocol_signers, read_deploy_upgrade_authority, to_address, Cluster,
    },
    update_protocol_config::find_vault_settings,
};

pub struct Options {
    cluster: Cluster,
    rpc_url: Option<String>,
    payer: PathBuf,
    protocol_signers: Vec<PathBuf>,
    buffer: Option<Pubkey>,
    spill: Option<Pubkey>,
    check_only: bool,
    yes: bool,
    dry_run: bool,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut cluster = Cluster::Localnet;
        let mut rpc_url = None;
        let mut payer = None;
        let mut protocol_signers = Vec::new();
        let mut buffer = None;
        let mut spill = None;
        let mut check_only = false;
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
                "--buffer" => buffer = Some(parse_pubkey(args.next(), "--buffer")),
                "--spill" => spill = Some(parse_pubkey(args.next(), "--spill")),
                "--check-only" => check_only = true,
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
        let required = usize::from(Role::Protocol.threshold());
        if protocol_signers.len() != required {
            usage_and_exit(&format!(
                "--protocol-signer must be passed {required} times (received {})",
                protocol_signers.len()
            ));
        }
        if buffer.is_none() && !check_only {
            usage_and_exit("--buffer is required unless --check-only is used");
        }

        Self {
            cluster,
            rpc_url,
            payer,
            protocol_signers,
            buffer,
            spill,
            check_only,
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

pub fn run(options: Options) -> Result<()> {
    let payer = load_keypair(&options.payer, "payer")?;
    let protocol_signers = load_protocol_signers(&options.protocol_signers)?;
    if options.cluster == Cluster::Mainnet && !options.dry_run && !options.yes {
        bail!("refusing to send a mainnet program upgrade without --yes");
    }

    let url = options.url();
    let rpc = SolanaRpc::new(url.clone());
    let loader_authority = read_deploy_upgrade_authority(&rpc)?;

    let config_account = rpc
        .get_account(to_address(&pda::protocol_config()))
        .context("fetching protocol config")?
        .ok_or_else(|| anyhow!("protocol config {} does not exist", pda::protocol_config()))?;
    let config = ProtocolConfig::from_account_bytes(&config_account.data)
        .map_err(|error| anyhow!("protocol config is invalid: {error:?}"))?;
    let protocol_vault = Pubkey::new_from_array(config.protocol_authority.to_bytes());
    if loader_authority != protocol_vault {
        bail!(
            "shielded-pool loader authority is {loader_authority}, but the configured protocol \
             Squads vault is {protocol_vault}; refusing to route the upgrade through the wrong vault"
        );
    }

    let settings = find_vault_settings(&rpc, &protocol_vault)?;
    if options.check_only {
        println!("cluster={}", options.cluster.name());
        println!("rpc_url={url}");
        println!("program={PROGRAM_ID_PUBKEY}");
        println!("program_upgrade_authority={protocol_vault}");
        println!("protocol_settings={settings}");
        println!("authority_check=ok");
        return Ok(());
    }

    let buffer = options
        .buffer
        .ok_or_else(|| anyhow!("--buffer is required unless --check-only is used"))?;

    let buffer_account = rpc
        .get_account(to_address(&buffer))
        .with_context(|| format!("fetching loader buffer {buffer}"))?
        .ok_or_else(|| anyhow!("loader buffer {buffer} does not exist"))?;
    if buffer_account.owner != BPF_LOADER_UPGRADEABLE_PUBKEY {
        bail!("buffer {buffer} is not owned by loader-v3");
    }
    let buffer_authority = match bincode::deserialize(&buffer_account.data) {
        Ok(UpgradeableLoaderState::Buffer { authority_address }) => authority_address,
        _ => bail!("account {buffer} is not a loader-v3 Buffer"),
    };
    if buffer_authority != Some(protocol_vault) {
        bail!(
            "buffer {} authority is {:?}, expected protocol Squads vault {protocol_vault}; run \
             `solana program set-buffer-authority {} --new-buffer-authority {protocol_vault}` first",
            buffer, buffer_authority, buffer
        );
    }

    let spill = options.spill.unwrap_or_else(|| payer.pubkey());
    let loader_ix = upgrade(&PROGRAM_ID_PUBKEY, &buffer, &protocol_vault, &spill);
    let signer_keys: Vec<Pubkey> = protocol_signers.iter().map(Signer::pubkey).collect();
    let execute_ix = execute_sync_ix(&settings, 0, &signer_keys, &[loader_ix]);

    println!("cluster={}", options.cluster.name());
    println!("rpc_url={url}");
    println!("payer={}", payer.pubkey());
    println!("program={PROGRAM_ID_PUBKEY}");
    println!("program_upgrade_authority={protocol_vault}");
    println!("protocol_settings={settings}");
    println!("buffer={buffer}");
    println!("spill={spill}");
    for (index, signer) in protocol_signers.iter().enumerate() {
        println!("protocol_signer_{}={}", index + 1, signer.pubkey());
    }
    if options.dry_run {
        println!("dry_run: no transaction sent");
        return Ok(());
    }

    let mut transaction_signers: Vec<&dyn Signer> = vec![&payer];
    transaction_signers.extend(protocol_signers.iter().map(|signer| signer as &dyn Signer));
    let signature = rpc
        .create_and_send_transaction(
            &[execute_ix],
            to_address(&payer.pubkey()),
            &transaction_signers,
        )
        .map_err(|error| anyhow!("Squads loader-v3 upgrade failed: {error}"))?;
    println!("upgrade_shielded_pool sig={signature}");
    Ok(())
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
    println!("xtask upgrade-shielded-pool [flags]");
    println!();
    println!("Execute a prepared loader-v3 Buffer upgrade through the protocol Squads vault.");
    println!("The buffer authority and program upgrade authority must both be that vault.");
    println!();
    println!("Flags:");
    println!("  --cluster <localnet|devnet|mainnet>   default: localnet");
    println!("  --rpc-url <URL>                       override the cluster default RPC URL");
    println!("  --payer <KEYPAIR_PATH>                outer fee payer (required)");
    println!("  --protocol-signer <KEYPAIR_PATH>      protocol signer; pass exactly twice");
    println!(
        "  --buffer <PUBKEY>                     prepared loader-v3 Buffer (required to send)"
    );
    println!("  --check-only                          validate loader authority + Squads settings");
    println!("  --spill <PUBKEY>                      receives reclaimed lamports; default: payer");
    println!("  --yes                                 confirm an irreversible mainnet send");
    println!("  --dry-run                             validate and print, send nothing");
    println!("  -h | --help                           print this help");
}

#[cfg(test)]
mod tests {
    use solana_loader_v3_interface_v7::instruction::UpgradeableLoaderInstruction;

    use super::*;

    #[test]
    fn loader_upgrade_has_the_vault_as_its_only_signer() {
        let buffer = Pubkey::new_unique();
        let vault = Pubkey::new_unique();
        let spill = Pubkey::new_unique();
        let instruction = upgrade(&PROGRAM_ID_PUBKEY, &buffer, &vault, &spill);

        let signers: Vec<_> = instruction
            .accounts
            .iter()
            .filter(|account| account.is_signer)
            .collect();
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].pubkey, vault);
        assert_eq!(
            instruction.data,
            bincode::serialize(&UpgradeableLoaderInstruction::Upgrade)
                .expect("serialize loader instruction")
        );
    }
}
