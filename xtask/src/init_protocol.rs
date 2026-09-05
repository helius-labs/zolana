use std::{path::PathBuf, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{read_keypair_file, Keypair};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateProtocolConfig, CreateTree},
    pda,
    state::{nullifier_tree_params, ProtocolConfig, SplAssetCounter},
    BPF_LOADER_UPGRADEABLE_PUBKEY, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_smart_account_client::{
    create_role_smart_account_ix,
    roles::Role,
    settings::{settings_member_keys, settings_seed, settings_threshold},
};
use zolana_test_utils::smart_account::{
    execute_sync_each, execute_sync_ix, program_config_pda, settings_pda, smart_account_pda,
    Permissions, SmartAccountSigner, PROGRAM_CONFIG_ACCOUNT_DISCRIMINATOR,
    SMART_ACCOUNT_PROGRAM_ID,
};
use zolana_tree::TreeFeeSchedule;

use crate::tree_fees::{
    at_cost_for_transaction_size, print_schedule, ForesterClose, TransactionSize,
};

const VAULT_FUNDING_BUFFER_LAMPORTS: u64 = 10_000_000;

pub mod authorities {
    use solana_pubkey::{pubkey, Pubkey};

    pub const PROTOCOL: [Pubkey; 5] = [
        pubkey!("2kgbLowvCQuMWxDKbHUZAURycziuRrvmtTuDEYMGMRsj"),
        pubkey!("AdWdKMo89o1HN2dMF1Bk9zRhtU7iT6tFPqL27uWoaMBi"),
        pubkey!("ESuhzg7TyJGBWToxxvsKez9HxP4KAKRDshBznppyRMDo"),
        pubkey!("GoZBYjLaMcjX1T6mqLBkeYehRDBb2ts19S2H6icvMBFd"),
        pubkey!("ECBkPzeojfxQpUGNM6u1dd1woER3wfmcYSVPbV8gxhJE"),
    ];

    pub const FORESTER: [Pubkey; 10] = [
        pubkey!("EuCYkVyZuHbLgjmhit6ZzufvzFhMVKG95JFE9HvTPUNy"),
        pubkey!("HhQPSJuUTXAPKLridqnLGCMzkpHw8PCNP7i8rZRmVLSA"),
        pubkey!("2tL473vNAomcuqYntCWZBuenKmxaxhGyGxcQxNDjvDfv"),
        pubkey!("5NVdqLMg4E8xdA3ctRpJ4u2g4JZfPQ7Z3NqpXrBuzznH"),
        pubkey!("4XFSyVZJdyeCm3V4DomswxaZYW71jN5Y2aUXDemy5PhP"),
        pubkey!("A5qG4cdfRF96jLEH3SM292mQd5iwhFkPZ3vUwGDE1jEu"),
        pubkey!("56Pa3mtPMph9iGV6pKEnZe7Mm7zn22f6CaRBTeUD5XVk"),
        pubkey!("4DRsXX5bnrTDX8mDbQx1a93uA7JQTCZ8TGm4dVHXRErH"),
        pubkey!("4riGd5piEfB6Ge3TCY8Vk8JGLP5HDyLkDEajN8rvAw4i"),
        pubkey!("E8Dmx8zP1E9xdcCJCZjzSUuFo61LPxSbvmg8a3NQKwMB"),
    ];
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cluster {
    Localnet,
    Devnet,
    Mainnet,
}

impl Cluster {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "localnet" => Ok(Self::Localnet),
            "devnet" => Ok(Self::Devnet),
            "mainnet" => Ok(Self::Mainnet),
            other => bail!("unknown cluster {other:?} (expected localnet|devnet|mainnet)"),
        }
    }

    pub(crate) fn default_url(self) -> &'static str {
        match self {
            Self::Localnet => "http://127.0.0.1:8899",
            Self::Devnet => "https://api.devnet.solana.com",
            Self::Mainnet => "https://api.mainnet-beta.solana.com",
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Localnet => "localnet",
            Self::Devnet => "devnet",
            Self::Mainnet => "mainnet",
        }
    }

    fn allows_airdrop(self) -> bool {
        matches!(self, Self::Localnet)
    }
}

pub struct Options {
    cluster: Cluster,
    rpc_url: Option<String>,
    payer: PathBuf,
    protocol_signers: Vec<PathBuf>,
    upgrade_authority: Option<PathBuf>,
    reuse_settings: Option<[Pubkey; 5]>,
    transaction_size: TransactionSize,
    yes: bool,
    dry_run: bool,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut cluster = Cluster::Localnet;
        let mut rpc_url = None;
        let mut payer = None;
        let mut protocol_signers = Vec::new();
        let mut upgrade_authority = None;
        let mut reuse_settings: [Option<Pubkey>; 5] = [None; 5];
        let mut transaction_size = TransactionSize::V1;
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
                "--upgrade-authority" => {
                    upgrade_authority =
                        Some(PathBuf::from(args.next().unwrap_or_else(|| {
                            usage_and_exit("--upgrade-authority missing value")
                        })));
                }
                "--protocol-settings"
                | "--tree-settings"
                | "--ring-settings"
                | "--merge-settings"
                | "--forester-settings" => {
                    let role = Role::ALL
                        .into_iter()
                        .position(|role| arg == format!("--{}-settings", role.label()))
                        .unwrap_or_else(|| usage_and_exit(&format!("unexpected arg {arg:?}")));
                    let value = args
                        .next()
                        .unwrap_or_else(|| usage_and_exit(&format!("{arg} missing value")));
                    let key = Pubkey::from_str(&value)
                        .unwrap_or_else(|e| usage_and_exit(&format!("{arg} {value:?}: {e}")));
                    let Some(slot) = reuse_settings.get_mut(role) else {
                        usage_and_exit("role index out of range")
                    };
                    *slot = Some(key);
                }
                "--transaction-size" => {
                    let value = args
                        .next()
                        .unwrap_or_else(|| usage_and_exit("--transaction-size missing value"));
                    transaction_size = TransactionSize::parse(&value)
                        .unwrap_or_else(|e| usage_and_exit(&e.to_string()));
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

        let reuse_settings = match reuse_settings {
            [None, None, None, None, None] => None,
            [Some(protocol), Some(tree), Some(ring), Some(merge), Some(forester)] => {
                Some([protocol, tree, ring, merge, forester])
            }
            reuse_settings => {
                let missing: Vec<String> = Role::ALL
                    .into_iter()
                    .zip(reuse_settings)
                    .filter(|(_, key)| key.is_none())
                    .map(|(role, _)| format!("--{}-settings", role.label()))
                    .collect();
                usage_and_exit(&format!(
                    "reusing existing smart accounts needs all five settings addresses; missing {}",
                    missing.join(", ")
                ))
            }
        };

        Self {
            cluster,
            rpc_url,
            payer,
            protocol_signers,
            upgrade_authority,
            reuse_settings,
            transaction_size,
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

struct Signers {
    payer: Keypair,
    protocol_signers: Vec<Keypair>,
    upgrade_authority: Option<Keypair>,
}

pub(crate) fn load_keypair(path: &PathBuf, label: &str) -> Result<Keypair> {
    read_keypair_file(path)
        .map_err(|e| anyhow!("failed to read {label} keypair {}: {e}", path.display()))
}

pub(crate) fn load_protocol_signers(paths: &[PathBuf]) -> Result<Vec<Keypair>> {
    let required = usize::from(Role::Protocol.threshold());
    if paths.len() != required {
        bail!(
            "the {}-of-{} protocol policy requires {required} signer keypairs, got {}",
            Role::Protocol.threshold(),
            authorities::PROTOCOL.len(),
            paths.len()
        );
    }

    let mut signers = Vec::with_capacity(required);
    for (index, path) in paths.iter().enumerate() {
        let label = format!("protocol-signer #{}", index + 1);
        let signer = load_keypair(path, &label)?;
        if !authorities::PROTOCOL.contains(&signer.pubkey()) {
            bail!(
                "{label} {} is not one of the hardcoded protocol authorities",
                signer.pubkey()
            );
        }
        if signers
            .iter()
            .any(|existing: &Keypair| existing.pubkey() == signer.pubkey())
        {
            bail!("{label} {} is duplicated", signer.pubkey());
        }
        signers.push(signer);
    }
    Ok(signers)
}

fn load_signers(options: &Options) -> Result<Signers> {
    let payer = load_keypair(&options.payer, "payer")?;
    let protocol_signers = load_protocol_signers(&options.protocol_signers)?;
    let upgrade_authority = options
        .upgrade_authority
        .as_ref()
        .map(|path| load_keypair(path, "upgrade-authority"))
        .transpose()?;

    Ok(Signers {
        payer,
        protocol_signers,
        upgrade_authority,
    })
}

pub(crate) struct ProgramConfig {
    pub(crate) smart_account_index: u128,
    treasury: Pubkey,
}

#[derive(Clone, Copy)]
struct RoleAddrs {
    label: &'static str,
    seed: u128,
    settings: Pubkey,
    vault: Pubkey,
}

pub(crate) fn to_address(key: &Pubkey) -> Address {
    Address::new_from_array(key.to_bytes())
}

fn shielded_pool_program() -> Pubkey {
    Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
}

fn parse_program_config(account: &Account) -> Result<ProgramConfig> {
    let data = &account.data;
    let discriminator = data
        .get(0..8)
        .ok_or_else(|| anyhow!("ProgramConfig too small: {} bytes", data.len()))?;
    if discriminator != PROGRAM_CONFIG_ACCOUNT_DISCRIMINATOR {
        bail!("ProgramConfig discriminator mismatch");
    }
    let index_bytes: [u8; 16] = data
        .get(8..24)
        .ok_or_else(|| anyhow!("ProgramConfig missing smart_account_index"))?
        .try_into()
        .expect("slice of length 16");
    let treasury_bytes: [u8; 32] = data
        .get(64..96)
        .ok_or_else(|| anyhow!("ProgramConfig missing treasury"))?
        .try_into()
        .expect("slice of length 32");
    Ok(ProgramConfig {
        smart_account_index: u128::from_le_bytes(index_bytes),
        treasury: Pubkey::new_from_array(treasury_bytes),
    })
}

pub(crate) fn read_program_config(rpc: &SolanaRpc) -> Result<ProgramConfig> {
    let (pc_pda, _) = program_config_pda();
    let account = rpc
        .get_account(to_address(&pc_pda))
        .context("fetching Squads ProgramConfig")?
        .ok_or_else(|| {
            anyhow!("Squads ProgramConfig {pc_pda} not found; is the smart-account program initialized on this cluster?")
        })?;
    parse_program_config(&account).with_context(|| format!("parsing ProgramConfig {pc_pda}"))
}

/// The Squads `Settings` accounts the previous init run created at consecutive
/// seeds, in [`Role::ALL`] creation order: protocol, tree, zone, and merge are
/// governed by the protocol authorities, forester by the forester authorities
/// (mirrors `create_all_smart_accounts`).
pub(crate) fn expected_role_members() -> [&'static [Pubkey]; 5] {
    [
        &authorities::PROTOCOL,
        &authorities::PROTOCOL,
        &authorities::PROTOCOL,
        &authorities::PROTOCOL,
        &authorities::FORESTER,
    ]
}

fn verify_settings_policy(
    label: &str,
    settings_key: &Pubkey,
    data: &[u8],
    expected_members: &[Pubkey],
    expected_threshold: u16,
) -> Result<()> {
    let threshold = settings_threshold(data)
        .with_context(|| format!("decoding {label} smart account settings {settings_key}"))?;
    if threshold != expected_threshold {
        bail!(
            "{label} smart account settings {settings_key} has threshold {threshold}, expected \
             {expected_threshold}"
        );
    }
    let member_keys = settings_member_keys(data)
        .with_context(|| format!("decoding {label} smart account settings {settings_key}"))?;
    if member_keys.len() != expected_members.len() {
        bail!(
            "{label} smart account settings {settings_key} has {} members, expected exactly {}",
            member_keys.len(),
            expected_members.len()
        );
    }
    for expected in expected_members {
        if !member_keys.contains(expected) {
            bail!(
                "{label} smart account settings {settings_key} does not list expected member \
                 {expected}"
            );
        }
    }
    Ok(())
}

/// Resolve the five role accounts from settings addresses supplied on the
/// command line, so an init reuses the authority smart accounts of an earlier
/// deployment instead of creating new ones. Each account must be a Squads
/// `Settings` owned by the smart-account program, must list the expected role
/// members at the required threshold, and must be the canonical PDA of the
/// seed stored inside it.
fn load_reused_roles(rpc: &SolanaRpc, settings_keys: &[Pubkey; 5]) -> Result<[RoleAddrs; 5]> {
    let mut roles = Vec::with_capacity(Role::ALL.len());
    for ((role, settings_key), expected_members) in Role::ALL
        .into_iter()
        .zip(settings_keys)
        .zip(expected_role_members())
    {
        let account = rpc
            .get_account(to_address(settings_key))
            .with_context(|| format!("fetching {} smart account settings", role.label()))?
            .filter(|account| account.owner == SMART_ACCOUNT_PROGRAM_ID)
            .ok_or_else(|| {
                anyhow!(
                    "{} smart account settings {settings_key} not found or not owned by {}",
                    role.label(),
                    SMART_ACCOUNT_PROGRAM_ID
                )
            })?;
        verify_settings_policy(
            role.label(),
            settings_key,
            &account.data,
            expected_members,
            role.threshold(),
        )?;
        let seed = settings_seed(&account.data).with_context(|| {
            format!(
                "decoding {} smart account settings {settings_key}",
                role.label()
            )
        })?;
        let (derived, _) = settings_pda(seed);
        if derived != *settings_key {
            bail!(
                "{} smart account settings {settings_key} stores seed {seed}, which derives \
                 {derived}",
                role.label()
            );
        }
        let (vault, _) = smart_account_pda(settings_key, 0);
        roles.push(RoleAddrs {
            label: role.label(),
            seed,
            settings: *settings_key,
            vault,
        });
    }
    roles
        .try_into()
        .map_err(|_| anyhow!("expected five reused role settings"))
}

/// Derive the five role accounts at the shared role table's seed offsets above
/// `base_index` (`zolana_smart_account_client::roles`: protocol, tree, zone,
/// merge, forester at +1..=+5).
fn derive_roles(base_index: u128) -> [RoleAddrs; 5] {
    Role::ALL.map(|role| {
        let (settings, _) = role.settings_pda(base_index);
        let (vault, _) = role.vault_pda(base_index);
        RoleAddrs {
            label: role.label(),
            seed: role.seed(base_index),
            settings,
            vault,
        }
    })
}

fn current_index(rpc: &SolanaRpc) -> Result<u128> {
    read_program_config(rpc).map(|config| config.smart_account_index)
}

fn signer_set(keys: &[Pubkey]) -> Vec<SmartAccountSigner> {
    keys.iter()
        .map(|key| SmartAccountSigner {
            key: *key,
            permissions: Permissions::all(),
        })
        .collect()
}

fn create_smart_account_with_retry(
    rpc: &SolanaRpc,
    payer: &Keypair,
    treasury: &Pubkey,
    settings_authority: Option<Pubkey>,
    signers: &[SmartAccountSigner],
    role: Role,
) -> Result<RoleAddrs> {
    const MAX_ATTEMPTS: usize = 5;
    let label = role.label();
    let mut attempt = 0;
    loop {
        let index = current_index(rpc)
            .with_context(|| format!("reading smart_account_index before {label} create"))?;
        let seed = index + 1;
        let (settings, _) = settings_pda(seed);
        let (vault, _) = smart_account_pda(&settings, 0);
        let ix = create_role_smart_account_ix(
            &payer.pubkey(),
            treasury,
            seed,
            settings_authority,
            signers,
            role,
            0,
        );
        match rpc.create_and_send_transaction(&[ix], to_address(&payer.pubkey()), &[payer]) {
            Ok(signature) => {
                println!(
                    "created {label} smart account: settings={settings} vault={vault} seed={seed} sig={signature}"
                );
                return Ok(RoleAddrs {
                    label,
                    seed,
                    settings,
                    vault,
                });
            }
            Err(error) => {
                attempt += 1;
                if attempt >= MAX_ATTEMPTS {
                    return Err(anyhow!(
                        "failed to create {label} smart account after {attempt} attempts: {error}"
                    ));
                }
                eprintln!(
                    "create {label} smart account attempt {attempt} failed ({error}); re-reading index and retrying"
                );
            }
        }
    }
}

fn create_all_smart_accounts(
    rpc: &SolanaRpc,
    payer: &Keypair,
    treasury: &Pubkey,
) -> Result<[RoleAddrs; 5]> {
    let protocol_signers = signer_set(&authorities::PROTOCOL);
    let forester_signers = signer_set(&authorities::FORESTER);

    let protocol = create_smart_account_with_retry(
        rpc,
        payer,
        treasury,
        None,
        &protocol_signers,
        Role::Protocol,
    )?;
    let protocol_vault = protocol.vault;
    let tree = create_smart_account_with_retry(
        rpc,
        payer,
        treasury,
        Some(protocol_vault),
        &protocol_signers,
        Role::Tree,
    )?;
    let ring = create_smart_account_with_retry(
        rpc,
        payer,
        treasury,
        Some(protocol_vault),
        &protocol_signers,
        Role::Ring,
    )?;
    let merge = create_smart_account_with_retry(
        rpc,
        payer,
        treasury,
        Some(protocol_vault),
        &protocol_signers,
        Role::Merge,
    )?;
    let forester = create_smart_account_with_retry(
        rpc,
        payer,
        treasury,
        Some(protocol_vault),
        &forester_signers,
        Role::Forester,
    )?;

    Ok([protocol, tree, ring, merge, forester])
}

/// Read the stored `protocol_authority` from the on-chain protocol config.
/// `None` means the config account does not exist yet (or is not owned by the
/// shielded-pool program), i.e. the protocol is not initialized.
fn read_stored_protocol_authority(rpc: &SolanaRpc) -> Result<Option<Pubkey>> {
    let account = rpc
        .get_account(to_address(&pda::protocol_config()))
        .context("fetching protocol_config")?;
    match account {
        Some(account) if account.owner == shielded_pool_program() => {
            let config = ProtocolConfig::from_account_bytes(&account.data)
                .map_err(|e| anyhow!("parsing protocol_config: {e:?}"))?;
            Ok(Some(Pubkey::new_from_array(
                config.protocol_authority.to_bytes(),
            )))
        }
        _ => Ok(None),
    }
}

fn system_transfer_ix(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = [0u8; 12];
    data[0] = 2;
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: Pubkey::default(),
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data: data.to_vec(),
    }
}

fn vault_funding_lamports(rpc: &SolanaRpc) -> Result<u64> {
    let counter_rent = rpc
        .get_minimum_balance_for_rent_exemption(SplAssetCounter::SIZE)
        .context("rent for spl_asset_counter")?;
    let vault_rent = rpc
        .get_minimum_balance_for_rent_exemption(0)
        .context("rent for vault")?;
    Ok(counter_rent + vault_rent + VAULT_FUNDING_BUFFER_LAMPORTS)
}

fn fund_protocol_vault(
    rpc: &mut SolanaRpc,
    cluster: Cluster,
    payer: &Keypair,
    vault: &Pubkey,
    lamports: u64,
) -> Result<()> {
    if cluster.allows_airdrop() {
        rpc.airdrop(vault, lamports)
            .map_err(|e| anyhow!("airdrop to protocol vault {vault} failed: {e}"))?;
    } else {
        rpc.create_and_send_transaction(
            &[system_transfer_ix(&payer.pubkey(), vault, lamports)],
            to_address(&payer.pubkey()),
            &[payer],
        )
        .map_err(|e| anyhow!("transfer to protocol vault {vault} failed: {e}"))?;
    }
    println!("funded protocol_vault={vault} lamports={lamports}");
    Ok(())
}

/// Read the real, nonzero loader-v3 upgrade authority required to initialize
/// the protocol config. Unsupported, immutable, zero-authority, and malformed
/// deployment states fail closed exactly like the on-chain gate.
pub(crate) fn read_deploy_upgrade_authority(rpc: &SolanaRpc) -> Result<Pubkey> {
    let program = rpc
        .get_account(to_address(&shielded_pool_program()))
        .context("fetching shielded-pool program account")?
        .ok_or_else(|| anyhow!("shielded-pool program account not found"))?;
    if program.owner != BPF_LOADER_UPGRADEABLE_PUBKEY {
        bail!("shielded-pool program is not deployed with loader-v3");
    }
    let program_data_address = match decode_loader_state(&program.data) {
        Some(UpgradeableLoaderState::Program {
            programdata_address,
        }) => programdata_address,
        _ => bail!("shielded-pool program account is not a loader-v3 Program state"),
    };
    let program_data = rpc
        .get_account(to_address(&program_data_address))
        .context("fetching shielded-pool ProgramData account")?
        .ok_or_else(|| anyhow!("ProgramData account {program_data_address} not found"))?;
    if program_data.owner != BPF_LOADER_UPGRADEABLE_PUBKEY {
        bail!("ProgramData account {program_data_address} is not loader-owned");
    }
    read_program_data_upgrade_authority(&program_data_address, &program_data.data)
}

/// Decode loader-v3 account state with the canonical agave type. bincode 1.x
/// (the wire format Solana account states use) allows trailing bytes: the
/// `ProgramData` account carries the ELF binary after the header.
fn decode_loader_state(data: &[u8]) -> Option<UpgradeableLoaderState> {
    bincode::deserialize(data).ok()
}

/// Read a loader-v3 `ProgramData` account's real, nonzero upgrade authority.
fn read_program_data_upgrade_authority(
    program_data_address: &Pubkey,
    data: &[u8],
) -> Result<Pubkey> {
    let Some(UpgradeableLoaderState::ProgramData {
        upgrade_authority_address,
        ..
    }) = decode_loader_state(data)
    else {
        bail!("ProgramData account {program_data_address} is not a loader-v3 ProgramData state");
    };
    let authority = upgrade_authority_address.ok_or_else(|| {
        anyhow!(
            "shielded-pool ProgramData account {program_data_address} has no upgrade authority; \
             initialize the protocol before making the program immutable"
        )
    })?;
    if authority == Pubkey::default() {
        bail!(
            "shielded-pool ProgramData account {program_data_address} has a zero upgrade \
             authority; initialize it with a real loader-v3 authority"
        );
    }
    Ok(authority)
}

#[derive(Clone, Copy)]
enum InitializationAuthority<'a> {
    Keypair(&'a Keypair),
    ProtocolVault,
}

fn resolve_initialization_authority<'a>(
    expected: Pubkey,
    supplied_keypair: Option<&'a Keypair>,
    protocol_vault: Pubkey,
) -> Result<InitializationAuthority<'a>> {
    if expected == protocol_vault {
        if let Some(keypair) = supplied_keypair {
            bail!(
                "--upgrade-authority {} was supplied, but the on-chain upgrade authority is the \
                 protocol Squads vault {protocol_vault}; omit the keypair so Squads authorizes \
                 initialization",
                keypair.pubkey()
            );
        }
        return Ok(InitializationAuthority::ProtocolVault);
    }

    let keypair = supplied_keypair.ok_or_else(|| {
        anyhow!(
            "the shielded-pool upgrade authority is {expected}, not the protocol Squads vault \
             {protocol_vault}; pass its keypair via --upgrade-authority"
        )
    })?;
    if keypair.pubkey() != expected {
        bail!(
            "--upgrade-authority {} does not match the on-chain upgrade authority {expected}",
            keypair.pubkey()
        );
    }
    Ok(InitializationAuthority::Keypair(keypair))
}

fn send_protocol_config(
    rpc: &SolanaRpc,
    payer: &Keypair,
    protocol_signers: &[Keypair],
    initialization_authority: InitializationAuthority<'_>,
    roles: &[RoleAddrs; 5],
) -> Result<()> {
    // Merging is now a per-user opt-in set via the user-registry
    // `set_merging_enabled` instruction, not a protocol-config field, so the
    // `merge` role no longer feeds the protocol config here.
    let [protocol, tree, ring, _merge, forester] = roles;
    let initialization_authority_key = match initialization_authority {
        InitializationAuthority::Keypair(keypair) => keypair.pubkey(),
        InitializationAuthority::ProtocolVault => protocol.vault,
    };
    let create_config_ix = CreateProtocolConfig {
        fee_payer: payer.pubkey(),
        initialization_authority: initialization_authority_key,
        protocol_authority: protocol.vault.to_bytes().into(),
        tree_creation_authority: tree.vault.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: forester.vault.to_bytes().into(),
        ring_creation_authority: ring.vault.to_bytes().into(),
        fee_authority: protocol.vault.to_bytes().into(),
        ring_activation_is_permissionless: false,
        spl_interface_creation_is_permissionless: true,
    }
    .instruction();

    let signature = match initialization_authority {
        InitializationAuthority::Keypair(keypair) => rpc
            .create_and_send_transaction(
                &[create_config_ix],
                to_address(&payer.pubkey()),
                &[payer, keypair],
            )
            .map_err(|e| anyhow!("create_protocol_config failed: {e}"))?,
        InitializationAuthority::ProtocolVault => {
            let signer_keys: Vec<Pubkey> = protocol_signers.iter().map(Signer::pubkey).collect();
            let sync = execute_sync_ix(&protocol.settings, 0, &signer_keys, &[create_config_ix]);
            let mut transaction_signers: Vec<&dyn Signer> = vec![payer];
            transaction_signers.extend(protocol_signers.iter().map(|signer| signer as &dyn Signer));
            rpc.create_and_send_transaction(
                &[sync],
                to_address(&payer.pubkey()),
                &transaction_signers,
            )
            .map_err(|e| anyhow!("create_protocol_config through Squads failed: {e}"))?
        }
    };
    println!(
        "created protocol_config={} protocol_authority={} initialization_authority={} sig={signature}",
        pda::protocol_config(),
        protocol.vault,
        initialization_authority_key,
    );
    Ok(())
}

fn send_asset_counter(
    rpc: &SolanaRpc,
    payer: &Keypair,
    protocol_signers: &[Keypair],
    protocol_settings: &Pubkey,
    protocol_vault: Pubkey,
) -> Result<()> {
    if rpc
        .get_account(to_address(&pda::spl_asset_counter()))
        .context("fetching spl_asset_counter")?
        .is_some()
    {
        println!("spl_asset_counter already exists, skipping");
        return Ok(());
    }
    let counter_ix = CreateAssetCounter {
        authority: protocol_vault,
    }
    .instruction();
    let signer_keys: Vec<Pubkey> = protocol_signers.iter().map(Signer::pubkey).collect();
    let sync = execute_sync_ix(protocol_settings, 0, &signer_keys, &[counter_ix]);
    let mut transaction_signers: Vec<&dyn Signer> = vec![payer];
    transaction_signers.extend(protocol_signers.iter().map(|signer| signer as &dyn Signer));
    let signature = rpc
        .create_and_send_transaction(&[sync], to_address(&payer.pubkey()), &transaction_signers)
        .map_err(|e| anyhow!("create_asset_counter failed: {e}"))?;
    println!(
        "created spl_asset_counter={} sig={signature}",
        pda::spl_asset_counter()
    );
    Ok(())
}

fn next_tree_id(rpc: &SolanaRpc, initialized: bool) -> Result<u16> {
    if !initialized {
        return Ok(0);
    }
    zolana_program_test::next_tree_id(rpc).context("reading next_tree_id from protocol_config")
}

fn create_tree(
    rpc: &SolanaRpc,
    payer: &Keypair,
    protocol_signer: &Keypair,
    tree_id: u16,
    tree_settings: &Pubkey,
    tree_vault: Pubkey,
    fees: TreeFeeSchedule,
) -> Result<Pubkey> {
    let create = CreateTree {
        payer: payer.pubkey(),
        authority: tree_vault,
        tree_id,
        nullifier_params: nullifier_tree_params(),
        fees,
    };
    let steps = execute_sync_each(
        tree_settings,
        0,
        &[protocol_signer.pubkey()],
        &create.instructions(),
    );
    let signature = rpc
        .create_and_send_transaction(
            &steps,
            to_address(&payer.pubkey()),
            &[payer, protocol_signer],
        )
        .map_err(|e| anyhow!("create_tree failed: {e}"))?;
    let tree = create.tree();
    println!("created tree={tree} tree_id={tree_id} sig={signature}");
    Ok(tree)
}

pub fn run(options: Options) -> Result<()> {
    let signers = load_signers(&options).context("loading signing keypairs")?;
    if options.cluster == Cluster::Mainnet && !options.dry_run && !options.yes {
        bail!("refusing to send mainnet transactions without --yes");
    }
    let url = options.url();
    let mut rpc = SolanaRpc::new(url.clone());

    rpc.assert_executable(&shielded_pool_program())
        .map_err(|e| anyhow!("shielded-pool program not executable: {e}"))?;
    rpc.assert_executable(&SMART_ACCOUNT_PROGRAM_ID)
        .map_err(|e| anyhow!("smart-account program not executable: {e}"))?;

    let stored_protocol_authority = read_stored_protocol_authority(&rpc)?;
    let initialized = stored_protocol_authority.is_some();
    if let Some(stored_protocol_authority) = stored_protocol_authority.filter(|_| !options.dry_run)
    {
        bail!(
            "protocol already initialized: {} exists with protocol_authority {}",
            pda::protocol_config(),
            stored_protocol_authority
        );
    }

    let program_config = read_program_config(&rpc)?;
    let reused_roles = options
        .reuse_settings
        .as_ref()
        .map(|settings| load_reused_roles(&rpc, settings))
        .transpose()
        .context("resolving the smart accounts to reuse")?;
    let roles = reused_roles.unwrap_or_else(|| derive_roles(program_config.smart_account_index));
    let protocol_vault = roles[0].vault;
    let deploy_upgrade_authority = if initialized {
        None
    } else {
        Some(read_deploy_upgrade_authority(&rpc)?)
    };
    let dry_run_initialization_authority = deploy_upgrade_authority
        .map(|expected| {
            resolve_initialization_authority(
                expected,
                signers.upgrade_authority.as_ref(),
                protocol_vault,
            )
        })
        .transpose()?;
    let tree_id = next_tree_id(&rpc, initialized)?;
    let forester_close = ForesterClose {
        settings: roles[4].settings,
        member: signers.payer.pubkey(),
        tree: pda::tree(tree_id),
    };
    let closes_per_transaction = forester_close.closes_per_transaction(options.transaction_size)?;
    let fees = at_cost_for_transaction_size(
        nullifier_tree_params().input_queue_zkp_batch_size,
        closes_per_transaction,
    )?;

    println!("cluster={}", options.cluster.name());
    println!("rpc_url={url}");
    println!("dry_run={}", options.dry_run);
    println!("protocol_already_initialized={initialized}");
    println!("deploy_upgrade_authority={deploy_upgrade_authority:?}");
    println!("smart_account_index={}", program_config.smart_account_index);
    println!("reuse_existing_smart_accounts={}", reused_roles.is_some());
    println!("treasury={}", program_config.treasury);
    println!("payer={}", signers.payer.pubkey());
    for (index, signer) in signers.protocol_signers.iter().enumerate() {
        println!("protocol_signer_{}={}", index + 1, signer.pubkey());
    }
    println!("tree_id={tree_id}");
    println!("tree_account={}", pda::tree(tree_id));
    println!("protocol_vault={protocol_vault}");
    for role in &roles {
        println!(
            "{}_settings={} {}_vault={} seed={}",
            role.label, role.settings, role.label, role.vault, role.seed
        );
    }
    println!("protocol_config={}", pda::protocol_config());
    println!("spl_asset_counter={}", pda::spl_asset_counter());
    print_schedule(options.transaction_size, closes_per_transaction, &fees);

    if options.dry_run {
        if let Some(initialization_authority) = dry_run_initialization_authority {
            let kind = match initialization_authority {
                InitializationAuthority::Keypair(_) => "keypair",
                InitializationAuthority::ProtocolVault => "protocol_squads_vault",
            };
            println!("initialization_authority_kind={kind}");
        }
        println!("dry_run: no transactions sent");
        return Ok(());
    }

    let created = if let Some(roles) = reused_roles {
        println!("smart_accounts_created=false");
        for role in &roles {
            println!(
                "reusing {}_settings={} {}_vault={} seed={}",
                role.label, role.settings, role.label, role.vault, role.seed
            );
        }

        let funding = vault_funding_lamports(&rpc)?;
        fund_protocol_vault(
            &mut rpc,
            options.cluster,
            &signers.payer,
            &roles[0].vault,
            funding,
        )?;

        roles
    } else {
        let created = create_all_smart_accounts(&rpc, &signers.payer, &program_config.treasury)
            .context("creating authority smart accounts")?;
        println!("smart_accounts_created=true");
        println!("protocol_vault={}", created[0].vault);

        let funding = vault_funding_lamports(&rpc)?;
        fund_protocol_vault(
            &mut rpc,
            options.cluster,
            &signers.payer,
            &created[0].vault,
            funding,
        )?;

        created
    };
    let initialization_authority = resolve_initialization_authority(
        deploy_upgrade_authority.ok_or_else(|| {
            anyhow!("an uninitialized protocol must have a loader-v3 upgrade authority")
        })?,
        signers.upgrade_authority.as_ref(),
        created[0].vault,
    )?;
    send_protocol_config(
        &rpc,
        &signers.payer,
        &signers.protocol_signers,
        initialization_authority,
        &created,
    )?;
    let protocol = &created[0];
    let tree = &created[1];
    send_asset_counter(
        &rpc,
        &signers.payer,
        &signers.protocol_signers,
        &protocol.settings,
        protocol.vault,
    )?;

    let tree_signer = signers.protocol_signers.first().ok_or_else(|| {
        anyhow!("the protocol policy did not provide a signer for tree initialization")
    })?;
    let tree_account = create_tree(
        &rpc,
        &signers.payer,
        tree_signer,
        tree_id,
        &tree.settings,
        tree.vault,
        fees,
    )?;

    println!("init_protocol=complete");
    println!("protocol_config={}", pda::protocol_config());
    println!("spl_asset_counter={}", pda::spl_asset_counter());
    println!("tree={tree_account}");
    for role in &created {
        println!("{}_vault={}", role.label, role.vault);
    }

    Ok(())
}

fn usage_and_exit(message: &str) -> ! {
    eprintln!("error: {message}");
    print_help();
    std::process::exit(2);
}

fn print_help() {
    println!("xtask init-protocol [flags]");
    println!();
    println!("Initialize the shielded-pool protocol on a cluster: Squads authority");
    println!("smart accounts, protocol config, SPL asset counter, and the initial tree.");
    println!();
    println!("Flags:");
    println!("  --cluster <localnet|devnet|mainnet>   default: localnet");
    println!("  --rpc-url <URL>                       override the cluster default RPC URL");
    println!("  --payer <KEYPAIR_PATH>                funds + outer fee payer (required)");
    println!(
        "  --protocol-signer <KEYPAIR_PATH>      protocol authority signer; pass exactly twice"
    );
    println!("  --upgrade-authority <KEYPAIR_PATH>    loader-v3 upgrade authority keypair;");
    println!("                                        omit when it is the protocol Squads vault");
    println!("  --protocol-settings <PUBKEY>          reuse existing authority smart accounts");
    println!("  --tree-settings <PUBKEY>              instead of creating new ones. All five");
    println!("  --ring-settings <PUBKEY>              are required together; each must be a");
    println!("  --merge-settings <PUBKEY>             Squads Settings account listing the");
    println!("  --forester-settings <PUBKEY>          expected role members");
    println!("  --transaction-size <v0|v1>            size limit of the forester's close");
    println!("                                        transactions (1232 or 4096 bytes); sets");
    println!(
        "                                        the tree's default fee schedule. default: v1"
    );
    println!("  --yes                                 confirm irreversible mainnet sends");
    println!("  --dry-run                             derive + print addresses, send nothing");
    println!("  -h | --help                           print this help");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal loader-v3 `ProgramData` header: u32 tag 3 || slot u64 le ||
    /// u8 option tag || 32-byte authority. The same layout the canonical
    /// `UpgradeableLoaderState` bincode deserialization reads on-chain.
    fn program_data_fixture(option_tag: u8, authority: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        data.push(option_tag);
        if option_tag == 1 {
            data.extend_from_slice(authority);
        }
        data.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        data
    }

    #[test]
    fn zeroed_upgrade_authority_is_rejected() {
        let data = program_data_fixture(1, &[0u8; 32]);
        assert!(read_program_data_upgrade_authority(&Pubkey::new_unique(), &data).is_err());
    }

    #[test]
    fn unset_upgrade_authority_is_rejected() {
        let data = program_data_fixture(0, &[0u8; 32]);
        assert!(read_program_data_upgrade_authority(&Pubkey::new_unique(), &data).is_err());
    }

    #[test]
    fn set_upgrade_authority_round_trips() {
        let authority = Pubkey::new_unique();
        let data = program_data_fixture(1, &authority.to_bytes());
        let parsed = read_program_data_upgrade_authority(&Pubkey::new_unique(), &data)
            .expect("valid ProgramData");
        assert_eq!(parsed, authority);
    }

    #[test]
    fn malformed_program_data_is_an_error() {
        let parsed = read_program_data_upgrade_authority(&Pubkey::new_unique(), &[0u8; 4]);
        assert!(parsed.is_err());
    }

    #[test]
    fn protocol_vault_is_selected_without_a_keypair() {
        let vault = Pubkey::new_unique();
        assert!(matches!(
            resolve_initialization_authority(vault, None, vault).expect("vault authority"),
            InitializationAuthority::ProtocolVault
        ));
    }

    #[test]
    fn direct_upgrade_authority_requires_the_matching_keypair() {
        let authority = Keypair::new();
        let vault = Pubkey::new_unique();
        assert!(matches!(
            resolve_initialization_authority(
                authority.pubkey(),
                Some(&authority),
                vault
            )
            .expect("direct authority"),
            InitializationAuthority::Keypair(keypair) if keypair.pubkey() == authority.pubkey()
        ));
        assert!(resolve_initialization_authority(authority.pubkey(), None, vault).is_err());
        assert!(
            resolve_initialization_authority(authority.pubkey(), Some(&Keypair::new()), vault)
                .is_err()
        );
    }

    #[test]
    fn protocol_vault_rejects_an_irrelevant_upgrade_keypair() {
        let vault = Pubkey::new_unique();
        assert!(resolve_initialization_authority(vault, Some(&Keypair::new()), vault).is_err());
    }
}
