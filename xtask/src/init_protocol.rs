use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateProtocolConfig, CreateTree},
    pda,
    state::{tree_account_size, ProtocolConfig, SplAssetCounter},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_test_utils::smart_account::{
    create_smart_account_ix, execute_sync_ix, program_config_pda, settings_pda, smart_account_pda,
    Permissions, SmartAccountSigner, PROGRAM_CONFIG_ACCOUNT_DISCRIMINATOR,
    SMART_ACCOUNT_PROGRAM_ID,
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

    pub const TREE_ACCOUNT: Pubkey = pubkey!("treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8");
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cluster {
    Localnet,
    Devnet,
    Mainnet,
}

impl Cluster {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "localnet" => Ok(Self::Localnet),
            "devnet" => Ok(Self::Devnet),
            "mainnet" => Ok(Self::Mainnet),
            other => bail!("unknown cluster {other:?} (expected localnet|devnet|mainnet)"),
        }
    }

    fn default_url(self) -> &'static str {
        match self {
            Self::Localnet => "http://127.0.0.1:8899",
            Self::Devnet => "https://api.devnet.solana.com",
            Self::Mainnet => "https://api.mainnet-beta.solana.com",
        }
    }

    fn name(self) -> &'static str {
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
    protocol_signer: PathBuf,
    tree_keypair: PathBuf,
    yes: bool,
    dry_run: bool,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut cluster = Cluster::Localnet;
        let mut rpc_url = None;
        let mut payer = None;
        let mut protocol_signer = None;
        let mut tree_keypair = None;
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
                "--tree-keypair" => {
                    tree_keypair =
                        Some(PathBuf::from(args.next().unwrap_or_else(|| {
                            usage_and_exit("--tree-keypair missing value")
                        })));
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
        let tree_keypair =
            tree_keypair.unwrap_or_else(|| usage_and_exit("--tree-keypair is required"));

        Self {
            cluster,
            rpc_url,
            payer,
            protocol_signer,
            tree_keypair,
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
    protocol_signer: Keypair,
    tree_keypair: Keypair,
}

fn load_keypair(path: &PathBuf, label: &str) -> Result<Keypair> {
    read_keypair_file(path)
        .map_err(|e| anyhow!("failed to read {label} keypair {}: {e}", path.display()))
}

fn load_signers(options: &Options) -> Result<Signers> {
    let payer = load_keypair(&options.payer, "payer")?;
    let protocol_signer = load_keypair(&options.protocol_signer, "protocol-signer")?;
    let tree_keypair = load_keypair(&options.tree_keypair, "tree-keypair")?;

    if !authorities::PROTOCOL.contains(&protocol_signer.pubkey()) {
        bail!(
            "protocol-signer {} is not one of the hardcoded protocol authorities",
            protocol_signer.pubkey()
        );
    }
    if tree_keypair.pubkey() != authorities::TREE_ACCOUNT {
        bail!(
            "tree-keypair {} does not match the hardcoded tree account {}",
            tree_keypair.pubkey(),
            authorities::TREE_ACCOUNT
        );
    }

    Ok(Signers {
        payer,
        protocol_signer,
        tree_keypair,
    })
}

struct ProgramConfig {
    smart_account_index: u128,
    treasury: Pubkey,
}

struct RoleAddrs {
    label: &'static str,
    seed: u128,
    settings: Pubkey,
    vault: Pubkey,
}

fn to_address(key: &Pubkey) -> Address {
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

fn read_program_config(rpc: &SolanaRpc) -> Result<ProgramConfig> {
    let (pc_pda, _) = program_config_pda();
    let account = rpc
        .get_account(to_address(&pc_pda))
        .context("fetching Squads ProgramConfig")?
        .ok_or_else(|| {
            anyhow!("Squads ProgramConfig {pc_pda} not found; is the smart-account program initialized on this cluster?")
        })?;
    parse_program_config(&account).with_context(|| format!("parsing ProgramConfig {pc_pda}"))
}

fn role_addrs(label: &'static str, seed: u128) -> RoleAddrs {
    let (settings, _) = settings_pda(seed);
    let (vault, _) = smart_account_pda(&settings, 0);
    RoleAddrs {
        label,
        seed,
        settings,
        vault,
    }
}

fn derive_roles(base_index: u128) -> [RoleAddrs; 5] {
    [
        role_addrs("protocol", base_index + 1),
        role_addrs("tree", base_index + 2),
        role_addrs("zone", base_index + 3),
        role_addrs("merge", base_index + 4),
        role_addrs("forester", base_index + 5),
    ]
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
    label: &'static str,
) -> Result<RoleAddrs> {
    const MAX_ATTEMPTS: usize = 5;
    let mut attempt = 0;
    loop {
        let index = current_index(rpc)
            .with_context(|| format!("reading smart_account_index before {label} create"))?;
        let seed = index + 1;
        let (settings, _) = settings_pda(seed);
        let (vault, _) = smart_account_pda(&settings, 0);
        let ix = create_smart_account_ix(
            &payer.pubkey(),
            treasury,
            seed,
            settings_authority,
            signers,
            1,
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

    let protocol =
        create_smart_account_with_retry(rpc, payer, treasury, None, &protocol_signers, "protocol")?;
    let protocol_vault = protocol.vault;
    let tree = create_smart_account_with_retry(
        rpc,
        payer,
        treasury,
        Some(protocol_vault),
        &protocol_signers,
        "tree",
    )?;
    let zone = create_smart_account_with_retry(
        rpc,
        payer,
        treasury,
        Some(protocol_vault),
        &protocol_signers,
        "zone",
    )?;
    let merge = create_smart_account_with_retry(
        rpc,
        payer,
        treasury,
        Some(protocol_vault),
        &protocol_signers,
        "merge",
    )?;
    let forester = create_smart_account_with_retry(
        rpc,
        payer,
        treasury,
        Some(protocol_vault),
        &forester_signers,
        "forester",
    )?;

    Ok([protocol, tree, zone, merge, forester])
}

fn protocol_already_initialized(rpc: &SolanaRpc) -> Result<bool> {
    let account = rpc
        .get_account(to_address(&pda::protocol_config()))
        .context("fetching protocol_config")?;
    Ok(account.is_some_and(|account| account.owner == shielded_pool_program()))
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
    let config_rent = rpc
        .get_minimum_balance_for_rent_exemption(ProtocolConfig::SIZE)
        .context("rent for protocol_config")?;
    let counter_rent = rpc
        .get_minimum_balance_for_rent_exemption(SplAssetCounter::SIZE)
        .context("rent for spl_asset_counter")?;
    let vault_rent = rpc
        .get_minimum_balance_for_rent_exemption(0)
        .context("rent for vault")?;
    Ok(config_rent + counter_rent + vault_rent + VAULT_FUNDING_BUFFER_LAMPORTS)
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

fn send_protocol_config(
    rpc: &SolanaRpc,
    payer: &Keypair,
    protocol_signer: &Keypair,
    roles: &[RoleAddrs; 5],
) -> Result<()> {
    // Merging is now a per-user opt-in set via the user-registry
    // `set_merging_enabled` instruction, not a protocol-config field, so the
    // `merge` role no longer feeds the protocol config here.
    let [protocol, tree, zone, _merge, forester] = roles;
    let create_config_ix = CreateProtocolConfig {
        authority: protocol.vault,
        protocol_authority: protocol.vault.to_bytes().into(),
        tree_creation_authority: tree.vault.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: forester.vault.to_bytes().into(),
        zone_creation_authority: zone.vault.to_bytes().into(),
        zone_creation_is_permissionless: false,
    }
    .instruction();
    let sync = execute_sync_ix(
        &protocol.settings,
        0,
        &[protocol_signer.pubkey()],
        &[create_config_ix],
    );
    let signature = rpc
        .create_and_send_transaction(
            &[sync],
            to_address(&payer.pubkey()),
            &[payer, protocol_signer],
        )
        .map_err(|e| anyhow!("create_protocol_config failed: {e}"))?;
    println!(
        "created protocol_config={} sig={signature}",
        pda::protocol_config()
    );
    Ok(())
}

fn send_asset_counter(
    rpc: &SolanaRpc,
    payer: &Keypair,
    protocol_signer: &Keypair,
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
    let sync = execute_sync_ix(
        protocol_settings,
        0,
        &[protocol_signer.pubkey()],
        &[counter_ix],
    );
    let signature = rpc
        .create_and_send_transaction(
            &[sync],
            to_address(&payer.pubkey()),
            &[payer, protocol_signer],
        )
        .map_err(|e| anyhow!("create_asset_counter failed: {e}"))?;
    println!(
        "created spl_asset_counter={} sig={signature}",
        pda::spl_asset_counter()
    );
    Ok(())
}

fn create_tree(
    rpc: &SolanaRpc,
    payer: &Keypair,
    protocol_signer: &Keypair,
    tree_keypair: &Keypair,
    tree_settings: &Pubkey,
    tree_vault: Pubkey,
) -> Result<()> {
    let size = tree_account_size();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(size)
        .context("rent for tree account")?;
    let alloc_ix = zolana_program_test::system_create_account_ix(
        &payer.pubkey(),
        &tree_keypair.pubkey(),
        rent,
        size as u64,
        &pda::shielded_pool_program_id(),
    );
    let create_tree_ix = CreateTree {
        authority: tree_vault,
        tree: tree_keypair.pubkey(),
        owner: tree_vault,
    }
    .instruction();
    let sync = execute_sync_ix(
        tree_settings,
        0,
        &[protocol_signer.pubkey()],
        &[create_tree_ix],
    );
    let signature = rpc
        .create_and_send_transaction(
            &[alloc_ix, sync],
            to_address(&payer.pubkey()),
            &[payer, tree_keypair, protocol_signer],
        )
        .map_err(|e| anyhow!("create_tree failed: {e}"))?;
    println!("created tree={} sig={signature}", tree_keypair.pubkey());
    Ok(())
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

    let initialized = protocol_already_initialized(&rpc)?;
    if initialized && !options.dry_run {
        bail!(
            "protocol already initialized: {} exists and is owned by the shielded-pool program",
            pda::protocol_config()
        );
    }

    let program_config = read_program_config(&rpc)?;
    let roles = derive_roles(program_config.smart_account_index);
    let protocol_vault = roles[0].vault;

    println!("cluster={}", options.cluster.name());
    println!("rpc_url={url}");
    println!("dry_run={}", options.dry_run);
    println!("protocol_already_initialized={initialized}");
    println!("smart_account_index={}", program_config.smart_account_index);
    println!("treasury={}", program_config.treasury);
    println!("payer={}", signers.payer.pubkey());
    println!("protocol_signer={}", signers.protocol_signer.pubkey());
    println!("tree_account={}", signers.tree_keypair.pubkey());
    println!("protocol_vault={protocol_vault}");
    for role in &roles {
        println!(
            "{}_settings={} {}_vault={} seed={}",
            role.label, role.settings, role.label, role.vault, role.seed
        );
    }
    println!("protocol_config={}", pda::protocol_config());
    println!("spl_asset_counter={}", pda::spl_asset_counter());

    if options.dry_run {
        println!("dry_run: no transactions sent");
        return Ok(());
    }

    let created = create_all_smart_accounts(&rpc, &signers.payer, &program_config.treasury)
        .context("creating authority smart accounts")?;
    let protocol = &created[0];
    let tree = &created[1];
    println!("smart_accounts_created=true");
    println!("protocol_vault={}", protocol.vault);

    let funding = vault_funding_lamports(&rpc)?;
    fund_protocol_vault(
        &mut rpc,
        options.cluster,
        &signers.payer,
        &protocol.vault,
        funding,
    )?;

    send_protocol_config(&rpc, &signers.payer, &signers.protocol_signer, &created)?;

    send_asset_counter(
        &rpc,
        &signers.payer,
        &signers.protocol_signer,
        &protocol.settings,
        protocol.vault,
    )?;

    create_tree(
        &rpc,
        &signers.payer,
        &signers.protocol_signer,
        &signers.tree_keypair,
        &tree.settings,
        tree.vault,
    )?;

    println!("init_protocol=complete");
    println!("protocol_config={}", pda::protocol_config());
    println!("spl_asset_counter={}", pda::spl_asset_counter());
    println!("tree={}", signers.tree_keypair.pubkey());
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
    println!("  --protocol-signer <KEYPAIR_PATH>      one of the protocol authorities (required)");
    println!("  --tree-keypair <KEYPAIR_PATH>         the tree account keypair (required)");
    println!("  --yes                                 confirm irreversible mainnet sends");
    println!("  --dry-run                             derive + print addresses, send nothing");
    println!("  -h | --help                           print this help");
}
