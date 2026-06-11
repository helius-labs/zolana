use std::{
    fs::{self, File},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use shielded_pool_program::instructions::create_pool_tree::init::pool_tree_account_size;
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{read_keypair_file, Keypair};
use solana_message::Message;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;
use spl_token::state::{Account as TokenAccount, Mint};
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CreatePoolTreeData, CreateProtocolConfigData,
        CreateSplInterfaceData,
    },
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SPL_ASSET_COUNTER_PDA_SEED,
    SPL_ASSET_REGISTRY_PDA_SEED, SPL_ASSET_VAULT_PDA_SEED, SPP_PROTOCOL_CONFIG_PDA_SEED,
};

const AIRDROP_LAMPORTS: u64 = 25_000_000_000;
const SOL_ASSET_ID: u64 = 1;
static TEMP_WORKSPACE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct ValidatorGuard {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl Drop for ValidatorGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn new() -> Result<Self> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before unix epoch")?
            .as_millis();
        let counter = TEMP_WORKSPACE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pocket-cli-e2e-{}-{millis}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn pocket_cli_creates_spec_p256_wallet() -> Result<()> {
    let temp = TempWorkspace::new()?;
    let wallet_path = temp.path.join("wallet.p256.json");
    let output = run_pocket_json(&[
        "create-shielded-wallet",
        "--output",
        path_str(&wallet_path)?,
    ])?;
    assert_eq!(output["scheme"], "p256");

    let wallet: Value = serde_json::from_slice(&fs::read(&wallet_path)?)?;
    assert_eq!(
        wallet["p256_public_key"]
            .as_str()
            .ok_or_else(|| anyhow!("wallet missing p256_public_key"))?
            .len(),
        66
    );
    // 0x + 31-byte (248-bit) field element = 64 chars. The 0x prefix is
    // required: the prover's field parser reads un-prefixed hex as decimal.
    assert_eq!(
        wallet["nullifier_secret"]
            .as_str()
            .ok_or_else(|| anyhow!("wallet missing nullifier_secret"))?
            .len(),
        64
    );
    Ok(())
}

#[test]
#[ignore = "starts solana-test-validator and runs real Groth16 proving"]
fn pocket_cli_drives_real_validator_and_prover() -> Result<()> {
    let root = workspace_root()?;
    let program_so = require_path(root.join("target/deploy/shielded_pool_program.so"))?;
    let prover_bin = require_path(root.join("target/prover-server"))?;
    let deposit_keys_file = require_path(root.join("target/spp/spp_0_1.key"))?;
    let transfer_keys_file = require_path(root.join("target/spp/spp_1_2.key"))?;
    let withdraw_keys_file = require_path(root.join("target/spp/spp_1_0.key"))?;
    let temp = TempWorkspace::new()?;
    let rpc_port = free_port()?;
    let faucet_port = free_port()?;
    let gossip_port = free_port()?;
    let dynamic_start = free_port()?;
    let dynamic_end = dynamic_start.saturating_add(50);
    let rpc_url = format!("http://127.0.0.1:{rpc_port}");

    let mut validator = start_validator(
        &temp.path,
        rpc_port,
        faucet_port,
        gossip_port,
        dynamic_start,
        dynamic_end,
        &program_so,
    )?;
    let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());
    wait_for_validator(&mut validator, &client)?;

    let payer_path = temp.path.join("payer.json");
    let recipient_path = temp.path.join("recipient.json");
    run_pocket_json(&[
        "create-wallet",
        "--rpc-url",
        &rpc_url,
        "--output",
        path_str(&payer_path)?,
        "--airdrop-lamports",
        &AIRDROP_LAMPORTS.to_string(),
    ])?;
    run_pocket_json(&[
        "create-wallet",
        "--rpc-url",
        &rpc_url,
        "--output",
        path_str(&recipient_path)?,
        "--airdrop-lamports",
        "1000000000",
    ])?;

    let payer = read_keypair_file(&payer_path)
        .map_err(|error| anyhow!("read payer {}: {error}", payer_path.display()))?;
    let recipient = read_keypair_file(&recipient_path)
        .map_err(|error| anyhow!("read recipient {}: {error}", recipient_path.display()))?;
    wait_for_lamports(&client, &payer.pubkey(), AIRDROP_LAMPORTS)?;
    wait_for_lamports(&client, &recipient.pubkey(), 1_000_000_000)?;
    fund_cpi_authority(&client)?;

    let tree = create_pool_tree(&client, &payer)?;
    let settlement = setup_spl_settlement(&client, &payer, &recipient)?;

    assert_eq!(token_amount(&client, &settlement.payer_token)?, 1_000);
    assert_eq!(token_amount(&client, &settlement.vault)?, 0);
    assert_eq!(token_amount(&client, &settlement.recipient_token)?, 0);
    assert_eq!(
        run_pocket_json(&[
            "balance",
            "--rpc-url",
            &rpc_url,
            "--token-account",
            &settlement.payer_token.to_string(),
        ])?["amount"],
        1_000
    );

    let payer_state = temp.path.join("payer.state.json");
    let recipient_state = temp.path.join("recipient.state.json");
    run_pocket_json(&[
        "shield",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&payer_path)?,
        "--state",
        path_str(&payer_state)?,
        "--tree",
        &tree.pubkey().to_string(),
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&deposit_keys_file)?,
        "--amount",
        "100",
        "--asset-pubkey",
        &settlement.mint.to_string(),
        "--user-spl-token",
        &settlement.payer_token.to_string(),
        "--spl-vault",
        &settlement.vault.to_string(),
        "--spl-asset-registry",
        &settlement.registry.to_string(),
    ])?;
    assert_eq!(token_amount(&client, &settlement.payer_token)?, 900);
    assert_eq!(token_amount(&client, &settlement.vault)?, 100);

    run_pocket_json(&[
        "transfer",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&payer_path)?,
        "--state",
        path_str(&payer_state)?,
        "--recipient-wallet",
        path_str(&recipient_path)?,
        "--recipient-state",
        path_str(&recipient_state)?,
        "--tree",
        &tree.pubkey().to_string(),
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&transfer_keys_file)?,
        "--amount",
        "40",
    ])?;
    assert_eq!(token_amount(&client, &settlement.payer_token)?, 900);
    assert_eq!(token_amount(&client, &settlement.vault)?, 100);

    run_pocket_json(&[
        "unshield",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&recipient_path)?,
        "--state",
        path_str(&recipient_state)?,
        "--tree",
        &tree.pubkey().to_string(),
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&withdraw_keys_file)?,
        "--amount",
        "40",
        "--asset-pubkey",
        &settlement.mint.to_string(),
        "--user-spl-token",
        &settlement.recipient_token.to_string(),
        "--spl-vault",
        &settlement.vault.to_string(),
        "--spl-asset-registry",
        &settlement.registry.to_string(),
    ])?;

    let recipient_balance = run_pocket_json(&[
        "balance",
        "--rpc-url",
        &rpc_url,
        "--token-account",
        &settlement.recipient_token.to_string(),
    ])?;
    assert_eq!(recipient_balance["amount"], 40);
    assert_eq!(token_amount(&client, &settlement.payer_token)?, 900);
    assert_eq!(token_amount(&client, &settlement.vault)?, 60);
    assert_eq!(token_amount(&client, &settlement.recipient_token)?, 40);
    Ok(())
}

#[test]
#[ignore = "starts solana-test-validator and runs real Groth16 proving"]
fn pocket_cli_drives_sol_shield_transfer_unshield() -> Result<()> {
    let root = workspace_root()?;
    let program_so = require_path(root.join("target/deploy/shielded_pool_program.so"))?;
    let prover_bin = require_path(root.join("target/prover-server"))?;
    let deposit_keys_file = require_path(root.join("target/spp/spp_0_1.key"))?;
    let transfer_keys_file = require_path(root.join("target/spp/spp_1_2.key"))?;
    let withdraw_keys_file = require_path(root.join("target/spp/spp_1_0.key"))?;
    let temp = TempWorkspace::new()?;
    let rpc_port = free_port()?;
    let faucet_port = free_port()?;
    let gossip_port = free_port()?;
    let dynamic_start = free_port()?;
    let dynamic_end = dynamic_start.saturating_add(50);
    let rpc_url = format!("http://127.0.0.1:{rpc_port}");

    let mut validator = start_validator(
        &temp.path,
        rpc_port,
        faucet_port,
        gossip_port,
        dynamic_start,
        dynamic_end,
        &program_so,
    )?;
    let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());
    wait_for_validator(&mut validator, &client)?;

    let wallet_a = temp.path.join("wallet-a.json");
    let wallet_b = temp.path.join("wallet-b.json");
    run_pocket_json(&[
        "create-wallet",
        "--rpc-url",
        &rpc_url,
        "--output",
        path_str(&wallet_a)?,
        "--airdrop-lamports",
        "25000000000",
    ])?;
    run_pocket_json(&[
        "create-wallet",
        "--rpc-url",
        &rpc_url,
        "--output",
        path_str(&wallet_b)?,
        "--airdrop-lamports",
        "5000000000",
    ])?;

    let payer = read_keypair_file(&wallet_a)
        .map_err(|error| anyhow!("read payer {}: {error}", wallet_a.display()))?;
    let wallet_b_keypair = read_keypair_file(&wallet_b)
        .map_err(|error| anyhow!("read wallet B {}: {error}", wallet_b.display()))?;
    wait_for_lamports(&client, &payer.pubkey(), 25_000_000_000)?;
    wait_for_lamports(&client, &wallet_b_keypair.pubkey(), 5_000_000_000)?;

    let tree_keypair = temp.path.join("pool-tree.json");
    let tree_json = run_pocket_json(&[
        "init-pool-tree",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&wallet_a)?,
        "--output",
        path_str(&tree_keypair)?,
    ])?;
    let tree = tree_json["tree"]
        .as_str()
        .ok_or_else(|| anyhow!("init-pool-tree output missing tree"))?
        .to_string();

    let state_a = temp.path.join("wallet-a.state.json");
    let state_b = temp.path.join("wallet-b.state.json");
    let p256_wallet_a = temp.path.join("wallet-a.p256.json");
    let p256_wallet_b = temp.path.join("wallet-b.p256.json");
    run_pocket_json(&[
        "create-shielded-wallet",
        "--output",
        path_str(&p256_wallet_a)?,
    ])?;
    run_pocket_json(&[
        "create-shielded-wallet",
        "--output",
        path_str(&p256_wallet_b)?,
    ])?;
    run_pocket_json(&[
        "shield",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&wallet_a)?,
        "--state",
        path_str(&state_a)?,
        "--tree",
        &tree,
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&deposit_keys_file)?,
        "--amount",
        "1000000000",
    ])?;
    assert_eq!(
        private_balance(&rpc_url, &state_a, Some(SOL_ASSET_ID))?,
        1_000_000_000
    );

    run_pocket_json(&[
        "transfer",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&wallet_a)?,
        "--state",
        path_str(&state_a)?,
        "--recipient-wallet",
        path_str(&wallet_b)?,
        "--recipient-state",
        path_str(&state_b)?,
        "--tree",
        &tree,
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&transfer_keys_file)?,
        "--amount",
        "400000000",
        "--asset-id",
        &SOL_ASSET_ID.to_string(),
    ])?;
    assert_eq!(
        private_balance(&rpc_url, &state_a, Some(SOL_ASSET_ID))?,
        600_000_000
    );
    assert_eq!(
        private_balance(&rpc_url, &state_b, Some(SOL_ASSET_ID))?,
        400_000_000
    );

    run_pocket_json(&[
        "shield",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&wallet_a)?,
        "--state",
        path_str(&state_a)?,
        "--owner-p256-wallet",
        path_str(&p256_wallet_a)?,
        "--tree",
        &tree,
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&deposit_keys_file)?,
        "--amount",
        "800000000",
    ])?;
    assert_eq!(
        private_balance(&rpc_url, &state_a, Some(SOL_ASSET_ID))?,
        1_400_000_000
    );

    run_pocket_json(&[
        "transfer",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&wallet_a)?,
        "--state",
        path_str(&state_a)?,
        "--owner-p256-wallet",
        path_str(&p256_wallet_a)?,
        "--recipient-p256-wallet",
        path_str(&p256_wallet_b)?,
        "--recipient-state",
        path_str(&state_b)?,
        "--tree",
        &tree,
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&transfer_keys_file)?,
        "--amount",
        "700000000",
        "--asset-id",
        &SOL_ASSET_ID.to_string(),
    ])?;
    assert_eq!(
        private_balance(&rpc_url, &state_a, Some(SOL_ASSET_ID))?,
        700_000_000
    );
    assert_eq!(
        private_balance(&rpc_url, &state_b, Some(SOL_ASSET_ID))?,
        1_100_000_000
    );

    run_pocket_json(&[
        "unshield",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&wallet_b)?,
        "--state",
        path_str(&state_b)?,
        "--owner-p256-wallet",
        path_str(&p256_wallet_b)?,
        "--tree",
        &tree,
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&withdraw_keys_file)?,
        "--amount",
        "700000000",
        "--asset-id",
        &SOL_ASSET_ID.to_string(),
    ])?;
    assert_eq!(
        private_balance(&rpc_url, &state_b, Some(SOL_ASSET_ID))?,
        400_000_000
    );

    run_pocket_json(&[
        "shield",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&wallet_b)?,
        "--state",
        path_str(&state_b)?,
        "--tree",
        &tree,
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&deposit_keys_file)?,
        "--amount",
        "500000000",
    ])?;
    assert_eq!(
        private_balance(&rpc_url, &state_b, Some(SOL_ASSET_ID))?,
        900_000_000
    );

    let wallet_a_public_before = client.get_balance(&payer.pubkey())?;
    run_pocket_json(&[
        "unshield",
        "--rpc-url",
        &rpc_url,
        "--payer",
        path_str(&wallet_b)?,
        "--state",
        path_str(&state_b)?,
        "--tree",
        &tree,
        "--prover-bin",
        path_str(&prover_bin)?,
        "--keys-file",
        path_str(&withdraw_keys_file)?,
        "--amount",
        "499990000",
        "--relayer-fee",
        "10000",
        "--user-sol-account",
        &payer.pubkey().to_string(),
    ])?;
    let wallet_a_public_after = client.get_balance(&payer.pubkey())?;
    assert_eq!(wallet_a_public_after - wallet_a_public_before, 499_990_000);

    assert_eq!(
        private_balance(&rpc_url, &state_a, Some(SOL_ASSET_ID))?,
        700_000_000
    );
    assert_eq!(
        private_balance(&rpc_url, &state_b, Some(SOL_ASSET_ID))?,
        400_000_000
    );
    assert!(client.get_balance(&wallet_b_keypair.pubkey())? > 4_400_000_000);
    Ok(())
}

#[derive(Clone, Copy)]
struct SplSettlement {
    mint: Pubkey,
    payer_token: Pubkey,
    recipient_token: Pubkey,
    vault: Pubkey,
    registry: Pubkey,
}

fn start_validator(
    temp: &Path,
    rpc_port: u16,
    faucet_port: u16,
    gossip_port: u16,
    dynamic_start: u16,
    dynamic_end: u16,
    program_so: &Path,
) -> Result<ValidatorGuard> {
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let ledger = temp.join("ledger");
    let stdout = temp.join("validator.stdout.log");
    let stderr = temp.join("validator.stderr.log");
    let child = Command::new("solana-test-validator")
        .args([
            "--reset",
            "--quiet",
            "--ledger",
            path_str(&ledger)?,
            "--rpc-port",
            &rpc_port.to_string(),
            "--faucet-port",
            &faucet_port.to_string(),
            "--gossip-port",
            &gossip_port.to_string(),
            "--dynamic-port-range",
            &format!("{dynamic_start}-{dynamic_end}"),
            "--bpf-program",
            &program_id.to_string(),
            path_str(program_so)?,
        ])
        .stdout(Stdio::from(File::create(&stdout)?))
        .stderr(Stdio::from(File::create(&stderr)?))
        .spawn()
        .context("start solana-test-validator")?;
    Ok(ValidatorGuard {
        child,
        stdout,
        stderr,
    })
}

fn wait_for_validator(validator: &mut ValidatorGuard, client: &RpcClient) -> Result<()> {
    let started = SystemTime::now();
    loop {
        if let Some(status) = validator.child.try_wait()? {
            bail!(
                "solana-test-validator exited before readiness: {status}\nstdout:\n{}\nstderr:\n{}",
                fs::read_to_string(&validator.stdout).unwrap_or_default(),
                fs::read_to_string(&validator.stderr).unwrap_or_default()
            );
        }
        if client.get_latest_blockhash().is_ok() {
            return Ok(());
        }
        if started.elapsed().unwrap_or_default() > Duration::from_secs(120) {
            bail!("timed out waiting for solana-test-validator");
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// Create the canonical protocol-config PDA (payer = authority) if it does not
/// already exist, returning its address. Admin instructions (create_pool_tree,
/// create_spl_interface) are gated on it.
fn ensure_protocol_config(client: &RpcClient, payer: &Keypair) -> Result<Pubkey> {
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let (config, _) =
        Pubkey::find_program_address(&[SPP_PROTOCOL_CONFIG_PDA_SEED], &program_id);
    if client.get_account(&config).is_ok() {
        return Ok(config);
    }
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: encode_instruction(
            tag::CREATE_PROTOCOL_CONFIG,
            &CreateProtocolConfigData {
                authority: payer.pubkey().to_bytes(),
            },
        ),
    };
    send_instructions(client, payer, &[ix], &[])?;
    Ok(config)
}

fn create_pool_tree(client: &RpcClient, payer: &Keypair) -> Result<Keypair> {
    let tree = Keypair::new();
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let protocol_config = ensure_protocol_config(client, payer)?;
    let size = pool_tree_account_size();
    let rent = client.get_minimum_balance_for_rent_exemption(size)?;
    let create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &tree.pubkey(),
        rent,
        size as u64,
        &program_id,
    );
    let pool_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new_readonly(protocol_config, false),
            AccountMeta::new(tree.pubkey(), false),
        ],
        data: encode_instruction(tag::CREATE_POOL_TREE, &CreatePoolTreeData),
    };
    send_instructions(client, payer, &[create_ix, pool_ix], &[&tree])?;
    Ok(tree)
}

fn setup_spl_settlement(
    client: &RpcClient,
    payer: &Keypair,
    recipient: &Keypair,
) -> Result<SplSettlement> {
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mint = Keypair::new();
    let payer_token = Keypair::new();
    let recipient_token = Keypair::new();
    // The protocol config is the canonical PDA the program creates itself.
    let protocol_config = ensure_protocol_config(client, payer)?;
    let token_program = spl_token::id();
    let mint_rent = client.get_minimum_balance_for_rent_exemption(Mint::LEN)?;
    let token_rent = client.get_minimum_balance_for_rent_exemption(TokenAccount::LEN)?;
    let cpi_authority = Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY);
    let (asset_counter, _) =
        Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &program_id);
    let (registry, _) = Pubkey::find_program_address(
        &[SPL_ASSET_REGISTRY_PDA_SEED, mint.pubkey().as_ref()],
        &program_id,
    );
    let (vault, _) = Pubkey::find_program_address(
        &[SPL_ASSET_VAULT_PDA_SEED, mint.pubkey().as_ref()],
        &program_id,
    );

    let instructions = vec![
        system_instruction::create_account(
            &payer.pubkey(),
            &mint.pubkey(),
            mint_rent,
            Mint::LEN as u64,
            &token_program,
        ),
        spl_token::instruction::initialize_mint2(
            &token_program,
            &mint.pubkey(),
            &payer.pubkey(),
            None,
            0,
        )?,
        system_instruction::create_account(
            &payer.pubkey(),
            &payer_token.pubkey(),
            token_rent,
            TokenAccount::LEN as u64,
            &token_program,
        ),
        spl_token::instruction::initialize_account3(
            &token_program,
            &payer_token.pubkey(),
            &mint.pubkey(),
            &payer.pubkey(),
        )?,
        system_instruction::create_account(
            &payer.pubkey(),
            &recipient_token.pubkey(),
            token_rent,
            TokenAccount::LEN as u64,
            &token_program,
        ),
        spl_token::instruction::initialize_account3(
            &token_program,
            &recipient_token.pubkey(),
            &mint.pubkey(),
            &recipient.pubkey(),
        )?,
        spl_token::instruction::mint_to(
            &token_program,
            &mint.pubkey(),
            &payer_token.pubkey(),
            &payer.pubkey(),
            &[],
            1_000,
        )?,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new_readonly(protocol_config, false),
                AccountMeta::new(asset_counter, false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(mint.pubkey(), false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(cpi_authority, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(token_program, false),
            ],
            data: encode_instruction(tag::CREATE_SPL_INTERFACE, &CreateSplInterfaceData),
        },
    ];
    send_instructions(
        client,
        payer,
        &instructions,
        &[&mint, &payer_token, &recipient_token],
    )?;

    Ok(SplSettlement {
        mint: mint.pubkey(),
        payer_token: payer_token.pubkey(),
        recipient_token: recipient_token.pubkey(),
        vault,
        registry,
    })
}

fn fund_cpi_authority(client: &RpcClient) -> Result<()> {
    let cpi_authority = Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY);
    let signature = client.request_airdrop(&cpi_authority, 1_000_000)?;
    client.confirm_transaction(&signature)?;
    wait_for_lamports(client, &cpi_authority, 1_000_000)?;
    Ok(())
}

fn wait_for_lamports(client: &RpcClient, pubkey: &Pubkey, minimum: u64) -> Result<()> {
    let started = SystemTime::now();
    loop {
        if client.get_balance(pubkey).unwrap_or(0) >= minimum {
            return Ok(());
        }
        if started.elapsed().unwrap_or_default() > Duration::from_secs(30) {
            bail!("timed out waiting for {pubkey} to have at least {minimum} lamports");
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn token_amount(client: &RpcClient, token_account: &Pubkey) -> Result<u64> {
    let account = client.get_account(token_account)?;
    Ok(TokenAccount::unpack(&account.data)?.amount)
}

fn send_instructions(
    client: &RpcClient,
    payer: &Keypair,
    instructions: &[Instruction],
    extra_signers: &[&Keypair],
) -> Result<()> {
    let blockhash = client.get_latest_blockhash()?;
    let message = Message::new(instructions, Some(&payer.pubkey()));
    let mut signers = Vec::with_capacity(extra_signers.len() + 1);
    signers.push(payer);
    signers.extend_from_slice(extra_signers);
    let transaction = Transaction::new(&signers, message, blockhash);
    client.send_and_confirm_transaction(&transaction)?;
    Ok(())
}

fn run_pocket_json(args: &[&str]) -> Result<Value> {
    let output = Command::new(env!("CARGO_BIN_EXE_pocket"))
        .args(args)
        .output()
        .context("run pocket CLI")?;
    if !output.status.success() {
        bail!(
            "pocket {:?} failed with status {}\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "decode pocket stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn private_balance(rpc_url: &str, state: &Path, asset_id: Option<u64>) -> Result<u64> {
    let mut args = vec!["balance", "--rpc-url", rpc_url, "--state", path_str(state)?];
    let asset_id_string = asset_id.map(|asset_id| asset_id.to_string());
    if let Some(asset_id_string) = asset_id_string.as_deref() {
        args.extend(["--asset-id", asset_id_string]);
    }
    let value = run_pocket_json(&args)?;
    value["private_amount"]
        .as_u64()
        .ok_or_else(|| anyhow!("balance output missing private_amount"))
}

fn workspace_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("run git rev-parse")?;
    if !output.status.success() {
        bail!("git rev-parse failed");
    }
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}

fn require_path(path: PathBuf) -> Result<PathBuf> {
    if path.exists() {
        Ok(path)
    } else {
        bail!(
            "missing {}; run `just test-pocket-cli-e2e` to build required artifacts",
            path.display()
        )
    }
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", path.display()))
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}
