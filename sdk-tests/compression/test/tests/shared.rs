use std::{path::Path, process::Command};

use anyhow::{anyhow, bail, Context, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use zolana_test_utils::{
    localnet::{isolated_temp_path, LocalnetValidator, ValidatorBackend, WorkspaceArtifacts},
    prover::spawn_workspace_prover,
};
use zolana_tree::TreeAccount;

pub const TRANSACT_CU_LIMIT: u32 = 1_400_000;

pub struct Environment {
    pub rpc: SolanaRpc,
    pub indexer: ZolanaIndexer,
    pub authority: Keypair,
    pub tree: Address,
}

pub fn setup() -> Result<Environment> {
    let artifacts = WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.."));
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let xtask = artifacts.path("target/debug/xtask");
    let account_dir = isolated_temp_path("zolana-compression-accounts");
    let ledger = isolated_temp_path("zolana-compression-ledger");
    for (label, path) in [("zolana CLI", cli.as_str()), ("xtask", xtask.as_str())] {
        if !Path::new(path).is_file() {
            bail!("{label} is missing at {path}; build it before running this test");
        }
    }
    let snapshot_status = Command::new(&xtask)
        .current_dir(artifacts.root())
        .args([
            "generate-account-snapshots",
            "--deploy-dir",
            "target/deploy",
            "--accounts-dir",
            &account_dir,
        ])
        .status()
        .context("generate canonical default-tree snapshots")?;
    if !snapshot_status.success() {
        bail!("default-tree snapshot generation failed");
    }

    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".into());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".into());
    LocalnetValidator {
        cli_bin: cli,
        backend: ValidatorBackend::default(),
        working_dir: artifacts.root(),
        rpc_port: rpc_port.clone(),
        photon_port: photon_port.clone(),
        ledger,
        account_dir,
        programs: vec![
            (
                compression_example_program::ID.to_string(),
                artifacts.path("target/deploy/compression_example_program.so"),
            ),
            (
                Address::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string(),
                artifacts.path("target/deploy/shielded_pool_program.so"),
            ),
        ],
    }
    .start();
    spawn_workspace_prover();

    let rpc_url = std::env::var("ZOLANA_LOCALNET_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{rpc_port}"));
    let indexer_url = std::env::var("ZOLANA_INDEXER_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{photon_port}"));
    let mut rpc = SolanaRpc::new(rpc_url);
    let authority = Keypair::new();
    rpc.airdrop(&authority.pubkey(), 10_000_000_000)?;
    let tree = pda::tree(0);
    if rpc.get_account(tree)?.is_none() {
        bail!("default tree {tree} was not loaded");
    }
    Ok(Environment {
        rpc,
        indexer: ZolanaIndexer::new(indexer_url),
        authority,
        tree,
    })
}

pub fn tree_root(rpc: &SolanaRpc, tree: Address) -> Result<(u16, [u8; 32])> {
    let mut data = rpc
        .get_account(tree)?
        .ok_or_else(|| anyhow!("tree account {tree} is missing"))?
        .data;
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|error| anyhow!("load tree: {error:?}"))?;
    let index = account.utxo_tree().current_root_index();
    let root = account
        .get_utxo_tree_root(index)
        .map_err(|error| anyhow!("read state root: {error:?}"))?;
    Ok((index, root))
}

pub fn send(
    env: &Environment,
    instruction: Instruction,
    cu_price: Option<u64>,
) -> Result<Signature> {
    send_from(env, instruction, &env.authority, cu_price)
}

pub fn send_from(
    env: &Environment,
    instruction: Instruction,
    payer: &dyn Signer,
    cu_price: Option<u64>,
) -> Result<Signature> {
    let mut instructions = vec![ComputeBudgetInstruction::set_compute_unit_limit(
        TRANSACT_CU_LIMIT,
    )];
    if let Some(price) = cu_price {
        instructions.push(ComputeBudgetInstruction::set_compute_unit_price(price));
    }
    instructions.push(instruction);
    Ok(env
        .rpc
        .create_and_send_transaction(&instructions, payer.pubkey(), &[payer])?)
}
