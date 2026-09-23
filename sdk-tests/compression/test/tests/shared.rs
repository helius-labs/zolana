use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use zolana_program_test::{fixture::write_protocol_snapshot, localnet::LocalnetValidator};
use zolana_test_utils::{
    localnet::{env_port, isolated_temp_path, WorkspaceArtifacts},
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
    let account_dir = PathBuf::from(isolated_temp_path("zolana-compression-accounts"));
    let spp_so = PathBuf::from(artifacts.path("target/deploy/shielded_pool_program.so"));
    write_protocol_snapshot(&spp_so, &account_dir)
        .map_err(|e| anyhow!("write the protocol snapshot: {e}"))?;

    let rpc_port = env_port("ZOLANA_LOCALNET_RPC_PORT", 8899);
    let photon_port = env_port("ZOLANA_LOCALNET_PHOTON_PORT", 8784);
    LocalnetValidator {
        cli_bin: std::env::var("ZOLANA_CLI_BIN")
            .unwrap_or_else(|_| artifacts.path("target/debug/zolana"))
            .into(),
        working_dir: artifacts.root().into(),
        rpc_port,
        photon_port,
        account_dir,
        programs: vec![
            (
                compression_example_program::ID,
                artifacts
                    .path("target/deploy/compression_example_program.so")
                    .into(),
            ),
            (Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), spp_so),
        ],
        slot_time: None,
    }
    .start()
    .map_err(|e| anyhow!("start the compression localnet: {e}"))?;
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

/// Submit as a transaction **v1** message, whose 4096-byte limit holds a
/// proof-carrying compression instruction. The compute ceilings live in the
/// message header instead of in a compute-budget instruction. A `cu_price` also
/// makes an otherwise identical message distinct, which is what the replay
/// negatives rely on.
pub fn send_from(
    env: &Environment,
    instruction: Instruction,
    payer: &dyn Signer,
    cu_price: Option<u64>,
) -> Result<Signature> {
    let budget = ComputeBudgetConfig::new(TRANSACT_CU_LIMIT);
    let budget = match cu_price {
        Some(price) => budget.with_compute_unit_price(price),
        None => budget,
    };
    Ok(env.rpc.create_and_send_transaction(
        std::slice::from_ref(&instruction),
        payer.pubkey(),
        &[payer],
        budget,
    )?)
}
