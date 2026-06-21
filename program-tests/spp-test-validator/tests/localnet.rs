//! Localnet orchestration and proof helpers shared by the World. Indexer polling
//! lives in `zolana_test_utils::test_validator_asserts`.

use anyhow::Result;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use zolana_client::{spawn_prover, Proof, ProofCompressed, Rpc, SolanaRpc};

pub(crate) const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
pub(crate) const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
pub(crate) const ZERO: [u8; 32] = [0u8; 32];
// Blinding positions in the fixed-position output layout
// `[spl_change, sol_change, recipients...]`.
pub(crate) const SPL_CHANGE_POSITION: u8 = 0;
pub(crate) const SOL_CHANGE_POSITION: u8 = 1;
pub(crate) const RECIPIENT_POSITION_BASE: u8 = 2;

/// Pack a Groth16 proof (with optional BSB22 commitment) into the 192-byte
/// layout the program reads.
pub(crate) fn pack_proof(proof: &Proof) -> Result<[u8; 192]> {
    let compressed = ProofCompressed::try_from(*proof)?;
    let mut out = [0u8; 192];
    out[0..32].copy_from_slice(&compressed.a);
    out[32..96].copy_from_slice(&compressed.b);
    out[96..128].copy_from_slice(&compressed.c);
    if let Some(commitment) = compressed.commitment {
        out[128..160].copy_from_slice(&commitment.commitment);
        out[160..192].copy_from_slice(&commitment.commitment_pok);
    }
    Ok(out)
}

/// Start the persistent prover server (idempotent), pointing it at the committed
/// proving keys.
pub(crate) fn start_prover() -> Result<()> {
    std::env::set_var(
        "ZOLANA_PROVER_KEYS_DIR",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../prover/server/proving-keys"
        ),
    );
    spawn_prover()?;
    Ok(())
}

/// Restart a fresh validator + Photon via the `zolana` CLI (the single source of
/// truth for localnet orchestration and readiness). `--skip-prover` leaves the
/// persistent prover server untouched so its proving keys stay loaded.
pub(crate) fn restart_localnet() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let program_id =
        std::env::var("SHIELDED_POOL_PROGRAM_ID").expect("SHIELDED_POOL_PROGRAM_ID must be set");
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());
    let program_so = format!("{root}/target/deploy/shielded_pool_program.so");

    let status = std::process::Command::new(&cli)
        .current_dir(root)
        .args([
            "test-validator",
            "--no-use-surfpool",
            "--with-photon",
            "--skip-prover",
            "--rpc-port",
            &rpc_port,
            "--photon-port",
            &photon_port,
            "--ledger",
            "/tmp/zolana-photon-test-ledger",
            "--sbf-program",
            &program_id,
            &program_so,
        ])
        .status()
        .expect("run zolana test-validator");
    assert!(status.success(), "zolana test-validator restart failed");
}

pub(crate) fn send_transaction(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> Result<Signature> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(ixs, Some(payer));
    let transaction = Transaction::new(signers, message, blockhash);
    Ok(rpc.send_transaction(&transaction)?)
}
