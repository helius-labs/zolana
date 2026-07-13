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
use zolana_interface::instruction::instruction_data::transact::TransactProof;
use zolana_smart_account_client::SMART_ACCOUNT_PROGRAM_ID;
use zolana_test_utils::smart_account;
use zolana_user_registry_interface::user_registry_program_id;

pub(crate) const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
pub(crate) const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
pub(crate) const ZERO: [u8; 32] = [0u8; 32];
// Blinding positions in the fixed-position output layout
// `[spl_change, sol_change, recipients...]`.
pub(crate) const SPL_CHANGE_POSITION: u8 = 0;
pub(crate) const SOL_CHANGE_POSITION: u8 = 1;
pub(crate) const RECIPIENT_POSITION_BASE: u8 = 2;

/// Pack a Groth16 proof (always BSB22-committed) into the 192-byte layout the
/// `merge_transact` program path reads.
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

/// Build the `transact` proof enum: the eddsa rail omits the BSB22 commitment, the
/// P256 rail keeps it.
pub(crate) fn transact_proof(proof: &Proof) -> Result<TransactProof> {
    Ok(ProofCompressed::try_from(*proof)?.to_transact_proof())
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

    // The merge_transact flow reads the sender's user-registry record, so the
    // user-registry program must live in the same validator as the shielded pool.
    let user_registry_id = user_registry_program_id().to_string();
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");

    let smart_account_id = SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");

    // Inject a pre-initialised ProgramConfig so the standard smart-account
    // seeds are deterministic.
    let account_dir = "/tmp/zolana-smart-account-accounts";
    smart_account::write_program_config_fixture(account_dir);

    let status = std::process::Command::new(&cli)
        .current_dir(root)
        .args([
            "dev",
            "start",
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
            "--sbf-program",
            &user_registry_id,
            &user_registry_so,
            "--sbf-program",
            &smart_account_id,
            &smart_account_so,
            "--account-dir",
            account_dir,
        ])
        .status()
        .expect("run zolana dev start");
    assert!(status.success(), "zolana dev start restart failed");
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
