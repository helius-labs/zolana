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

    // The merge_transact flow reads the sender's user-registry record, so the
    // user-registry program must live in the same validator as the shielded pool.
    let user_registry_id = user_registry_program_id().to_string();
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");

    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");

    // Inject a pre-initialised ProgramConfig so the validator starts with
    // smart_account_index = 0. Seeds for the three accounts are therefore
    // deterministic: protocol = 1, forester = 2, merge = 3.
    let account_dir = "/tmp/zolana-smart-account-accounts";
    write_program_config_fixture(account_dir);

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
        .expect("run zolana test-validator");
    assert!(status.success(), "zolana test-validator restart failed");
}

fn write_program_config_fixture(account_dir: &str) {
    let (pda, _) = smart_account::program_config_pda();

    // 160-byte ProgramConfig layout:
    // discriminator[8] + smart_account_index[16] + authority[32] + smart_account_creation_fee[8] + treasury[32] + _reserved[64]
    // smart_account_index = 0 means the first settings seed = 1.
    // treasury must be a non-executable, non-default pubkey.
    let mut data = [0u8; 160];
    data[..8].copy_from_slice(&smart_account::PROGRAM_CONFIG_ACCOUNT_DISCRIMINATOR);
    data[64..96].copy_from_slice(&smart_account::treasury_pda().to_bytes());
    let encoded = base64_encode(&data);

    let json = format!(
        r#"{{"pubkey":"{pda}","account":{{"lamports":1000000,"data":["{encoded}","base64"],"owner":"{}","executable":false,"rentEpoch":18446744073709551615}}}}"#,
        smart_account::SMART_ACCOUNT_PROGRAM_ID,
    );

    std::fs::create_dir_all(account_dir).expect("create smart account account dir");
    std::fs::write(format!("{account_dir}/squads_program_config.json"), json)
        .expect("write squads program config fixture");
}

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let ch = |idx: u32| char::from(*CHARS.get((idx & 0x3F) as usize).expect("base64 index"));
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(*chunk.first().unwrap_or(&0));
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ch(n >> 18));
        out.push(ch(n >> 12));
        out.push(if chunk.len() > 1 { ch(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { ch(n) } else { '=' });
    }
    out
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
