//! Localnet orchestration for the Squads zone lifecycle suite. A persistent
//! prover server is started once (lazy per-shape key loading) for the
//! proof-gated `transact` scenarios (the backend proves through it); the proofless
//! `deposit` never touches it. Each scenario restarts a fresh validator + Photon
//! loaded with the SPP, user-registry, smart-account, and Squads zone programs.
//! Indexer polling lives in `zolana_test_utils::test_validator_asserts`.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_address_lookup_table_interface::{
    instruction::{create_lookup_table, extend_lookup_table},
    state::AddressLookupTable,
};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use zolana_client::{spawn_prover, Rpc, SolanaRpc};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_squads_interface::SQUADS_ZONE_PROGRAM_ID;
use zolana_test_utils::smart_account;
use zolana_user_registry_interface::user_registry_program_id;

pub(crate) const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
pub(crate) const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";

fn repo_root() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../..").to_string()
}

/// Start the persistent prover server (idempotent), pointing it at the repo's
/// `prover/server/proving-keys`. The squads keys (`squads_zone_*`,
/// `squads_key_encryption_*`, written by `generate_keys_squads.sh` /
/// `just ensure-squads-keys`) and the SPP zone-rail keys (`transfer_p256_zone_*`)
/// live there. The server lazy-loads each shape on first request; an
/// already-running prover is left untouched so its loaded keys stay warm across
/// scenarios. Override with `ZOLANA_PROVER_KEYS_DIR`.
pub(crate) fn start_prover() -> Result<()> {
    if std::env::var("ZOLANA_PROVER_KEYS_DIR").is_err() {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../prover/server/proving-keys"
            ),
        );
    }
    spawn_prover()?;
    Ok(())
}

fn squads_program_so(root: &str) -> String {
    std::env::var("SQUADS_ZONE_PROGRAM_PATH")
        .unwrap_or_else(|_| format!("{root}/zones/squads/target/deploy/zolana_squads_program.so"))
}

fn use_repo_photon_by_default(root: &str) {
    if std::env::var("PHOTON_BIN").is_ok() || std::env::var("ZOLANA_PHOTON_BIN").is_ok() {
        return;
    }
    let photon = format!("{root}/target/bin/photon");
    if Path::new(&photon).exists() {
        std::env::set_var("ZOLANA_PHOTON_BIN", photon);
    }
}

/// Restart a fresh validator + Photon via the `zolana` CLI, loading every program
/// the deposit path touches: SPP (settlement), the smart-account program (the
/// protocol config is created via its CPI), the user-registry (co-loaded for
/// parity with the other suites), and the Squads zone (whose `deposit` CPIs SPP).
/// The account directory seeds only the smart-account `ProgramConfig`; viewing key
/// accounts are created at runtime through the backend.
pub(crate) fn restart_localnet() {
    let root = repo_root();
    use_repo_photon_by_default(&root);
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());
    // The validator faucet binds a fixed port (default 9900) that does not track
    // the RPC port, so two clones running localnet at once collide on it. Derive
    // it from the RPC port (keeping 9900 for the default 8899) so a shifted RPC
    // port isolates the faucet too, and let an explicit override win.
    let faucet_port = std::env::var("ZOLANA_LOCALNET_FAUCET_PORT").unwrap_or_else(|_| {
        rpc_port
            .parse::<u16>()
            .map(|port| (port + 1001).to_string())
            .unwrap_or_else(|_| "9900".to_string())
    });

    let spp_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
    let spp_so = format!("{root}/target/deploy/shielded_pool_program.so");
    let user_registry_id = user_registry_program_id().to_string();
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");
    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");
    let squads_id = Pubkey::new_from_array(SQUADS_ZONE_PROGRAM_ID).to_string();
    let squads_so = squads_program_so(&root);

    for so in [&spp_so, &user_registry_so, &smart_account_so, &squads_so] {
        assert!(
            Path::new(so).exists(),
            "missing program binary {so}; run `just build-programs build-cli ensure-smart-account` \
             and `cargo build-sbf --features bpf-entrypoint --manifest-path \
             zones/squads/program/Cargo.toml` first"
        );
    }

    // Isolate the genesis account directory per RPC port: parallel port-offset
    // clones each rewrite this dir on every restart, and a validator reading a
    // concurrently-rewritten fixture at genesis panics early. Keying it to the
    // RPC port keeps each offset's genesis independent.
    // Only the smart-account `ProgramConfig` is genesis-seeded; every viewing key
    // account is created at runtime through the backend, so none is written here.
    let account_dir = format!("/tmp/zolana-squads-validator-accounts-{rpc_port}");
    smart_account::write_program_config_fixture(&account_dir);

    // Under a busy machine (other clones' provers / key generation), a fresh
    // validator can lose a race for its fixed RPC/photon ports to a not-yet-reaped
    // predecessor, or its ledger lock can still be held by a dying predecessor,
    // making it exit early (status 101). Free the ports first, use a UNIQUE ledger
    // directory per restart to sidestep the lock race, and retry the CLI a few
    // times so a transient startup loss does not fail an otherwise-green scenario.
    let restart_once = || -> bool {
        kill_port_holders(&[&rpc_port, &photon_port, &faucet_port]);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let ledger = format!("/tmp/zolana-squads-validator-ledger-{nanos}");
        std::process::Command::new(&cli)
            .current_dir(&root)
            .args([
                "test-validator",
                "--no-use-surfpool",
                "--with-photon",
                "--skip-prover",
                "--rpc-port",
                &rpc_port,
                "--faucet-port",
                &faucet_port,
                "--photon-port",
                &photon_port,
                "--ledger",
                &ledger,
                "--sbf-program",
                &spp_id,
                &spp_so,
                "--sbf-program",
                &user_registry_id,
                &user_registry_so,
                "--sbf-program",
                &smart_account_id,
                &smart_account_so,
                "--sbf-program",
                &squads_id,
                &squads_so,
                "--account-dir",
                account_dir.as_str(),
            ])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    };

    for attempt in 1..=4 {
        if restart_once() {
            return;
        }
        eprintln!("zolana test-validator restart attempt {attempt} failed; retrying");
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    panic!("zolana test-validator restart failed after 4 attempts");
}

/// Best-effort kill of any process listening on the given TCP ports, so a stray
/// validator/photon from a prior scenario cannot hold this scenario's ports.
fn kill_port_holders(ports: &[&str]) {
    for port in ports {
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "lsof -ti tcp:{port} 2>/dev/null | xargs -r kill -9 2>/dev/null"
            ))
            .status();
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
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

/// Send `ixs` as a v0 (versioned) transaction resolving `lookup_tables`, so
/// accounts moved into an address lookup table are referenced by 1-byte index
/// instead of a 32-byte static key. Used by the SPL withdrawal, whose two 192-byte
/// proofs plus the 5-account SPL settlement tail push a legacy transaction just
/// over the 1232-byte raw size limit.
pub(crate) fn send_v0_transaction(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
    lookup_tables: &[AddressLookupTableAccount],
) -> Result<Signature> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = v0::Message::try_compile(&payer.pubkey(), ixs, lookup_tables, blockhash)
        .map_err(|e| anyhow!("compile v0 message: {e}"))?;
    let transaction = VersionedTransaction::try_new(VersionedMessage::V0(message), signers)
        .map_err(|e| anyhow!("sign v0 transaction: {e}"))?;

    // Skip preflight: the lookup table was just created, and a preflight simulation
    // can run against a bank that has not yet loaded it ("address table account
    // that doesn't exist"), even though it is confirmed on-chain (the caller
    // fetched it). The real execution bank resolves it, so send directly and then
    // confirm.
    let signature = rpc
        .client()
        .send_transaction_with_config(
            &transaction,
            RpcSendTransactionConfig {
                skip_preflight: true,
                ..Default::default()
            },
        )
        .map_err(|e| anyhow!("send v0 transaction: {e}"))?;

    let started = Instant::now();
    loop {
        // `get_signature_statuses` surfaces an execution error (skip_preflight
        // means the send call itself does not), so a rejected transaction fails
        // fast with its real cause instead of timing out.
        if let Some(status) = rpc
            .client()
            .get_signature_statuses(&[signature])
            .map_err(|e| anyhow!("status v0 transaction: {e}"))?
            .value
            .into_iter()
            .next()
            .flatten()
        {
            if let Some(err) = status.err {
                return Err(anyhow!("v0 transaction {signature} failed on-chain: {err}"));
            }
            return Ok(signature);
        }
        if started.elapsed() > Duration::from_secs(30) {
            return Err(anyhow!("v0 transaction {signature} not confirmed in time"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Create and populate an address lookup table holding `addresses`, then wait for
/// it to activate (a table cannot be used in the slot it was last extended) and
/// return it resolved for v0 message compilation. The `payer` is both the table
/// authority and the funder.
pub(crate) fn create_address_lookup_table(
    rpc: &mut SolanaRpc,
    payer: &Keypair,
    addresses: &[Pubkey],
) -> Result<AddressLookupTableAccount> {
    // `create_lookup_table` requires `recent_slot` to be present in the SlotHashes
    // sysvar; the current tip is not yet there (the program rejects it with "N is
    // not a recent slot"), so use its parent.
    let recent_slot = rpc
        .client()
        .get_slot()
        .map_err(|e| anyhow!("get_slot: {e}"))?
        .saturating_sub(1);
    let (create_ix, table) = create_lookup_table(payer.pubkey(), payer.pubkey(), recent_slot);
    send_transaction(rpc, &[create_ix], &payer.pubkey(), &[payer])?;

    let extend_ix = extend_lookup_table(
        table,
        payer.pubkey(),
        Some(payer.pubkey()),
        addresses.to_vec(),
    );
    send_transaction(rpc, &[extend_ix], &payer.pubkey(), &[payer])?;

    // The table becomes usable only after the validator advances past the slot in
    // which it was last extended; wait a couple of slots before returning it.
    let activation_slot = rpc
        .client()
        .get_slot()
        .map_err(|e| anyhow!("get_slot: {e}"))?
        + 2;
    let started = Instant::now();
    loop {
        let slot = rpc
            .client()
            .get_slot()
            .map_err(|e| anyhow!("get_slot: {e}"))?;
        if slot >= activation_slot {
            break;
        }
        if started.elapsed() > Duration::from_secs(30) {
            return Err(anyhow!("lookup table {table} did not activate in time"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let account = rpc
        .get_account(Address::new_from_array(table.to_bytes()))
        .map_err(|e| anyhow!("fetch lookup table {table}: {e}"))?
        .ok_or_else(|| anyhow!("lookup table {table} account missing"))?;
    let parsed = AddressLookupTable::deserialize(&account.data)
        .map_err(|e| anyhow!("deserialize lookup table {table}: {e}"))?;
    Ok(AddressLookupTableAccount {
        key: table,
        addresses: parsed.addresses.to_vec(),
    })
}
