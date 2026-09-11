//! Runtime probes for transaction v1.
//!
//! These do not exercise the shielded pool. They ask one question about the
//! backend itself: does it *execute* a v1 transaction, or merely accept one?
//!
//! The distinction is the whole reason this file exists. A v1 message carries
//! its compute ceiling, its loaded-accounts-data-size ceiling and its priority
//! fee in the message header rather than in compute-budget instructions. A
//! runtime that parses v1 but still derives the budget by scanning instructions
//! (litesvm before 0.16, via `process_compute_budget_instructions`) finds no
//! such instruction, silently falls back to the legacy default of 200,000 units
//! per instruction, and runs the transaction anyway. Every cheap probe passes
//! against that runtime. Only a transaction heavy enough to exceed the legacy
//! default ever fails, and by then the cause is opaque.
//!
//! So two of the three probes below assert a *refusal* or a *charge*, not a
//! success. They are the only things in this repository that separate "accepts
//! v1" from "executes v1", and a crate-version audit of the backend gets that
//! distinction wrong in both directions.
//!
//! The probes spawn their own backend on a dedicated port so they never contend
//! with the shielded-pool suites, and so the thing under test is unambiguous.

use std::{
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use serial_test::serial;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{v1, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction::transfer;
use solana_transaction::versioned::VersionedTransaction;
use zolana_client::{Rpc, SolanaRpc};

/// The runtime's ceiling on the account data one transaction may load, and what
/// a transaction carrying no `set_loaded_accounts_data_size_limit` instruction
/// used to receive by default. A v1 header reads an unset field as zero rather
/// than as "the default", so every probe states it explicitly.
const MAX_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

/// A port of its own, so a probe never contends with the shielded-pool suites'
/// fixed 8899 and never has to join the `serial-validator` group.
fn probe_port() -> u16 {
    std::env::var("ZOLANA_V1_PROBE_PORT")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(8920)
}

fn surfpool_bin() -> PathBuf {
    std::env::var("ZOLANA_SURFPOOL_BIN").map_or_else(
        |_| {
            PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
                .join("target/tools/surfpool")
        },
        PathBuf::from,
    )
}

/// A backend held open for one probe, killed when the probe ends.
struct Backend {
    child: Child,
    url: String,
}

impl Backend {
    /// Start surfpool offline with no programs: a probe needs an RPC that can
    /// airdrop and run a system transfer, nothing else.
    fn start() -> Result<Self> {
        let bin = surfpool_bin();
        if !bin.is_file() {
            return Err(anyhow!(
                "surfpool is not installed at {}; run `just install-surfpool`",
                bin.display()
            ));
        }
        let port = probe_port();
        let child = Command::new(&bin)
            .args([
                "start",
                "--offline",
                "--no-tui",
                "--no-deploy",
                "--no-studio",
                "--port",
                &port.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawn surfpool from {}", bin.display()))?;
        let backend = Self {
            child,
            url: format!("http://127.0.0.1:{port}"),
        };
        backend.wait_until_listening(port)?;
        Ok(backend)
    }

    fn wait_until_listening(&self, port: u16) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                // Accepting a connection precedes serving requests; give the
                // RPC a moment to finish coming up rather than racing it.
                sleep(Duration::from_millis(500));
                return Ok(());
            }
            sleep(Duration::from_millis(100));
        }
        Err(anyhow!("surfpool did not listen on port {port} within 60s"))
    }

    fn rpc(&self) -> SolanaRpc {
        SolanaRpc::new(self.url.clone())
    }

    /// A funded payer, plus the balance it starts from.
    fn funded_payer(&self, rpc: &mut SolanaRpc) -> Result<Keypair> {
        let payer = Keypair::new();
        rpc.airdrop(&payer.pubkey(), 1_000_000_000)
            .context("fund the probe payer")?;
        Ok(payer)
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Build and sign a single-instruction v1 transaction.
///
/// `config` is taken whole rather than assembled here, so a probe can state a
/// deliberately wrong ceiling and require the backend to enforce it.
fn sign_v1(
    payer: &Keypair,
    instruction: &Instruction,
    blockhash: Hash,
    config: v1::TransactionConfig,
) -> Result<VersionedTransaction> {
    let message = v1::Message::try_compile_with_config(
        &Address::new_from_array(payer.pubkey().to_bytes()),
        std::slice::from_ref(instruction),
        blockhash,
        config,
    )
    .map_err(|error| anyhow!("compile the v1 message: {error:?}"))?;
    VersionedTransaction::try_new(VersionedMessage::V1(message), &[payer])
        .map_err(|error| anyhow!("sign the v1 transaction: {error:?}"))
}

fn workable_config() -> v1::TransactionConfig {
    v1::TransactionConfig::empty()
        .with_compute_unit_limit(200_000)
        .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE)
}

/// The v1 format raises the size ceiling from one 1,232-byte packet to 4,096
/// bytes, which is what the widest shielded-pool shapes need. Every other size
/// assumption in this repository rests on the backend accepting it, so pin that
/// against the real backend rather than inferring it from a crate version.
///
/// On its own this proves very little -- see the two probes below.
#[test]
#[serial]
fn the_backend_accepts_a_v1_transaction() -> Result<()> {
    let backend = Backend::start()?;
    let mut rpc = backend.rpc();
    let payer = backend.funded_payer(&mut rpc)?;

    let instruction = transfer(&payer.pubkey(), &Pubkey::new_unique(), 1_000_000);
    let (blockhash, _) = rpc.get_latest_blockhash().context("latest blockhash")?;
    let transaction = sign_v1(&payer, &instruction, blockhash, workable_config())?;

    // Round-trip locally first, so a backend rejection cannot be blamed on a
    // malformed message built here.
    let bytes = bincode::serde::encode_to_vec(&transaction, bincode::config::legacy())
        .context("serialize the v1 transaction")?;
    let (decoded, _): (VersionedTransaction, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
            .context("the v1 transaction does not round-trip locally")?;
    assert_eq!(decoded.signatures, transaction.signatures);
    println!("v1 transaction serializes to {} bytes", bytes.len());

    rpc.process_versioned_transaction(transaction)
        .context("send the v1 transaction")?;
    Ok(())
}

/// Declare a ceiling the transaction provably cannot honour -- one compute unit
/// -- and require the failure.
///
/// A backend reading the header refuses it. A backend ignoring the header hands
/// the transaction the 200,000-unit legacy default and it confirms. The
/// assertion is the refusal, and it is the cheapest honest test of whether the
/// header is read at all: it needs no heavy work, no proof, and no program.
#[test]
#[serial]
fn the_backend_enforces_the_v1_header_compute_limit() -> Result<()> {
    let backend = Backend::start()?;
    let mut rpc = backend.rpc();
    let payer = backend.funded_payer(&mut rpc)?;

    let instruction = transfer(&payer.pubkey(), &Pubkey::new_unique(), 1_000_000);
    let (blockhash, _) = rpc.get_latest_blockhash().context("latest blockhash")?;
    let transaction = sign_v1(
        &payer,
        &instruction,
        blockhash,
        v1::TransactionConfig::empty()
            .with_compute_unit_limit(1)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE),
    )?;

    let Err(error) = rpc.process_versioned_transaction(transaction) else {
        panic!(
            "a v1 transaction declaring a one-unit compute ceiling confirmed, so the backend \
             ignored the header and fell back to the legacy per-instruction default: it parses \
             v1 but does not execute it (litesvm before 0.16)"
        );
    };
    println!("one-unit v1 ceiling refused with: {error}");
    Ok(())
}

/// The header's priority fee is the field a parsing-but-not-executing backend
/// drops *quietly*: unlike the compute ceiling it is under-charged rather than
/// loudly failed, so the payer is billed the base fee only and nothing looks
/// wrong. Bill it explicitly and require the lamports to leave the payer.
#[test]
#[serial]
fn the_backend_charges_the_v1_header_priority_fee() -> Result<()> {
    const PRIORITY_FEE_LAMPORTS: u64 = 1_000_000;
    const TRANSFERRED: u64 = 1_000_000;

    let backend = Backend::start()?;
    let mut rpc = backend.rpc();
    let payer = backend.funded_payer(&mut rpc)?;
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let before = rpc.get_balance(payer_address).context("balance before")?;

    let instruction = transfer(&payer.pubkey(), &Pubkey::new_unique(), TRANSFERRED);
    let (blockhash, _) = rpc.get_latest_blockhash().context("latest blockhash")?;
    let transaction = sign_v1(
        &payer,
        &instruction,
        blockhash,
        workable_config().with_priority_fee(PRIORITY_FEE_LAMPORTS),
    )?;
    rpc.process_versioned_transaction(transaction)
        .context("send the v1 transaction carrying a priority fee")?;

    let after = rpc.get_balance(payer_address).context("balance after")?;
    let fees = before
        .saturating_sub(after)
        .saturating_sub(TRANSFERRED);
    assert!(
        fees >= PRIORITY_FEE_LAMPORTS,
        "the payer was billed {fees} lamports in fees, which does not cover the \
         {PRIORITY_FEE_LAMPORTS}-lamport priority fee declared in the v1 header: the backend \
         parsed the header but did not charge it"
    );
    Ok(())
}
