use std::{env, process::Command};

use anyhow::{ensure, Context, Result};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::SolanaRpc;
use zolana_event_parser::indexed_events_from_instruction_groups;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{instruction::Deposit, SHIELDED_POOL_PROGRAM_ID};
use zolana_program_test::{deposit_outputs_from_event, DepositOutput, ZolanaProgramTest};

use crate::localnet::{send_transaction, WorkspaceArtifacts};

pub const NOTE_AMOUNT: u64 = 1_000_000_000;

pub struct BenchmarkConfig {
    pub inputs: usize,
    pub runs: usize,
    pub concurrency: usize,
    pub warm_keys: bool,
    pub interleaved: bool,
    pub gomaxprocs: Option<usize>,
    pub prover_concurrency: Option<usize>,
}

impl BenchmarkConfig {
    pub fn from_env() -> Result<Self> {
        let layout = env::var("E2E_BENCH_LAYOUT").unwrap_or_else(|_| "clustered".into());
        ensure!(
            ["clustered", "scattered", "interleaved"].contains(&layout.as_str()),
            "invalid benchmark layout"
        );
        let config = Self {
            inputs: number("E2E_BENCH_INPUTS", 144)?,
            runs: number("E2E_BENCH_RUNS", 1)?,
            concurrency: number("E2E_BENCH_CONCURRENCY", 4)?,
            warm_keys: env::var("E2E_BENCH_WARM_KEYS").as_deref() == Ok("1"),
            interleaved: layout != "clustered",
            gomaxprocs: optional_number("GOMAXPROCS")?,
            prover_concurrency: optional_number("PROVER_SYNC_CONCURRENCY")?,
        };
        ensure!(
            config.inputs > 0 && config.inputs <= 512 && config.runs > 0 && config.concurrency > 0,
            "invalid benchmark shape"
        );
        Ok(config)
    }

    pub fn layout(&self) -> &'static str {
        if self.interleaved {
            "interleaved"
        } else {
            "clustered"
        }
    }
}

fn number(name: &str, default: usize) -> Result<usize> {
    env::var(name).map_or(Ok(default), |value| {
        value.parse().with_context(|| format!("invalid {name}"))
    })
}

fn optional_number(name: &str) -> Result<Option<usize>> {
    env::var(name)
        .ok()
        .map(|value| value.parse().with_context(|| format!("invalid {name}")))
        .transpose()
}

fn listener_pid(port: u16) -> Result<String> {
    let output = Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
        .output()
        .context("find benchmark prover process")?;
    let mut pids = String::from_utf8(output.stdout)?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    pids.sort();
    pids.dedup();
    ensure!(
        pids.len() <= 1,
        "multiple listeners on benchmark prover port {port}"
    );
    Ok(pids.pop().unwrap_or_default())
}

pub fn restart_prover() -> Result<()> {
    let artifacts = WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let cli = env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let address = env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".into());
    let port = address
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse::<u16>()
        .context("benchmark requires an explicit local prover port")?;
    ensure!(
        address.starts_with("http://127.0.0.1:") || address.starts_with("http://localhost:"),
        "benchmark prover must be local"
    );
    let previous_pid = listener_pid(port)?;
    let status = Command::new(cli)
        .args([
            "dev",
            "prover",
            "start",
            "--prover-port",
            &port.to_string(),
            "--auto-download=false",
        ])
        .env("ZOLANA_PROVER_KEYS_DIR", artifacts.prover_keys_dir())
        .status()
        .context("restart benchmark prover")?;
    ensure!(status.success(), "benchmark prover restart failed");
    let pid = listener_pid(port)?;
    ensure!(
        !pid.is_empty() && pid != previous_pid,
        "benchmark prover process did not restart"
    );
    println!("BENCH_PROVER port={port} previous_pid={previous_pid} pid={pid} fresh=true");
    Ok(())
}

pub fn deposit_notes(
    rpc: &mut SolanaRpc,
    payer: &Keypair,
    tree: Pubkey,
    owner: [u8; 32],
    count: usize,
    interleaved: bool,
) -> Result<Vec<DepositOutput>> {
    let stride = if interleaved { 2 } else { 1 };
    let leaves = count * stride;
    rpc.airdrop(&payer.pubkey(), (leaves as u64 + 10) * NOTE_AMOUNT)?;
    let decoy = Poseidon::hashv(&[&owner, &[1; 32]])?;
    let mut notes = Vec::with_capacity(count);
    for start in (0..leaves).step_by(32) {
        let end = (start + 32).min(leaves);
        let mut instructions = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        for batch in (start..end).step_by(8) {
            let deposits = (batch..(batch + 8).min(end))
                .map(|index| {
                    ZolanaProgramTest::sol_shield_data(
                        NOTE_AMOUNT,
                        if index % stride == 0 { owner } else { decoy },
                    )
                })
                .collect();
            instructions.push(
                Deposit {
                    tree,
                    depositor: payer.pubkey(),
                    deposits,
                }
                .instruction()?,
            );
        }
        let signature = send_transaction(rpc, &instructions, &payer.pubkey(), &[payer])?;
        let groups = rpc.fetch_confirmed_instruction_groups(&signature)?;
        let events = indexed_events_from_instruction_groups(
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            &groups.groups,
        );
        let mut index = start;
        for event in &events {
            for note in deposit_outputs_from_event(event)? {
                if index % stride == 0 {
                    notes.push(note);
                }
                index += 1;
            }
        }
        ensure!(index == end, "deposit event count mismatch");
    }
    ensure!(
        notes.len() == count,
        "expected {count} deposits, got {}",
        notes.len()
    );
    Ok(notes)
}
