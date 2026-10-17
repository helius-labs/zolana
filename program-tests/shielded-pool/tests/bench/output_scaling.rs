//! Output-scaling sweep: wide `transact` shapes run directly and through the
//! test batch program, with real proofs, the smallest heap each needs, the
//! batch write transactions, and probes of the CPI instruction-data cap.

use std::fmt::Write as _;

use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig},
};
use mollusk_svm::{program::loader_keys::LOADER_V3, result::InstructionResult, Mollusk};
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

use shielded_pool_tests::support::batch::{
    fill_batch, load_batch_program, send_v1_traced, transact_instruction, v1_size, ProvenSpend,
    ScalingSpend, SentTransaction, SettleBatch, SplitTransact, BATCH_PROGRAM_ID,
    BATCH_PROGRAM_PATH, MAX_HEAP_BYTES,
};

use shielded_pool_tests::support::{
    batch_ring::{ring_transact_instruction, RingScalingSpend},
    ring::RingRail,
};

/// A ring program's transaction-level digest: ring rails are sized with it
/// present, the larger of the two encodings.
const RING_DATA_HASH: [u8; 32] = [0x11; 32];

use super::{
    bench_setup, mollusk_program_account, snapshot_account, to_mollusk_instruction,
    transact_accounts, PLAIN_PROGRAM_PATH, PROFILING_SBF_DIR,
};

const MIN_HEAP_KIB: u32 = 32;
const MAX_HEAP_KIB: u32 = MAX_HEAP_BYTES / 1024;
const MAX_CPI_INSTRUCTION_DATA_LEN: usize = 10 * 1024;

fn run_at_heap(
    mollusk: &mut Mollusk,
    ix: &Instruction,
    accounts: &[(Pubkey, Account)],
    heap_kib: u32,
) -> InstructionResult {
    mollusk.compute_budget.heap_size = heap_kib * 1024;
    let result = mollusk.process_instruction(ix, accounts);
    take_profiling_entries();
    result
}

/// The smallest heap (KiB) the instruction succeeds with, or the failure at
/// the largest heap a transaction can request.
fn min_heap_kib(
    mollusk: &mut Mollusk,
    ix: &Instruction,
    accounts: &[(Pubkey, Account)],
) -> Result<u32, InstructionResult> {
    let at_max = run_at_heap(mollusk, ix, accounts, MAX_HEAP_KIB);
    if at_max.program_result.is_err() {
        return Err(at_max);
    }
    let (mut failing, mut passing) = (MIN_HEAP_KIB - 1, MAX_HEAP_KIB);
    while passing - failing > 1 {
        let mid = (failing + passing) / 2;
        if run_at_heap(mollusk, ix, accounts, mid)
            .program_result
            .is_ok()
        {
            passing = mid;
        } else {
            failing = mid;
        }
    }
    Ok(passing)
}

struct Measured {
    heap_kib: u32,
    cu: u64,
}

fn measure(
    mollusk: &mut Mollusk,
    ix: &Instruction,
    accounts: &[(Pubkey, Account)],
    name: &str,
    bench: &mut CuBenchmark,
) -> Result<Measured, String> {
    let heap_kib = min_heap_kib(mollusk, ix, accounts)
        .map_err(|failure| format!("{:?} / {:?}", failure.program_result, failure.raw_result))?;
    mollusk.compute_budget.heap_size = heap_kib * 1024;
    let result = mollusk.process_instruction(ix, accounts);
    let entries = take_profiling_entries();
    assert!(result.program_result.is_ok(), "{name} at its probed heap");
    assert!(!entries.is_empty(), "no profiling entries for '{name}'");
    bench.add_from_entries(name, entries);
    Ok(Measured {
        heap_kib,
        cu: result.compute_units_consumed,
    })
}

fn dedup_accounts(accounts: Vec<(Pubkey, Account)>) -> Vec<(Pubkey, Account)> {
    let mut unique: Vec<(Pubkey, Account)> = Vec::with_capacity(accounts.len());
    for (key, account) in accounts {
        if !unique.iter().any(|(seen, _)| *seen == key) {
            unique.push((key, account));
        }
    }
    unique
}

fn scaling_mollusk() -> Mollusk {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&program_id, "shielded_pool_program");
    let batch_elf = std::fs::read(BATCH_PROGRAM_PATH).expect("build spp-batch-program first");
    mollusk.add_program_with_loader_and_elf(&BATCH_PROGRAM_ID, &LOADER_V3, &batch_elf);
    mollusk
}

struct ShapeRow {
    shape: String,
    cpi_data_len: usize,
    direct: Option<Result<Measured, String>>,
    settle: Result<Measured, String>,
    litesvm: Result<SentTransaction, String>,
    settle_tx_bytes: usize,
    settle_tx_addresses: usize,
    direct_tx_bytes: usize,
    direct_tx_addresses: usize,
    write_transactions: usize,
    batch_account_bytes: usize,
    prove_first_secs: f64,
    prove_second_secs: f64,
}

/// One entry of `SPP_BENCH_BATCH_SHAPES` / `SPP_BENCH_PROBE_SHAPES`:
/// `<inputs>x<outputs>` or `<inputs>x<outputs>/<sent inputs>x<sent outputs>`,
/// the latter a shape whose trailing slots are compact padding.
#[derive(Clone, Copy)]
struct ShapeSpec {
    rail: Option<RingRail>,
    n_inputs: usize,
    n_outputs: usize,
    sent_inputs: usize,
    sent_outputs: usize,
}

fn shape_specs_from_env(name: &str) -> Vec<ShapeSpec> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .filter(|entry| !entry.trim().is_empty())
        .map(|entry| {
            let parse = |shape: &str| -> (usize, usize) {
                let (n_inputs, n_outputs) = shape
                    .split_once('x')
                    .unwrap_or_else(|| panic!("shape {entry} is not <inputs>x<outputs>"));
                (
                    n_inputs.parse().expect("input count"),
                    n_outputs.parse().expect("output count"),
                )
            };
            let (rail, entry) = match entry.trim().split_once(':') {
                Some(("ring", rest)) => (Some(RingRail::Eddsa), rest),
                Some(("p256", rest)) => (Some(RingRail::P256), rest),
                Some((rail, _)) => panic!("unknown rail {rail}"),
                None => (None, entry.trim()),
            };
            let (shape, sent) = match entry.split_once('/') {
                Some((shape, sent)) => (parse(shape), parse(sent)),
                None => (parse(entry), parse(entry)),
            };
            ShapeSpec {
                rail,
                n_inputs: shape.0,
                n_outputs: shape.1,
                sent_inputs: sent.0,
                sent_outputs: sent.1,
            }
        })
        .collect()
}

fn run_shape(
    mollusk: &mut Mollusk,
    spec: &ShapeSpec,
    prove: bool,
    bench: &mut CuBenchmark,
) -> ShapeRow {
    let ShapeSpec {
        rail,
        n_inputs,
        n_outputs,
        sent_inputs,
        sent_outputs,
    } = *spec;
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let (mut pt, _authority, tree, tree_id) = bench_setup();
    load_batch_program(&mut pt).expect("load batch program");
    mollusk.warp_to_slot(pt.svm.get_sysvar::<Clock>().slot);
    let authority = pt.payer.insecure_clone();
    let rail_label = rail.map_or("confidential", RingRail::label);
    let shape = if (sent_inputs, sent_outputs) == (n_inputs, n_outputs) {
        format!("{rail_label} {n_inputs}x{n_outputs}")
    } else {
        format!("{rail_label} {n_inputs}x{n_outputs} (sent {sent_inputs}x{sent_outputs})")
    };
    let spend = match rail {
        None => ScalingSpend {
            n_inputs,
            n_outputs,
            sent_inputs,
            sent_outputs,
            prove,
        }
        .build(&pt, tree, tree_id),
        Some(rail) => RingScalingSpend {
            rail,
            n_inputs,
            n_outputs,
            sent_inputs,
            sent_outputs,
            ring_data_hash: Some(RING_DATA_HASH),
            allow_dummy_inputs: true,
            prove,
        }
        .build(&mut pt, tree, tree_id),
    };
    let ProvenSpend { data, timing } =
        spend.unwrap_or_else(|error| panic!("{shape} spend: {error}"));
    let split = SplitTransact::new(&data).expect("split transact data");

    let (direct_ix, transact) = match rail {
        None => {
            let ix = transact_instruction(authority.pubkey(), tree, data);
            (ix.clone(), ix)
        }
        Some(_) => (
            ring_transact_instruction(authority.pubkey(), tree, data.clone(), true),
            ring_transact_instruction(authority.pubkey(), tree, data, false),
        ),
    };
    let direct_size = v1_size(
        &authority.pubkey(),
        std::slice::from_ref(&transact),
        Some(MAX_HEAP_BYTES),
    )
    .expect("direct size");
    let direct_accounts = transact_accounts(&pt, &direct_ix, &program_id, None);
    let direct = (prove && std::env::var_os("SPP_BENCH_DIRECT").is_some()).then(|| {
        measure(
            mollusk,
            &to_mollusk_instruction(&direct_ix),
            &direct_accounts,
            &format!("direct transact {shape}"),
            bench,
        )
    });

    let fill = fill_batch(&mut pt, &authority, 1, &split, usize::MAX)
        .unwrap_or_else(|error| panic!("{shape} fill batch: {error}"));
    let settle = SettleBatch {
        authority: authority.pubkey(),
        batch: fill.batch,
        transact: &transact,
        split: &split,
    }
    .instruction()
    .expect("settle instruction");
    let mut settle_accounts = vec![
        snapshot_account(&pt, &authority.pubkey()),
        snapshot_account(&pt, &fill.batch),
        mollusk_program_account(&program_id),
        mollusk_program_account(&BATCH_PROGRAM_ID),
    ];
    settle_accounts.extend(direct_accounts);
    let settle_accounts = dedup_accounts(settle_accounts);
    let settle_ix = to_mollusk_instruction(&settle);
    let measured = if prove {
        measure(
            mollusk,
            &settle_ix,
            &settle_accounts,
            &format!("batch settle {shape}"),
            bench,
        )
    } else {
        let failure = run_at_heap(mollusk, &settle_ix, &settle_accounts, MAX_HEAP_KIB);
        Err(format!(
            "{:?} / {:?} after {} CU",
            failure.program_result, failure.raw_result, failure.compute_units_consumed
        ))
    };
    let heap_bytes = match &measured {
        Ok(measured) => measured.heap_kib * 1024,
        Err(_) => MAX_HEAP_BYTES,
    };
    let settle_size = v1_size(
        &authority.pubkey(),
        std::slice::from_ref(&settle),
        Some(heap_bytes),
    )
    .expect("settle size");
    let litesvm =
        send_v1_traced(&mut pt, &authority, &[settle], Some(heap_bytes)).map_err(|error| {
            let text = error.to_string();
            let first = text.lines().next().unwrap_or_default().to_owned();
            let reason = text
                .lines()
                .rev()
                .find(|line| line.contains("failed") || line.contains("too large"))
                .unwrap_or_default();
            format!("{first} {reason}")
        });
    ShapeRow {
        shape,
        cpi_data_len: split.cpi_data_len(),
        direct,
        settle: measured,
        litesvm,
        settle_tx_bytes: settle_size.bytes,
        settle_tx_addresses: settle_size.addresses,
        direct_tx_bytes: direct_size.bytes,
        direct_tx_addresses: direct_size.addresses,
        write_transactions: fill.write_transactions,
        batch_account_bytes: fill.account_bytes,
        prove_first_secs: timing.as_ref().map_or(0.0, |timing| timing.first_secs),
        prove_second_secs: timing.as_ref().map_or(0.0, |timing| timing.second_secs),
    }
}

fn cell(measured: &Result<Measured, String>) -> (String, String) {
    match measured {
        Ok(measured) => (measured.cu.to_string(), measured.heap_kib.to_string()),
        Err(error) => (format!("fails: {error}"), "-".to_owned()),
    }
}

/// The most inline outputs a direct `transact` carries in one 4,096-byte v1
/// transaction (settling in place), next to the batch path's CPI data cap.
#[test]
#[ignore]
fn in_place_output_capacity() {
    let (pt, _authority, tree, tree_id) = bench_setup();
    let payer = pt.payer.pubkey();
    for n_inputs in [1usize, 16, 49] {
        let fits = |n_outputs: usize| {
            let ProvenSpend { data, .. } = ScalingSpend {
                n_inputs,
                n_outputs,
                sent_inputs: n_inputs,
                sent_outputs: n_outputs,
                prove: false,
            }
            .build(&pt, tree, tree_id)
            .expect("spend");
            let ix = transact_instruction(payer, tree, data);
            let size = v1_size(&payer, &[ix], Some(MAX_HEAP_BYTES)).expect("size");
            (size.fits(), size.bytes, size.addresses)
        };
        let (mut fitting, mut failing) = (1usize, 255usize);
        while failing - fitting > 1 {
            let mid = (fitting + failing) / 2;
            if fits(mid).0 {
                fitting = mid;
            } else {
                failing = mid;
            }
        }
        let (_, bytes, addresses) = fits(fitting);
        let (_, over_bytes, _) = fits(fitting + 1);
        println!(
            "in place {n_inputs} inputs: max {fitting} outputs ({bytes} bytes, {addresses} \
             addresses); {} outputs need {over_bytes} bytes",
            fitting + 1
        );
    }
}

/// `SPP_BENCH_BATCH_SHAPES` are proven and measured; `SPP_BENCH_PROBE_SHAPES`
/// are built without a proof and only settled, to locate the CPI data cap.
/// `SPP_BENCH_DIRECT` adds the direct `transact` profile of proven shapes.
#[test]
#[ignore]
fn bench_cu_batch_settlement() {
    std::env::set_var("SHIELDED_POOL_PROGRAM_PATH", PLAIN_PROGRAM_PATH);
    let mut mollusk = scaling_mollusk();
    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "Shielded Pool -- batch settlement CU benchmark".into(),
        description: "Wide transact shapes with one distinct owner per output, settled through \
                      the test batch program's settle CPI (inputs and outputs read from the \
                      batch account), each at the smallest heap it succeeds with."
            .into(),
        output_path: concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/CU_BENCHMARK_BATCH_SETTLEMENT.md"
        )
        .into(),
        regenerate_command: Some(
            "SPP_BENCH_BATCH_SHAPES=4x64 cargo test -p shielded-pool-tests --features proofs \
             --test bench_cu bench_cu_batch_settlement -- --ignored --nocapture"
                .into(),
        ),
        ..Default::default()
    });

    let mut rows = Vec::new();
    for spec in shape_specs_from_env("SPP_BENCH_BATCH_SHAPES") {
        let row = run_shape(&mut mollusk, &spec, true, &mut bench);
        println!("{}", summary_row(&row));
        rows.push(row);
    }
    for spec in shape_specs_from_env("SPP_BENCH_PROBE_SHAPES") {
        let row = run_shape(&mut mollusk, &spec, false, &mut bench);
        println!("{}", summary_row(&row));
        rows.push(row);
    }

    let mut summary = String::from(
        "| shape | CPI data bytes | settle CU (mollusk) | heap KiB | settle CU (LiteSVM v1 tx) | \
         trace entries | settle tx bytes | addresses | write txs | batch account bytes | \
         prove s (first) | prove s (second) | direct CU | direct heap KiB | top-level tx bytes / addresses |\n\
         | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for row in &rows {
        summary.push_str(&summary_row(row));
        summary.push('\n');
    }
    println!("{summary}");
    let summary_path = std::env::var("SPP_BENCH_SUMMARY_PATH").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/OUTPUT_SCALING_SUMMARY.md").to_owned()
    });
    std::fs::write(summary_path, &summary).expect("write summary");
    if !shape_specs_from_env("SPP_BENCH_BATCH_SHAPES").is_empty() {
        bench
            .generate()
            .expect("write CU_BENCHMARK_BATCH_SETTLEMENT.md");
    }
}

fn summary_row(row: &ShapeRow) -> String {
    let (settle_cu, settle_heap) = cell(&row.settle);
    let (direct_cu, direct_heap) = row
        .direct
        .as_ref()
        .map_or(("-".to_owned(), "-".to_owned()), cell);
    let (litesvm_cu, trace) = match &row.litesvm {
        Ok(sent) => (
            sent.compute_units.to_string(),
            sent.trace_entries.to_string(),
        ),
        Err(error) => (format!("fails: {error}"), "-".to_owned()),
    };
    let over_cap = if row.cpi_data_len > MAX_CPI_INSTRUCTION_DATA_LEN {
        " (over cap)"
    } else {
        ""
    };
    let mut line = String::new();
    write!(
        line,
        "| {} | {}{} | {} | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {} | {} | {} / {} |",
        row.shape,
        row.cpi_data_len,
        over_cap,
        settle_cu,
        settle_heap,
        litesvm_cu,
        trace,
        row.settle_tx_bytes,
        row.settle_tx_addresses,
        row.write_transactions,
        row.batch_account_bytes,
        row.prove_first_secs,
        row.prove_second_secs,
        direct_cu,
        direct_heap,
        row.direct_tx_bytes,
        row.direct_tx_addresses,
    )
    .expect("format row");
    line
}
