use std::{
    any::type_name,
    collections::BTreeMap,
    env, fs,
    sync::{Mutex, PoisonError},
    thread,
    time::Instant,
};

use zk_program_sdk::{Groth16Prover, ProofResult, ZkProgram};

const ENABLED_BY: &str = "ZK_PROGRAM_SDK_BENCHMARK";
const OUTPUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/scenarios/BENCHMARK.md");
const HEADER: &str = "# ZK Program SDK -- Scenario Benchmark

Constraints and proving time for every proof the scenario tests generate. \
**Constraints** is the circuit's R1CS constraint count, taken from the same synthesis \
its proving key is generated from. **Proof time** is the wall time of \
`Groth16Prover::prove`, which runs the circuit natively, checks that the constraints \
are satisfied, creates the Groth16 proof and verifies it once.

Regenerate with `just bench-zk-program-sdk`. It runs a release build one test at a time, so \
each proof has every core for its parallel proving.

| Test | Circuit | Proof | Constraints | Proof time |
| ---- | ------- | ----- | ----------: | ---------: |
";

struct Row {
    circuit: String,
    proof: &'static str,
    constraints: usize,
    prove_ms: u128,
}

static ROWS: Mutex<BTreeMap<String, Vec<Row>>> = Mutex::new(BTreeMap::new());

pub fn prove<P: ZkProgram>(
    prover: &Groth16Prover<P>,
    proof_inputs: &P,
    proof: &'static str,
) -> ProofResult {
    let start = Instant::now();
    let result = prover.prove(proof_inputs).expect(proof);
    let prove_ms = start.elapsed().as_millis();
    if env::var_os(ENABLED_BY).is_some() {
        record(Row {
            circuit: circuit_name::<P>(),
            proof: proof.strip_suffix(" proof").unwrap_or(proof),
            constraints: prover.constraint_count().expect("constraint count"),
            prove_ms,
        });
    }
    result
}

fn record(row: Row) {
    let test = thread::current().name().unwrap_or("unnamed").to_string();
    let mut rows = ROWS.lock().unwrap_or_else(PoisonError::into_inner);
    rows.entry(test).or_default().push(row);
    fs::write(OUTPUT_PATH, render(&rows)).expect("write BENCHMARK.md");
}

fn render(rows: &BTreeMap<String, Vec<Row>>) -> String {
    let mut markdown = String::from(HEADER);
    for (test, runs) in rows {
        for row in runs {
            markdown.push_str(&format!(
                "| `{test}` | `{}` | {} | {} | {} ms |\n",
                row.circuit,
                row.proof,
                grouped(row.constraints),
                row.prove_ms
            ));
        }
    }
    markdown
}

fn circuit_name<P>() -> String {
    let full = type_name::<P>();
    let (path, generics) = full.split_at(full.find('<').unwrap_or(full.len()));
    let name = path.rsplit("::").next().unwrap_or(path);
    format!("{name}{generics}")
}

fn grouped(value: usize) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}
