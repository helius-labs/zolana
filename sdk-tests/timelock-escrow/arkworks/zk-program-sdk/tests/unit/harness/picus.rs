//! Runs [Picus](https://github.com/Veridise/Picus) on the SDK's
//! `export_picus_r1cs` files. Picus reports whether every output wire is
//! fixed once the inputs are: exit code 8 is safe, 9 unsafe (it found two
//! witnesses that differ on an output), 0 unknown (the solver timed out).
//!
//! Setup, known to work on macOS arm64 with Picus 138b151 and cvc5 1.4.1:
//!
//! - Racket 8+: `brew install minimal-racket`.
//! - Picus: `git clone https://github.com/Veridise/Picus`, then
//!   `raco pkg install --auto --batch` and `raco make picus.rkt` in the clone.
//! - `run-picus` on `PATH`: a wrapper script that `exec`s
//!   `<clone>/run-picus "$@"`. A symlink does not work, since the script finds
//!   `picus.rkt` next to its own path.
//! - cvc5 with finite-field support on `PATH` as `cvc5`: the release asset
//!   `cvc5-macOS-arm64-static-gpl.zip` (or the Linux `-static-gpl` one). Only
//!   the GPL builds link CoCoA, the library behind finite-field solving;
//!   `cvc5 --show-config` must print `cocoa : yes`. Homebrew has no cvc5.
//!
//! cvc5 is the solver because it reasons over the prime field. Z3 has no field
//! theory: it handles linear rows such as additions but stalls on products,
//! inverses and bit decompositions. Picus's default query timeout is 5000 ms.
//!
//! By hand: `run-picus --solver cvc5 --timeout 5000 circuit.r1cs`. Each wire's
//! label in the file is its arkworks variable index, so a wire in an unsafe
//! counterexample maps back to its `CircuitLabel`. Picus scales to gadgets, not
//! whole programs: a single Poseidon proves in seconds, while a chain of three
//! or the escrow circuit's 13,777 rows did not finish in minutes.

#![cfg(feature = "external-tools")]

use std::{
    fs::File,
    os::unix::process::CommandExt,
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use super::{
    circom::Compiled,
    iden3::{read_r1cs, write_r1cs, R1cs},
    path, WorkDir,
};

const SOLVER: &str = "cvc5";
const POLL: Duration = Duration::from_millis(50);

/// The wall-clock limit of one `run-picus` call unless a test sets its own.
pub const DEFAULT_LIMIT: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Safe,
    Unsafe,
    Unknown,
}

pub fn verdict(work: &WorkDir, name: &str, r1cs: &[u8]) -> Verdict {
    verdict_within(work, name, r1cs, DEFAULT_LIMIT)
}

/// Like [`verdict`], but a run that outlasts `limit` is killed and reported
/// as `Unknown`, the verdict Picus gives when its solver times out.
pub fn verdict_within(work: &WorkDir, name: &str, r1cs: &[u8], limit: Duration) -> Verdict {
    run(name, &work.write(&format!("{name}.r1cs"), r1cs), limit)
}

/// Picus on a compiled circom reference, with its `.sym` beside the `.r1cs`
/// so a counterexample names circom's signals. The targets are circom's
/// `signal output`s; to target private inputs, [`promote_all`] the bytes of
/// `compiled.r1cs` and pass them to [`verdict_within`].
pub fn circom_verdict(work: &WorkDir, name: &str, compiled: &Compiled, limit: Duration) -> Verdict {
    let r1cs = work.join(&format!("{name}.r1cs"));
    std::fs::copy(&compiled.r1cs, &r1cs).expect("circom r1cs copy");
    std::fs::copy(&compiled.sym, work.join(&format!("{name}.sym"))).expect("circom sym copy");
    run(name, &r1cs, limit)
}

// Picus runs as racket under a bash wrapper, with cvc5 below it: a timeout
// kills the whole process group. Its output goes to files, not pipes, so a
// long log cannot block it while the harness polls.
fn run(name: &str, r1cs: &Path, limit: Duration) -> Verdict {
    let log = |stream: &str| r1cs.with_extension(format!("picus.{stream}"));
    let (stdout, stderr) = (log("stdout"), log("stderr"));
    let mut child = Command::new("run-picus")
        .args(["--solver", SOLVER, path(r1cs)])
        .stdout(File::create(&stdout).expect("picus stdout"))
        .stderr(File::create(&stderr).expect("picus stderr"))
        .process_group(0)
        .spawn()
        .expect("run-picus on PATH");
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().expect("run-picus status") {
            break status;
        }
        if Instant::now() >= deadline {
            let group = format!("-{}", child.id());
            let _ = Command::new("kill").args(["-KILL", &group]).status();
            let _ = child.wait();
            return Verdict::Unknown;
        }
        thread::sleep(POLL);
    };
    match status.code() {
        Some(8) => Verdict::Safe,
        Some(9) => Verdict::Unsafe,
        Some(0) => Verdict::Unknown,
        code => panic!(
            "run-picus {name} failed with {code:?}:\n{}\n{}",
            std::fs::read_to_string(&stdout).unwrap_or_default(),
            std::fs::read_to_string(&stderr).unwrap_or_default()
        ),
    }
}

/// The wire of an `export_picus_r1cs` file that holds `variable`, a wire of
/// the `export_r1cs` file and the exported assignment. The two orders differ
/// once a gadget allocates a witness: the Picus export puts gadget witnesses
/// first as outputs and inverse hints last.
pub fn picus_wire(picus_r1cs: &[u8], variable: usize) -> usize {
    let label = u64::try_from(variable).expect("variable label");
    read_r1cs(picus_r1cs)
        .wire_labels
        .iter()
        .position(|wire_label| *wire_label == label)
        .expect("a wire labelled with the variable")
}

/// Promotes every wire of `wires` to an output, as [`promote`] does for one;
/// the wires are numbered as in `r1cs`.
pub fn promote_all(r1cs: &[u8], wires: &[usize]) -> Vec<u8> {
    let mut sorted = wires.to_vec();
    sorted.sort_unstable();
    sorted
        .into_iter()
        .fold(r1cs.to_vec(), |promoted, wire| promote(&promoted, wire))
}

/// Moves the private input at `wire` to the end of the outputs, so Picus asks
/// whether the remaining inputs fix it.
pub fn promote(r1cs: &[u8], wire: usize) -> Vec<u8> {
    let R1cs {
        mut header,
        a,
        b,
        c,
        wire_labels,
    } = read_r1cs(r1cs);
    let first_output = 1;
    let promoted = first_output + header.public_outputs;
    let first_private = promoted + header.public_inputs;
    assert!(
        (first_private..first_private + header.private_inputs).contains(&wire),
        "wire {wire} is not a private input"
    );
    let new_wire = |old: usize| match old {
        old if old == wire => promoted,
        old if (promoted..wire).contains(&old) => old + 1,
        old => old,
    };
    let remap = |rows: Vec<Vec<_>>| {
        rows.into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|(coefficient, old)| (coefficient, new_wire(old)))
                    .collect()
            })
            .collect()
    };
    let mut labels = wire_labels.clone();
    for (old, label) in wire_labels.into_iter().enumerate() {
        labels[new_wire(old)] = label;
    }
    header.public_outputs += 1;
    header.private_inputs -= 1;
    write_r1cs(&R1cs {
        header,
        a: remap(a),
        b: remap(b),
        c: remap(c),
        wire_labels: labels,
    })
}
