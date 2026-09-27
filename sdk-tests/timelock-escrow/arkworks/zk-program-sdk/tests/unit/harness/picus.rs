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

use std::process::Command;

use super::{
    iden3::{read_r1cs, write_r1cs, R1cs},
    path, WorkDir,
};

const SOLVER: &str = "cvc5";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Safe,
    Unsafe,
    Unknown,
}

pub fn verdict(work: &WorkDir, name: &str, r1cs: &[u8]) -> Verdict {
    let r1cs = work.write(&format!("{name}.r1cs"), r1cs);
    let output = Command::new("run-picus")
        .args(["--solver", SOLVER, path(&r1cs)])
        .output()
        .expect("run-picus on PATH");
    match output.status.code() {
        Some(8) => Verdict::Safe,
        Some(9) => Verdict::Unsafe,
        Some(0) => Verdict::Unknown,
        code => panic!(
            "run-picus {name} failed with {code:?}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    }
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
