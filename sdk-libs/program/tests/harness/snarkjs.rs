#![cfg(feature = "external-tools")]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

use super::{
    artifacts,
    iden3::{read_r1cs, R1csHeader},
    locked, path, WorkDir,
};

const MIN_PTAU_POWER: u32 = 4;

pub fn output(args: &[&str]) -> (bool, String) {
    let output = Command::new("snarkjs")
        .args(args)
        .output()
        .expect("snarkjs on PATH");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success() && !log.contains("[ERROR]"), log)
}

pub fn run(args: &[&str]) {
    let (success, log) = output(args);
    assert!(success, "snarkjs {args:?} failed:\n{log}");
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WtnsCheck {
    Accepted,
    Rejected,
    Failed(String),
}

pub fn wtns_check(r1cs: &Path, wtns: &Path) -> WtnsCheck {
    let (success, log) = output(&["wtns", "check", path(r1cs), path(wtns)]);
    if log.contains("[ERROR]") {
        WtnsCheck::Failed(log)
    } else if success && log.contains("WITNESS IS CORRECT") {
        WtnsCheck::Accepted
    } else if !success && log.contains("WITNESS IS NOT CORRECT") {
        WtnsCheck::Rejected
    } else {
        WtnsCheck::Failed(log)
    }
}

/// The smallest power (at least 4) whose ptau `groth16 setup` accepts for
/// this header: snarkjs needs 2^power > constraints + public inputs + public
/// outputs.
pub fn ptau_power(header: &R1csHeader) -> u32 {
    let rows = header.constraints + header.public_inputs + header.public_outputs;
    (usize::BITS - rows.leading_zeros()).max(MIN_PTAU_POWER)
}

/// A throwaway phase-1 ptau of 2^power, created once per power and cached.
pub fn throwaway_ptau(power: u32) -> PathBuf {
    let dir = artifacts().join("snarkjs");
    let ptau = dir.join(format!("throwaway_{power}_final.ptau"));
    let _lock = locked(&dir);
    if ptau.exists() {
        return ptau;
    }
    let initial = dir.join(format!("throwaway_{power}_0000.ptau"));
    let contributed = dir.join(format!("throwaway_{power}_0001.ptau"));
    let prepared = dir.join(format!("throwaway_{power}_prepared.ptau"));
    run(&[
        "powersoftau",
        "new",
        "bn128",
        &power.to_string(),
        path(&initial),
    ]);
    run(&[
        "powersoftau",
        "contribute",
        path(&initial),
        path(&contributed),
        "--name=throwaway",
        "-e=zolana-program throwaway phase 1",
    ]);
    run(&[
        "powersoftau",
        "prepare",
        "phase2",
        path(&contributed),
        path(&prepared),
    ]);
    std::fs::rename(&prepared, &ptau).expect("ptau");
    for intermediate in [initial, contributed] {
        std::fs::remove_file(intermediate).expect("intermediate ptau");
    }
    ptau
}

/// Groth16 setup, prove and verify over the throwaway ptau of the smallest
/// power the circuit fits.
pub fn groth16(work: &WorkDir, r1cs: &Path, wtns: &Path) -> (bool, Value) {
    let header = read_r1cs(&std::fs::read(r1cs).expect("r1cs")).header;
    let ptau = throwaway_ptau(ptau_power(&header));
    let zkey = work.join("circuit.zkey");
    let verification_key = work.join("verification_key.json");
    let proof = work.join("proof.json");
    let public = work.join("public.json");
    run(&["groth16", "setup", path(r1cs), path(&ptau), path(&zkey)]);
    run(&[
        "zkey",
        "export",
        "verificationkey",
        path(&zkey),
        path(&verification_key),
    ]);
    run(&[
        "groth16",
        "prove",
        path(&zkey),
        path(wtns),
        path(&proof),
        path(&public),
    ]);
    let (verified, _) = output(&[
        "groth16",
        "verify",
        path(&verification_key),
        path(&public),
        path(&proof),
    ]);
    let public = std::fs::read_to_string(&public).expect("public json");
    (
        verified,
        serde_json::from_str(&public).expect("public signals"),
    )
}
