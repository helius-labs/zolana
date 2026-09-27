#![cfg(feature = "external-tools")]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

use super::{artifacts, locked, path, WorkDir};

const PTAU_POWER: &str = "4";

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

pub fn throwaway_ptau() -> PathBuf {
    let dir = artifacts().join("snarkjs");
    let ptau = dir.join(format!("throwaway_{PTAU_POWER}_final.ptau"));
    let _lock = locked(&dir);
    if ptau.exists() {
        return ptau;
    }
    let initial = dir.join("throwaway_0000.ptau");
    let contributed = dir.join("throwaway_0001.ptau");
    let prepared = dir.join("throwaway_prepared.ptau");
    run(&["powersoftau", "new", "bn128", PTAU_POWER, path(&initial)]);
    run(&[
        "powersoftau",
        "contribute",
        path(&initial),
        path(&contributed),
        "--name=throwaway",
        "-e=zk-program-sdk throwaway phase 1",
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

pub fn groth16(work: &WorkDir, r1cs: &Path, wtns: &Path) -> (bool, Value) {
    let ptau = throwaway_ptau();
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
