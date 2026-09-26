use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};
use zk_program_sdk::ZkProgram;

pub(crate) const PTAU_POWER: &str = "14";

pub(crate) struct Ceremony {
    pub(crate) dir: PathBuf,
    pub(crate) ptau: PathBuf,
}

impl Ceremony {
    pub(crate) fn r1cs(&self) -> PathBuf {
        self.dir.join("circuit.r1cs")
    }

    pub(crate) fn initial_zkey(&self) -> PathBuf {
        self.dir.join("circuit_0000.zkey")
    }

    pub(crate) fn final_zkey(&self) -> PathBuf {
        self.dir.join("circuit_final.zkey")
    }

    pub(crate) fn verification_key(&self) -> PathBuf {
        self.dir.join("verification_key.json")
    }
}

pub(crate) fn snarkjs_dir() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("snarkjs")
}

pub(crate) fn snarkjs_output(args: &[&str]) -> (bool, String) {
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

pub(crate) fn run_snarkjs(args: &[&str]) -> bool {
    snarkjs_output(args).0
}

pub(crate) fn snarkjs(args: &[&str]) {
    let (success, log) = snarkjs_output(args);
    assert!(success, "snarkjs {args:?} failed:\n{log}");
}

pub(crate) fn path(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

pub(crate) fn locked(dir: &Path) -> File {
    std::fs::create_dir_all(dir).expect("ceremony directory");
    let lock = File::create(dir.join(".lock")).expect("lock file");
    lock.lock().expect("ceremony lock");
    lock
}

pub(crate) fn throwaway_ptau() -> PathBuf {
    let dir = snarkjs_dir();
    let ptau = dir.join(format!("throwaway_{PTAU_POWER}_final.ptau"));
    let _lock = locked(&dir);
    if ptau.exists() {
        return ptau;
    }
    let initial = dir.join("throwaway_0000.ptau");
    let contributed = dir.join("throwaway_0001.ptau");
    let prepared = dir.join("throwaway_prepared.ptau");
    snarkjs(&["powersoftau", "new", "bn128", PTAU_POWER, path(&initial)]);
    snarkjs(&[
        "powersoftau",
        "contribute",
        path(&initial),
        path(&contributed),
        "--name=throwaway",
        "-e=zolana throwaway phase 1",
    ]);
    snarkjs(&[
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

pub(crate) fn ceremony<P: ZkProgram>(name: &str) -> Ceremony {
    let ptau = throwaway_ptau();
    let r1cs = P::export_r1cs().expect("r1cs export");
    let digest = hex::encode(Sha256::digest(&r1cs));
    let ceremony = Ceremony {
        dir: snarkjs_dir().join(format!("{name}-{}", digest.get(..16).expect("digest"))),
        ptau,
    };
    let _lock = locked(&ceremony.dir);
    if ceremony.final_zkey().exists() {
        return ceremony;
    }
    std::fs::write(ceremony.r1cs(), &r1cs).expect("r1cs file");
    let contributed = ceremony.dir.join("circuit_0001.zkey");
    let beacon = ceremony.dir.join("circuit_beacon.zkey");
    snarkjs(&[
        "groth16",
        "setup",
        path(&ceremony.r1cs()),
        path(&ceremony.ptau),
        path(&ceremony.initial_zkey()),
    ]);
    snarkjs(&[
        "zkey",
        "contribute",
        path(&ceremony.initial_zkey()),
        path(&contributed),
        "--name=throwaway",
        "-e=zolana throwaway phase 2",
    ]);
    snarkjs(&[
        "zkey",
        "beacon",
        path(&contributed),
        path(&beacon),
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "10",
        "-n=throwaway beacon",
    ]);
    snarkjs(&[
        "zkey",
        "verify",
        path(&ceremony.r1cs()),
        path(&ceremony.ptau),
        path(&beacon),
    ]);
    snarkjs(&[
        "zkey",
        "export",
        "verificationkey",
        path(&beacon),
        path(&ceremony.verification_key()),
    ]);
    std::fs::rename(&beacon, ceremony.final_zkey()).expect("final zkey");
    std::fs::remove_file(contributed).expect("intermediate zkey");
    ceremony
}
