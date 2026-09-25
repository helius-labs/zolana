use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use timelock_escrow_arkworks::{Escrow, Withdraw};
use zk_program_sdk::{
    Groth16Keys, Groth16Prover, ProofResult, RelationError, SetupKind, SolanaProof,
    VerifyingKeyExport, ZkProgram,
};

mod iden3;
mod programs;
mod shared;

const PTAU_POWER: &str = "14";

struct Ceremony {
    dir: PathBuf,
    ptau: PathBuf,
}

impl Ceremony {
    fn r1cs(&self) -> PathBuf {
        self.dir.join("circuit.r1cs")
    }

    fn initial_zkey(&self) -> PathBuf {
        self.dir.join("circuit_0000.zkey")
    }

    fn final_zkey(&self) -> PathBuf {
        self.dir.join("circuit_final.zkey")
    }

    fn verification_key(&self) -> PathBuf {
        self.dir.join("verification_key.json")
    }
}

fn snarkjs_dir() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("snarkjs")
}

fn snarkjs_output(args: &[&str]) -> (bool, String) {
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

fn run_snarkjs(args: &[&str]) -> bool {
    snarkjs_output(args).0
}

fn snarkjs(args: &[&str]) {
    let (success, log) = snarkjs_output(args);
    assert!(success, "snarkjs {args:?} failed:\n{log}");
}

fn path(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

fn locked(dir: &Path) -> File {
    std::fs::create_dir_all(dir).expect("ceremony directory");
    let lock = File::create(dir.join(".lock")).expect("lock file");
    lock.lock().expect("ceremony lock");
    lock
}

fn throwaway_ptau() -> PathBuf {
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

fn ceremony<P: ZkProgram>(name: &str) -> Ceremony {
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

fn decimal<F: PrimeField>(value: &F) -> String {
    value.into_bigint().to_string()
}

fn fq_be(bytes: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(bytes)
}

fn snarkjs_proof(proof: &SolanaProof) -> Value {
    let (a_x, a_y) = proof.a.split_at(32);
    let a = -G1Affine::new(fq_be(a_x), fq_be(a_y));
    let (a_x, a_y) = a.xy().expect("proof point a");
    let (c_x, c_y) = proof.c.split_at(32);
    let b = proof.b.as_chunks::<32>().0;
    let b = |index: usize| decimal(&fq_be(b.get(index).expect("proof point b")));
    json!({
        "pi_a": [decimal(&a_x), decimal(&a_y), "1"],
        "pi_b": [[b(1), b(0)], [b(3), b(2)], ["1", "0"]],
        "pi_c": [decimal(&fq_be(c_x)), decimal(&fq_be(c_y)), "1"],
        "protocol": "groth16",
        "curve": "bn128",
    })
}

fn fq_json(proof: &Value, pointer: &str) -> Fq {
    let coordinate = proof
        .pointer(pointer)
        .and_then(Value::as_str)
        .expect("decimal coordinate");
    Fq::from_str(coordinate).expect("base field coordinate")
}

fn solana_proof(proof: &Value) -> SolanaProof {
    let be = |value: Fq| {
        let bytes = value.into_bigint().to_bytes_be();
        <[u8; 32]>::try_from(bytes).expect("32 bytes")
    };
    let a = G1Affine::new(fq_json(proof, "/pi_a/0"), fq_json(proof, "/pi_a/1"));
    let (a_x, a_y) = (-a).xy().expect("proof point a");
    let b = G2Affine::new(
        Fq2::new(fq_json(proof, "/pi_b/0/0"), fq_json(proof, "/pi_b/0/1")),
        Fq2::new(fq_json(proof, "/pi_b/1/0"), fq_json(proof, "/pi_b/1/1")),
    );
    let (b_x, b_y) = b.xy().expect("proof point b");
    let c = [fq_json(proof, "/pi_c/0"), fq_json(proof, "/pi_c/1")];
    SolanaProof {
        a: [be(a_x), be(a_y)].concat().try_into().expect("a"),
        b: [be(b_x.c1), be(b_x.c0), be(b_y.c1), be(b_y.c0)]
            .concat()
            .try_into()
            .expect("b"),
        c: c.map(be).concat().try_into().expect("c"),
    }
}

fn public_json(public_hash: [u8; 32]) -> Value {
    json!([decimal(&Fr::from_be_bytes_mod_order(&public_hash))])
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(path, value.to_string()).expect("json file");
}

fn proves_from_a_snarkjs_zkey<P: ZkProgram>(name: &str, program: &P) {
    let ceremony = ceremony::<P>(name);
    let work = WorkDir::new(name);
    let prover =
        Groth16Prover::<P>::new(Groth16Keys::load_zkey::<P>(&ceremony.final_zkey()).expect("zkey"))
            .expect("prover");
    let result: ProofResult = prover.prove(program).expect("proof");

    let wtns = work.join("witness.wtns");
    std::fs::write(&wtns, program.export_assignment().expect("assignment")).expect("wtns file");
    let witness_checks = run_snarkjs(&["wtns", "check", path(&ceremony.r1cs()), path(&wtns)]);

    let proof = work.join("rust_proof.json");
    let public = work.join("public.json");
    let tampered_public = work.join("tampered_public.json");
    write_json(&proof, &snarkjs_proof(&result.proof));
    write_json(&public, &public_json(result.public_hash));
    let mut tampered_hash = result.public_hash;
    tampered_hash[31] ^= 1;
    write_json(&tampered_public, &public_json(tampered_hash));
    let verify = |public: &Path| {
        run_snarkjs(&[
            "groth16",
            "verify",
            path(&ceremony.verification_key()),
            path(public),
            path(&proof),
        ])
    };

    let snarkjs_proof_path = work.join("snarkjs_proof.json");
    let snarkjs_public_path = work.join("snarkjs_public.json");
    snarkjs(&[
        "groth16",
        "prove",
        path(&ceremony.final_zkey()),
        path(&wtns),
        path(&snarkjs_proof_path),
        path(&snarkjs_public_path),
    ]);
    let read_json = |path: &Path| -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("json file")).expect("json")
    };
    let snarkjs_result = ProofResult {
        proof: solana_proof(&read_json(&snarkjs_proof_path)),
        public_hash: result.public_hash,
    };

    assert_eq!(
        (
            prover.verify(&result).is_ok(),
            witness_checks,
            verify(&public),
            verify(&tampered_public),
            read_json(&snarkjs_public_path),
            prover.verify(&snarkjs_result).is_ok(),
        ),
        (
            true,
            true,
            true,
            false,
            public_json(result.public_hash),
            true
        )
    );
}

struct WorkDir(PathBuf);

impl WorkDir {
    fn new(name: &str) -> Self {
        let dir = snarkjs_dir().join(format!("run-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("work directory");
        Self(dir)
    }

    fn join(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn escrow_proves_from_a_snarkjs_zkey() {
    proves_from_a_snarkjs_zkey("escrow", &programs::escrow());
}

#[test]
fn withdraw_proves_from_a_snarkjs_zkey() {
    proves_from_a_snarkjs_zkey("withdraw", &programs::withdraw());
}

#[test]
fn a_libsnark_reduction_proof_does_not_verify_against_a_zkey() {
    let ceremony = ceremony::<Withdraw>("withdraw");
    let program = programs::withdraw();
    let keys = Groth16Keys::load_zkey::<Withdraw>(&ceremony.final_zkey()).expect("zkey");
    let r1cs = iden3::read_r1cs(&std::fs::read(ceremony.r1cs()).expect("r1cs"));
    let matrices = r1cs.matrices();
    let assignment = iden3::read_wtns(&program.export_assignment().expect("assignment"));
    let public_hash: [u8; 32] = assignment
        .get(1)
        .expect("public hash variable")
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("32 bytes");
    let proof_with = |keys: &Groth16Keys| {
        Groth16::<Bn254, LibsnarkReduction>::create_proof_with_reduction_and_matrices(
            keys.proving_key(),
            Fr::from(3u64),
            Fr::from(5u64),
            &matrices,
            matrices.num_instance_variables,
            matrices.num_constraints,
            &assignment,
        )
        .expect("libsnark proof")
    };
    let local_keys = Groth16Prover::<Withdraw>::new_with_test_setup().expect("local setup");

    assert_eq!(
        (
            r1cs.first_unsatisfied(&assignment),
            SolanaProof::from(&proof_with(&keys))
                .verify(keys.verifying_key(), public_hash)
                .err()
                .map(|error| error.to_string()),
            SolanaProof::from(&proof_with(local_keys.keys()))
                .verify(local_keys.keys().verifying_key(), public_hash)
                .err()
                .map(|error| error.to_string()),
        ),
        (
            None,
            Some(RelationError::ProofRejected.to_string()),
            Some(RelationError::ProofRejected.to_string()),
        )
    );
}

fn zkey_sections(bytes: &[u8]) -> Vec<(u32, usize, usize)> {
    let u32_at = |offset: usize| {
        u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .expect("u32")
                .try_into()
                .expect("u32"),
        )
    };
    let count = u32_at(8);
    let mut offset = 12;
    (0..count)
        .map(|_| {
            let kind = u32_at(offset);
            let size = u64::from_le_bytes(
                bytes
                    .get(offset + 4..offset + 12)
                    .expect("u64")
                    .try_into()
                    .expect("u64"),
            );
            let size = usize::try_from(size).expect("size");
            let start = offset + 12;
            offset = start + size;
            (kind, start, size)
        })
        .collect()
}

fn section_start(bytes: &[u8], kind: u32) -> usize {
    zkey_sections(bytes)
        .into_iter()
        .find(|(id, _, _)| *id == kind)
        .map(|(_, start, _)| start)
        .expect("zkey section")
}

fn montgomery_le(value: &Fq) -> Vec<u8> {
    value.0.to_bytes_le()
}

fn g2_outside_the_subgroup() -> Vec<u8> {
    let point = (1u64..)
        .filter_map(|x| {
            G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(x), Fq::from(0u64)), false)
        })
        .find(|point| !point.is_in_correct_subgroup_assuming_on_curve())
        .expect("a point outside the subgroup");
    let (x, y) = point.xy().expect("affine point");
    [x.c0, x.c1, y.c0, y.c1]
        .iter()
        .flat_map(montgomery_le)
        .collect()
}

fn load_modified(name: &str, bytes: &[u8]) -> Option<String> {
    let dir = WorkDir::new(name);
    let zkey = dir.join("modified.zkey");
    std::fs::write(&zkey, bytes).expect("zkey file");
    Groth16Keys::load_zkey::<Withdraw>(&zkey)
        .err()
        .map(|error| error.to_string())
}

#[test]
fn load_zkey_rejects_keys_that_do_not_belong_to_the_circuit() {
    let ceremony = ceremony::<Withdraw>("withdraw");
    let bytes = std::fs::read(ceremony.final_zkey()).expect("zkey");

    let mut off_curve = bytes.clone();
    let a_start = section_start(&bytes, 5);
    if let Some(byte) = off_curve.get_mut(a_start) {
        *byte ^= 1;
    }

    let mut outside_subgroup = bytes.clone();
    let b2_start = section_start(&bytes, 7);
    if let Some(point) = outside_subgroup.get_mut(b2_start..b2_start + 128) {
        point.copy_from_slice(&g2_outside_the_subgroup());
    }

    let mut other_coefficient = bytes.clone();
    let coefficient_value = section_start(&bytes, 4) + 4 + 12;
    if let Some(byte) = other_coefficient.get_mut(coefficient_value) {
        *byte ^= 1;
    }

    let mut identity_delta = bytes.clone();
    let delta_g2_start = section_start(&bytes, 2) + 84 + 2 * 64 + 2 * 128 + 64;
    if let Some(point) = identity_delta.get_mut(delta_g2_start..delta_g2_start + 128) {
        point.fill(0);
    }

    let truncated = bytes.get(..bytes.len() - 1).expect("truncated").to_vec();

    assert_eq!(
        (
            Groth16Keys::load_zkey::<Escrow>(&ceremony.final_zkey())
                .err()
                .map(|error| error.to_string()),
            Groth16Keys::load_zkey::<Withdraw>(&ceremony.initial_zkey())
                .err()
                .map(|error| error.to_string()),
            load_modified("identity-delta", &identity_delta),
            load_modified("off-curve", &off_curve),
            load_modified("outside-subgroup", &outside_subgroup),
            load_modified("other-coefficient", &other_coefficient),
            load_modified("truncated", &truncated),
            load_modified("unchanged", &bytes),
        ),
        (
            Some(RelationError::KeysForAnotherCircuit.to_string()),
            Some(RelationError::UncontributedZkey.to_string()),
            Some(RelationError::InvalidKeyPoint("delta").to_string()),
            Some(RelationError::InvalidKeyPoint("A").to_string()),
            Some(RelationError::InvalidKeyPoint("B2").to_string()),
            Some(RelationError::KeysForAnotherCircuit.to_string()),
            Some(RelationError::InvalidZkey("the zkey ends early").to_string()),
            None,
        )
    );
}

#[test]
fn a_ceremony_zkey_exports_a_production_verifying_key() {
    let ceremony = ceremony::<Withdraw>("withdraw");
    let dir = WorkDir::new("export");
    let zkey = ceremony.final_zkey();
    let exported = Groth16Keys::load_zkey::<Withdraw>(&zkey)
        .expect("zkey")
        .export_verifying_key(&VerifyingKeyExport {
            proving_key: &zkey,
            output_dir: &dir.0,
            output_filename: "withdraw.rs",
            const_name: "VERIFYINGKEY",
            setup: SetupKind::Production,
        })
        .map_err(|error| error.to_string());
    let file = std::fs::read_to_string(dir.join("withdraw.rs")).expect("exported vk");
    let digest = Sha256::digest(std::fs::read(&zkey).expect("zkey"));
    let digest_bytes = digest
        .iter()
        .map(|byte| format!("{byte}u8"))
        .collect::<Vec<_>>()
        .join(", ");

    assert_eq!(
        (
            exported,
            file.contains("pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = false;"),
            file.contains(&format!(
                "pub const VERIFYINGKEY_PROVING_KEY_SHA256: [u8; 32] = [{digest_bytes}];"
            )),
        ),
        (Ok(()), true, true)
    );
}
