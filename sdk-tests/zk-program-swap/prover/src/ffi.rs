use std::{
    collections::HashMap,
    ffi::{c_char, CStr, CString},
    path::{Path, PathBuf},
    sync::Once,
};

#[allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
mod bind {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub type WitnessMap = HashMap<String, Vec<String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CircuitId {
    Make = 0,
    Cancel = 1,
    Take = 2,
    TakeVerifiableEncryption = 3,
}

#[derive(Debug, Clone)]
pub struct ProveOutput {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub public_input_hash: [u8; 32],
    pub proof_commitment: [u8; 64],
    pub proof_commitment_pok: [u8; 64],
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("gnark FFI error: {0}")]
    Go(String),
    #[error("path is not valid UTF-8")]
    PathEncoding,
    #[error("interior NUL in C string")]
    NulInString(#[from] std::ffi::NulError),
    #[error("witness JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("proving keys missing at {0} -- run setup first")]
    MissingKeys(String),
}

pub type Result<T> = std::result::Result<T, Error>;

fn path_to_cstring(path: &Path) -> Result<CString> {
    let s = path.to_str().ok_or(Error::PathEncoding)?;
    Ok(CString::new(s)?)
}

pub fn setup(circuit: CircuitId, out_dir: &Path) -> Result<()> {
    ensure_keys_loaded(circuit);

    std::fs::create_dir_all(out_dir)?;
    let dir = path_to_cstring(out_dir)?;
    let err = unsafe { bind::Setup(circuit as i32, dir.as_ptr() as *mut c_char) };
    if err.is_null() {
        Ok(())
    } else {
        Err(Error::Go(unsafe { ptr_to_string_freed(err) }))
    }
}

fn load_keys(circuit: CircuitId, proving_key_path: &Path, verifying_key_path: &Path) -> Result<()> {
    let proving_key_cstr = path_to_cstring(proving_key_path)?;
    let verifying_key_cstr = path_to_cstring(verifying_key_path)?;
    let err = unsafe {
        bind::LoadKeys(
            circuit as i32,
            proving_key_cstr.as_ptr() as *mut c_char,
            verifying_key_cstr.as_ptr() as *mut c_char,
        )
    };
    if err.is_null() {
        Ok(())
    } else {
        Err(Error::Go(unsafe { ptr_to_string_freed(err) }))
    }
}

pub fn preload(circuit: CircuitId) -> Result<()> {
    if circuit_once(circuit).is_completed() {
        return Ok(());
    }
    let dir = build_dir(circuit);
    let proving_key_path = dir.join("pk.bin");
    let verifying_key_path = dir.join("vk.bin");
    if !proving_key_path.exists() || !verifying_key_path.exists() {
        return Err(Error::MissingKeys(dir.display().to_string()));
    }
    load_keys(circuit, &proving_key_path, &verifying_key_path)?;
    circuit_once(circuit).call_once(|| {});
    Ok(())
}

pub fn prove(circuit: CircuitId, witness: &WitnessMap) -> Result<ProveOutput> {
    ensure_keys_loaded(circuit);

    let json = serde_json::to_string(witness)?;
    let json_c = CString::new(json)?;

    let prove_result_ptr = unsafe { bind::Prove(circuit as i32, json_c.as_ptr() as *mut c_char) };
    if prove_result_ptr.is_null() {
        return Err(Error::Go("Prove returned NULL".into()));
    }

    let prove_result = unsafe { &*prove_result_ptr };
    if !prove_result.error.is_null() {
        let msg = unsafe { ptr_to_string_cloned(prove_result.error) };
        unsafe { bind::FreeProveResult(prove_result_ptr) };
        return Err(Error::Go(msg));
    }

    let output = ProveOutput {
        proof_a: prove_result.proof_a,
        proof_b: prove_result.proof_b,
        proof_c: prove_result.proof_c,
        public_input_hash: prove_result.public_input,
        proof_commitment: prove_result.proof_commitment,
        proof_commitment_pok: prove_result.proof_commitment_pok,
    };
    unsafe { bind::FreeProveResult(prove_result_ptr) };
    Ok(output)
}

fn build_dir(circuit: CircuitId) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/gnark");
    let sub = match circuit {
        CircuitId::Make => "make",
        CircuitId::Cancel => "cancel",
        CircuitId::Take => "take",
        CircuitId::TakeVerifiableEncryption => "take_verifiable_encryption",
    };
    base.join(sub)
}

fn circuit_once(circuit: CircuitId) -> &'static Once {
    static MAKE: Once = Once::new();
    static CANCEL: Once = Once::new();
    static TAKE: Once = Once::new();
    static TAKE_VERIFIABLE_ENCRYPTION: Once = Once::new();
    match circuit {
        CircuitId::Make => &MAKE,
        CircuitId::Cancel => &CANCEL,
        CircuitId::Take => &TAKE,
        CircuitId::TakeVerifiableEncryption => &TAKE_VERIFIABLE_ENCRYPTION,
    }
}

fn ensure_keys_loaded(circuit: CircuitId) {
    circuit_once(circuit).call_once(|| {
        let dir = build_dir(circuit);
        let proving_key_path = dir.join("pk.bin");
        let verifying_key_path = dir.join("vk.bin");
        if proving_key_path.exists() && verifying_key_path.exists() {
            if let Err(e) = load_keys(circuit, &proving_key_path, &verifying_key_path) {
                eprintln!(
                    "prover: failed to lazy-load keys for {circuit:?} from {}: {e}",
                    dir.display()
                );
            }
        }
    });
}

unsafe fn ptr_to_string_cloned(p: *mut c_char) -> String {
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

unsafe fn ptr_to_string_freed(p: *mut c_char) -> String {
    let s = ptr_to_string_cloned(p);
    bind::FreeString(p);
    s
}
