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

#[derive(Debug, Clone)]
pub struct ProveOutput {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub public_input_hash: [u8; 32],
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
}

pub type Result<T> = std::result::Result<T, Error>;

static KEYS_LOADED: Once = Once::new();

fn path_to_cstring(path: &Path) -> Result<CString> {
    let s = path.to_str().ok_or(Error::PathEncoding)?;
    Ok(CString::new(s)?)
}

/// Directory holding the read circuit's `pk.bin` / `vk.bin`.
pub fn build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/gnark/read")
}

pub fn setup(out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    let dir = path_to_cstring(out_dir)?;
    let err = unsafe { bind::Setup(dir.as_ptr() as *mut c_char) };
    if err.is_null() {
        KEYS_LOADED.call_once(|| {});
        Ok(())
    } else {
        Err(Error::Go(unsafe { ptr_to_string_freed(err) }))
    }
}

fn load_keys(proving_key_path: &Path) -> Result<()> {
    let proving_key_cstr = path_to_cstring(proving_key_path)?;
    let err = unsafe { bind::LoadKeys(proving_key_cstr.as_ptr() as *mut c_char) };
    if err.is_null() {
        Ok(())
    } else {
        Err(Error::Go(unsafe { ptr_to_string_freed(err) }))
    }
}

pub fn prove(witness: &WitnessMap) -> Result<ProveOutput> {
    KEYS_LOADED.call_once(|| {
        let proving_key_path = build_dir().join("pk.bin");
        if let Err(e) = load_keys(&proving_key_path) {
            eprintln!(
                "prover: failed to load the read proving key from {}: {e}",
                proving_key_path.display()
            );
        }
    });

    let json = serde_json::to_string(witness)?;
    let json_c = CString::new(json)?;

    let prove_result_ptr = unsafe { bind::Prove(json_c.as_ptr() as *mut c_char) };
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
    };
    unsafe { bind::FreeProveResult(prove_result_ptr) };
    Ok(output)
}

unsafe fn ptr_to_string_cloned(p: *mut c_char) -> String {
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

unsafe fn ptr_to_string_freed(p: *mut c_char) -> String {
    let s = ptr_to_string_cloned(p);
    bind::FreeString(p);
    s
}
