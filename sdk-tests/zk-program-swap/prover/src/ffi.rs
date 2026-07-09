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
    Stub = 0,
    Create = 1,
    Cancel = 2,
    Fill = 3,
    FillVerifiableEncryption = 4,
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

fn load_keys(circuit: CircuitId, pk_path: &Path, vk_path: &Path) -> Result<()> {
    let pk = path_to_cstring(pk_path)?;
    let vk = path_to_cstring(vk_path)?;
    let err = unsafe {
        bind::LoadKeys(
            circuit as i32,
            pk.as_ptr() as *mut c_char,
            vk.as_ptr() as *mut c_char,
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
    let pk = dir.join("pk.bin");
    let vk = dir.join("vk.bin");
    if !pk.exists() || !vk.exists() {
        return Err(Error::MissingKeys(dir.display().to_string()));
    }
    load_keys(circuit, &pk, &vk)?;
    circuit_once(circuit).call_once(|| {});
    Ok(())
}

pub fn prove(circuit: CircuitId, witness: &WitnessMap) -> Result<ProveOutput> {
    ensure_keys_loaded(circuit);

    let json = serde_json::to_string(witness)?;
    let json_c = CString::new(json)?;

    let result = unsafe { bind::Prove(circuit as i32, json_c.as_ptr() as *mut c_char) };
    if result.is_null() {
        return Err(Error::Go("Prove returned NULL".into()));
    }

    let r = unsafe { &*result };
    if !r.error.is_null() {
        let msg = unsafe { ptr_to_string_cloned(r.error) };
        unsafe { bind::FreeProveResult(result) };
        return Err(Error::Go(msg));
    }

    let out = ProveOutput {
        proof_a: r.proof_a,
        proof_b: r.proof_b,
        proof_c: r.proof_c,
        public_input_hash: r.public_input,
        proof_commitment: r.proof_commitment,
        proof_commitment_pok: r.proof_commitment_pok,
    };
    unsafe { bind::FreeProveResult(result) };
    Ok(out)
}

fn build_dir(circuit: CircuitId) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/gnark");
    let sub = match circuit {
        CircuitId::Stub => "stub",
        CircuitId::Create => "create",
        CircuitId::Cancel => "cancel",
        CircuitId::Fill => "fill",
        CircuitId::FillVerifiableEncryption => "fill_verifiable_encryption",
    };
    base.join(sub)
}

fn circuit_once(circuit: CircuitId) -> &'static Once {
    static STUB: Once = Once::new();
    static CREATE: Once = Once::new();
    static CANCEL: Once = Once::new();
    static FILL: Once = Once::new();
    static FILL_VERIFIABLE_ENCRYPTION: Once = Once::new();
    match circuit {
        CircuitId::Stub => &STUB,
        CircuitId::Create => &CREATE,
        CircuitId::Cancel => &CANCEL,
        CircuitId::Fill => &FILL,
        CircuitId::FillVerifiableEncryption => &FILL_VERIFIABLE_ENCRYPTION,
    }
}

fn ensure_keys_loaded(circuit: CircuitId) {
    circuit_once(circuit).call_once(|| {
        let dir = build_dir(circuit);
        let pk = dir.join("pk.bin");
        let vk = dir.join("vk.bin");
        if pk.exists() && vk.exists() {
            if let Err(e) = load_keys(circuit, &pk, &vk) {
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
