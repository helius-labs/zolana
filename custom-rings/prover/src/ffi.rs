//! Bindings to the cgo c-archive built from `circuits/`.
//!
//! `setup` / `preload` / `prove` are the whole engine surface. They exist
//! unconditionally so the rest of the crate compiles without a Go toolchain;
//! when `build.rs` did not link the archive they all fail with
//! [`Error::EngineUnavailable`] instead of silently succeeding.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

/// Witness field name -> its decimal-string values. Scalars carry exactly one
/// value, byte arrays one value per byte; the Go assigner
/// (`circuits/witness/witness.go`) rejects a map with a missing, extra, or
/// wrong-length key, so this is a total description of the circuit witness.
pub type WitnessMap = HashMap<String, Vec<String>>;

/// Circuit selector. The discriminants are the ffi contract with
/// `circuits/main.go`, which names the same value `CircuitAuditorKeyEncryption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CircuitId {
    AuditorKeyEncryption = 0,
}

impl CircuitId {
    /// Directory name under `build/gnark/` holding this circuit's keys, and the
    /// name accepted by the setup binary.
    pub fn name(self) -> &'static str {
        match self {
            CircuitId::AuditorKeyEncryption => "auditor_key_encryption",
        }
    }
}

/// Raw gnark proof output: uncompressed big-endian curve points, before the
/// negate-and-compress step in [`crate::proof`].
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
    #[error(
        "the Go circuits are not linked into this build: custom-ring-tests/prover/build.rs \
         skipped the cgo build (missing circuits/main.go or Go toolchain)"
    )]
    EngineUnavailable,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Runs the gnark trusted setup and writes `pk.bin` / `vk.bin` into `out_dir`.
pub fn setup(circuit: CircuitId, out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    engine::setup(circuit, out_dir)
}

/// Loads this circuit's keys from its canonical build directory, erroring if
/// they have not been generated yet. Idempotent.
pub fn preload(circuit: CircuitId) -> Result<()> {
    engine::preload(circuit)
}

/// Proves `witness`, lazily loading the keys on first use.
pub fn prove(circuit: CircuitId, witness: &WitnessMap) -> Result<ProveOutput> {
    let json = serde_json::to_string(witness)?;
    engine::prove(circuit, &json)
}

/// Canonical key location: `custom-ring-tests/build/gnark/<circuit>/`.
pub fn build_dir(circuit: CircuitId) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../build/gnark")
        .join(circuit.name())
}

#[cfg(custom_ring_go_circuits)]
mod engine {
    use std::{
        ffi::{c_char, CStr, CString},
        path::Path,
        sync::Once,
    };

    use super::{build_dir, CircuitId, Error, ProveOutput, Result};

    #[allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
    mod bind {
        include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
    }

    fn path_to_cstring(path: &Path) -> Result<CString> {
        let s = path.to_str().ok_or(Error::PathEncoding)?;
        Ok(CString::new(s)?)
    }

    pub(super) fn setup(circuit: CircuitId, out_dir: &Path) -> Result<()> {
        ensure_keys_loaded(circuit);

        let dir = path_to_cstring(out_dir)?;
        let err = unsafe { bind::Setup(circuit as i32, dir.as_ptr() as *mut c_char) };
        if err.is_null() {
            Ok(())
        } else {
            Err(Error::Go(unsafe { ptr_to_string_freed(err) }))
        }
    }

    fn load_keys(
        circuit: CircuitId,
        proving_key_path: &Path,
        verifying_key_path: &Path,
    ) -> Result<()> {
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

    pub(super) fn preload(circuit: CircuitId) -> Result<()> {
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

    pub(super) fn prove(circuit: CircuitId, witness_json: &str) -> Result<ProveOutput> {
        ensure_keys_loaded(circuit);

        let json_c = CString::new(witness_json)?;
        let prove_result_ptr =
            unsafe { bind::Prove(circuit as i32, json_c.as_ptr() as *mut c_char) };
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

    fn circuit_once(circuit: CircuitId) -> &'static Once {
        static AUDITOR_KEY_ENCRYPTION: Once = Once::new();
        match circuit {
            CircuitId::AuditorKeyEncryption => &AUDITOR_KEY_ENCRYPTION,
        }
    }

    /// Best-effort lazy load. A missing key file is not an error here: `setup`
    /// is the call that creates it, and `prove` reports the Go-side "proving key
    /// not loaded" error with the circuit id attached.
    fn ensure_keys_loaded(circuit: CircuitId) {
        circuit_once(circuit).call_once(|| {
            let dir = build_dir(circuit);
            let proving_key_path = dir.join("pk.bin");
            let verifying_key_path = dir.join("vk.bin");
            if proving_key_path.exists() && verifying_key_path.exists() {
                if let Err(e) = load_keys(circuit, &proving_key_path, &verifying_key_path) {
                    eprintln!(
                        "custom-ring-prover: failed to lazy-load keys for {circuit:?} from {}: {e}",
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
}

#[cfg(not(custom_ring_go_circuits))]
mod engine {
    use std::path::Path;

    use super::{CircuitId, Error, ProveOutput, Result};

    pub(super) fn setup(_circuit: CircuitId, _out_dir: &Path) -> Result<()> {
        Err(Error::EngineUnavailable)
    }

    pub(super) fn preload(_circuit: CircuitId) -> Result<()> {
        Err(Error::EngineUnavailable)
    }

    pub(super) fn prove(_circuit: CircuitId, _witness_json: &str) -> Result<ProveOutput> {
        Err(Error::EngineUnavailable)
    }
}
