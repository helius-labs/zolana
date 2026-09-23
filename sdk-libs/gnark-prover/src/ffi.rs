use std::ffi::{c_char, CStr};

/// Rust mirror of the Go bridge's `C_ProveResult` (sdk-libs/gnark-prover/go/prover.go).
/// The field order and types must match it exactly.
#[repr(C)]
pub struct ProveResult {
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    public_input: [u8; 32],
    has_commitment: u8,
    proof_commitment: [u8; 64],
    proof_commitment_pok: [u8; 64],
    error: *mut c_char,
}

/// The Go archive's exported functions, resolved in the crate that links the
/// archive. [`crate::prover!`] declares them there and fills this in, so the
/// symbol references and the archive land in the same rlib.
pub struct Symbols {
    pub setup: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char,
    pub load_keys: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char,
    pub prove: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut ProveResult,
    pub free_prove_result: unsafe extern "C" fn(*mut ProveResult),
    pub free_string: unsafe extern "C" fn(*mut c_char),
}

/// Declares the Go archive's symbols in the calling crate and builds its
/// [`Prover`](crate::Prover). The calling crate's build script links the
/// archive with `zolana_gnark_prover_build::build_prover_archive`, and its keys live
/// in `<crate>/../build/gnark/<circuit>`.
///
/// ```ignore
/// pub static PROVER: zolana_gnark_prover::Prover<CircuitId> = zolana_gnark_prover::prover!();
/// ```
#[macro_export]
macro_rules! prover {
    () => {{
        unsafe extern "C" {
            fn Setup(
                name: *const ::core::ffi::c_char,
                out_dir: *const ::core::ffi::c_char,
            ) -> *mut ::core::ffi::c_char;
            fn LoadKeys(
                name: *const ::core::ffi::c_char,
                proving_key_path: *const ::core::ffi::c_char,
            ) -> *mut ::core::ffi::c_char;
            fn Prove(
                name: *const ::core::ffi::c_char,
                witness_json: *const ::core::ffi::c_char,
            ) -> *mut $crate::ProveResult;
            fn FreeProveResult(result: *mut $crate::ProveResult);
            fn FreeString(s: *mut ::core::ffi::c_char);
        }
        $crate::Prover::new(
            $crate::Symbols {
                setup: Setup,
                load_keys: LoadKeys,
                prove: Prove,
                free_prove_result: FreeProveResult,
                free_string: FreeString,
            },
            concat!(env!("CARGO_MANIFEST_DIR"), "/../build/gnark"),
        )
    }};
}

impl ProveResult {
    /// The Go error string, if the call failed.
    ///
    /// # Safety
    /// `self.error` is null or a NUL-terminated string the Go side allocated.
    pub(crate) unsafe fn error(&self) -> Option<String> {
        (!self.error.is_null()).then(|| CStr::from_ptr(self.error).to_string_lossy().into_owned())
    }

    pub(crate) fn output(&self) -> crate::ProveOutput {
        crate::ProveOutput {
            proof_a: self.proof_a,
            proof_b: self.proof_b,
            proof_c: self.proof_c,
            public_input_hash: self.public_input,
            commitment: (self.has_commitment != 0).then_some(crate::Commitment {
                commitment: self.proof_commitment,
                pok: self.proof_commitment_pok,
            }),
        }
    }
}
