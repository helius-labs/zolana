use std::{
    ffi::{c_char, CStr, CString},
    fmt,
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, OnceLock, PoisonError},
};

use crate::{Error, ProveOutput, Result, Symbols, WitnessMap};

/// A circuit a prover crate's Go archive registers.
pub trait Circuit: Copy + PartialEq + fmt::Debug + 'static {
    /// Every circuit the archive registers, in setup CLI order.
    const ALL: &'static [Self];

    /// The name the Go side registers the circuit under. It is also the
    /// circuit's key directory under the key root and its setup CLI argument.
    fn name(self) -> &'static str;
}

/// One prover crate's Go archive. Each circuit's proving key is loaded from
/// disk on first use and stays loaded in the archive.
pub struct Prover<C> {
    symbols: Symbols,
    keys_root: &'static str,
    /// Whether each circuit of [`Circuit::ALL`] has its proving key loaded, by
    /// index. The lock is held across a load, so concurrent first proofs of
    /// one circuit load its key once.
    loaded: OnceLock<Box<[Mutex<bool>]>>,
    circuit: PhantomData<fn() -> C>,
}

impl<C: Circuit> Prover<C> {
    /// Built by [`crate::prover!`], which supplies the calling crate's symbols
    /// and key root.
    pub const fn new(symbols: Symbols, keys_root: &'static str) -> Self {
        Self {
            symbols,
            keys_root,
            loaded: OnceLock::new(),
            circuit: PhantomData,
        }
    }

    /// Directory holding the circuit's `pk.bin` and `vk.bin`.
    pub fn keys_dir(&self, circuit: C) -> PathBuf {
        Path::new(self.keys_root).join(circuit.name())
    }

    /// Generate fresh keys for `circuit` into `out_dir` and keep its proving
    /// key loaded. It never loads the keys already on disk first, which would
    /// be replaced anyway.
    pub fn setup(&self, circuit: C, out_dir: &Path) -> Result<()> {
        self.run_setup(self.symbols.setup, circuit, out_dir)
    }

    /// [`Self::setup`] with randomness from a fixed seed derived from the
    /// circuit name, so the same circuit and gnark version always get the
    /// same `pk.bin` and `vk.bin`. The seed is public: anyone can forge proofs
    /// against these keys, so they are for tests only and must never back a
    /// deployed verifier.
    pub fn setup_insecure_test_keys(&self, circuit: C, out_dir: &Path) -> Result<()> {
        self.run_setup(self.symbols.setup_insecure_test_keys, circuit, out_dir)
    }

    fn run_setup(
        &self,
        setup: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char,
        circuit: C,
        out_dir: &Path,
    ) -> Result<()> {
        std::fs::create_dir_all(out_dir)?;
        let name = CString::new(circuit.name())?;
        let dir = path_cstring(out_dir)?;
        let mut loaded = self.lock_loaded(circuit)?;
        self.check(unsafe { setup(name.as_ptr(), dir.as_ptr()) })?;
        *loaded = true;
        Ok(())
    }

    /// Load `circuit`'s proving key from [`Self::keys_dir`] unless it is
    /// loaded. A failed load is reported and retried on the next call.
    pub fn preload(&self, circuit: C) -> Result<()> {
        let mut loaded = self.lock_loaded(circuit)?;
        if *loaded {
            return Ok(());
        }
        let proving_key = self.keys_dir(circuit).join("pk.bin");
        if !proving_key.exists() {
            return Err(Error::MissingKeys(proving_key));
        }
        let name = CString::new(circuit.name())?;
        let path = path_cstring(&proving_key)?;
        self.check(unsafe { (self.symbols.load_keys)(name.as_ptr(), path.as_ptr()) })?;
        *loaded = true;
        Ok(())
    }

    pub fn prove(&self, circuit: C, witness: &WitnessMap) -> Result<ProveOutput> {
        self.preload(circuit)?;
        let name = CString::new(circuit.name())?;
        let witness = CString::new(serde_json::to_string(witness)?)?;
        let result = unsafe { (self.symbols.prove)(name.as_ptr(), witness.as_ptr()) };
        if result.is_null() {
            return Err(Error::Go("Prove returned NULL".into()));
        }
        // SAFETY: `result` is a live allocation from Prove until freed below.
        let output = unsafe {
            let result_ref = &*result;
            match result_ref.error() {
                Some(message) => Err(Error::Go(message)),
                None => Ok(result_ref.output()),
            }
        };
        unsafe { (self.symbols.free_prove_result)(result) };
        output
    }

    fn lock_loaded(&self, circuit: C) -> Result<MutexGuard<'_, bool>> {
        let loaded = self
            .loaded
            .get_or_init(|| C::ALL.iter().map(|_| Mutex::new(false)).collect());
        let slot = C::ALL
            .iter()
            .position(|registered| *registered == circuit)
            .and_then(|index| loaded.get(index))
            .ok_or(Error::UnlistedCircuit(circuit.name()))?;
        // A panic mid-load leaves the flag false, so the next call reloads.
        Ok(slot.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Turn an error string returned by a Go call into a result, freeing it.
    fn check(&self, error: *mut c_char) -> Result<()> {
        if error.is_null() {
            return Ok(());
        }
        // SAFETY: a non-null return is a NUL-terminated string the Go side
        // allocated for the caller to free with FreeString.
        let message = unsafe { CStr::from_ptr(error).to_string_lossy().into_owned() };
        unsafe { (self.symbols.free_string)(error) };
        Err(Error::Go(message))
    }
}

fn path_cstring(path: &Path) -> Result<CString> {
    let path = path.to_str().ok_or(Error::PathEncoding)?;
    Ok(CString::new(path)?)
}
