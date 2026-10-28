use std::path::PathBuf;

/// The crate that defines the circuits: a workspace package, or the package
/// of a manifest (default: the one in the current directory or its parents).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackageSelection {
    pub package: Option<String>,
    pub manifest_path: Option<PathBuf>,
}

/// The JavaScript environment a wasm package loads in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WasmTarget {
    #[default]
    Web,
    Nodejs,
}

/// What `compile` builds and where. Build outputs go to `zk/<package>` in the
/// cargo target directory unless an output directory is given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileOptions {
    pub package: PackageSelection,
    /// Reuse the compiled Xark circuit artifacts when present.
    pub skip_r1cs: bool,
    /// Use reproducible fixed-seed test keys.
    pub test: bool,
    /// Do not generate keys or write the verifying keys.
    pub skip_keys: bool,
    /// Do not build the wasm package.
    pub skip_wasm: bool,
    /// Compare the regenerated verifier modules with the committed ones
    /// instead of writing them, and build no wasm.
    pub check: bool,
    /// Cargo features that build the circuits; the export adds `r1cs-export`.
    pub r1cs_features: String,
    pub r1cs_out: Option<PathBuf>,
    /// Cargo features of the wasm package.
    pub wasm_features: String,
    pub wasm_target: WasmTarget,
    /// Disable the JavaScript worker pool in the emitted runtime options.
    pub single_threaded: bool,
    /// Build the package without the provers.
    pub no_prover: bool,
    /// Also export the proof/key conversion helpers used by independent verifiers.
    pub verifier: bool,
    /// Run wasm-opt.
    pub wasm_opt: bool,
    pub wasm_out: Option<PathBuf>,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            package: PackageSelection::default(),
            skip_r1cs: false,
            skip_keys: false,
            test: false,
            skip_wasm: false,
            check: false,
            r1cs_features: "circuits".into(),
            r1cs_out: None,
            wasm_features: "wasm".into(),
            wasm_target: WasmTarget::Web,
            single_threaded: false,
            no_prover: false,
            verifier: false,
            wasm_opt: false,
            wasm_out: None,
        }
    }
}

impl CompileOptions {
    /// Prover builds use a thread pool unless single-threaded is requested.
    pub fn threads(&self) -> bool {
        !self.single_threaded && !self.no_prover
    }
}

/// The SBF build of the Solana program that verifies the circuits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SbfOptions {
    pub skip_sbf: bool,
    /// Cargo features of the SBF program, for example its entrypoint feature.
    pub sbf_features: Option<String>,
    /// Directory for the program .so (default: cargo build-sbf's).
    pub sbf_out_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildOptions {
    pub compile: CompileOptions,
    pub sbf: SbfOptions,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetupOptions {
    pub package: PackageSelection,
    /// Use reproducible fixed-seed test keys.
    pub test: bool,
    /// Directory containing the compiled circuits.
    pub out: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportVerifierOptions {
    pub package: PackageSelection,
    /// Trusted sha256sum manifest for the serialized verifying keys.
    pub checksums: PathBuf,
    /// Directory containing the compiled circuits and their keys.
    pub out: Option<PathBuf>,
}
