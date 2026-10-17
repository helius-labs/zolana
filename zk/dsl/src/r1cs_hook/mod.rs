//! The contract between a circuit crate's r1cs export hook and the build that
//! runs it. The derives emit one `#[test]` per circuit named
//! `{HOOK_PREFIX}<snake_case name>`; the build runs those tests with
//! `{OUT_DIR_ENV}` naming an output directory, and each hook writes
//! `<name>.r1cs` and `<name>.verifier.rs` there and prints
//! `{MARKER}<path of the .r1cs>`.

/// The test name prefix of every r1cs export hook.
pub const HOOK_PREFIX: &str = "__zk_r1cs_";

/// The environment variable naming the directory the hooks write to.
pub const OUT_DIR_ENV: &str = "ZOLANA_ZK_R1CS_OUT";

/// The stdout prefix of a line naming a written `.r1cs` file.
pub const MARKER: &str = "zolana-zk-r1cs: ";

/// The file name suffix of the verifier module rendered next to each `.r1cs`.
pub const VERIFIER_SUFFIX: &str = "verifier.rs";

#[cfg(feature = "setup")]
mod verifier_codegen;

#[cfg(feature = "setup")]
pub use verifier_codegen::{binding_base, render_verifier, rust_type};

/// The text a verifying key module carries when it was not generated from an
/// insecure test setup. A build keeps such a module instead of overwriting it
/// with a test key.
pub const PRODUCTION_KEY: &str = "VERIFYINGKEY_INSECURE_TEST_SETUP: bool = false";

/// Writes the r1cs of `C` and its verifier module `glue` for the hook of
/// circuit `name`. Panics, failing the hook test, when the export fails.
#[cfg(feature = "setup")]
pub fn write_r1cs<C: crate::ZkCircuit>(name: &str, glue: &str) {
    let dir = std::path::PathBuf::from(
        std::env::var_os(OUT_DIR_ENV)
            .unwrap_or_else(|| panic!("{OUT_DIR_ENV} names no directory for {name}.r1cs")),
    );
    let r1cs = C::export_r1cs().unwrap_or_else(|error| panic!("{name}: {error}"));
    let path = dir.join(format!("{name}.r1cs"));
    std::fs::write(&path, r1cs).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    println!("{MARKER}{}", path.display());
    let verifier = dir.join(format!("{name}.{VERIFIER_SUFFIX}"));
    std::fs::write(&verifier, glue)
        .unwrap_or_else(|error| panic!("{}: {error}", verifier.display()));
}

/// The hook of a circuit with regular public inputs: its verifier binds every
/// public field directly.
#[cfg(feature = "setup")]
pub fn write_circuit_r1cs<C: crate::ZkCircuit>(
    name: &str,
    layout: &[(&'static str, crate::PublicFieldKind)],
) {
    write_r1cs::<C>(name, &render_verifier(name, layout));
}
