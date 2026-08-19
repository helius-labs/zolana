use std::{env, path::PathBuf, process::Command};

/// Compiles `circuits/` to a cgo c-archive and generates the FFI bindings.
///
/// The Go module is optional at build time: while `circuits/main.go` is absent
/// the archive cannot exist, so the build emits a warning and leaves
/// `cfg(custom_ring_go_circuits)` unset. Everything touching the FFI is gated on
/// that cfg, which keeps the crate compiling as a skeleton and makes the missing
/// engine a compile error rather than a silent no-op once code depends on it.
fn main() {
    println!("cargo:rerun-if-changed=circuits/main.go");
    println!("cargo:rerun-if-changed=circuits/go.mod");
    println!("cargo:rerun-if-changed=circuits/go.sum");
    println!("cargo:rerun-if-changed=circuits/witness/witness.go");
    println!("cargo:rerun-if-changed=circuits/auditor_key_encryption/circuit.go");
    println!("cargo:rerun-if-changed=circuits/auditor_key_encryption/pack.go");
    println!("cargo:rustc-check-cfg=cfg(custom_ring_go_circuits)");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let go_dir = manifest_dir.join("circuits");
    let go_entrypoint = go_dir.join("main.go");
    if !go_entrypoint.exists() {
        println!(
            "cargo:warning=custom-ring-prover: {} is missing, skipping the cgo build; \
             the FFI surface stays disabled (cfg custom_ring_go_circuits unset)",
            go_entrypoint.display()
        );
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let lib_out = out_dir.join("libprover.a");

    let status = Command::new("go")
        .current_dir(&go_dir)
        .env("CGO_ENABLED", "1")
        .env("CC", "clang")
        .args(["mod", "tidy"])
        .status()
        .expect("failed to run go mod tidy");
    assert!(status.success(), "go mod tidy failed");

    let status = Command::new("go")
        .current_dir(&go_dir)
        .env("CGO_ENABLED", "1")
        .env("CC", "clang")
        .args([
            "build",
            "-buildmode=c-archive",
            "-o",
            lib_out.to_str().unwrap(),
            ".",
        ])
        .status()
        .expect("failed to run go build");
    assert!(status.success(), "go build failed");

    let header_path = out_dir.join("libprover.h");
    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().unwrap())
        .allowlist_function("Setup")
        .allowlist_function("LoadKeys")
        .allowlist_function("Prove")
        .allowlist_function("FreeProveResult")
        .allowlist_function("FreeString")
        .allowlist_type("C_ProveResult")
        .generate()
        .expect("failed to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=prover");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=resolv");
    }

    println!("cargo:rustc-cfg=custom_ring_go_circuits");
}
