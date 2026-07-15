use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=circuits/main.go");
    println!("cargo:rerun-if-changed=circuits/go.mod");
    println!("cargo:rerun-if-changed=circuits/go.sum");
    println!("cargo:rerun-if-changed=circuits/make/make.go");
    println!("cargo:rerun-if-changed=circuits/cancel/cancel.go");
    println!("cargo:rerun-if-changed=circuits/take/take.go");
    println!("cargo:rerun-if-changed=circuits/take_verifiable_encryption/take.go");
    println!("cargo:rerun-if-changed=circuits/witness/witness.go");
    println!("cargo:rerun-if-changed=circuits/orderterms/orderterms.go");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let go_dir = manifest_dir.join("circuits");
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
}
