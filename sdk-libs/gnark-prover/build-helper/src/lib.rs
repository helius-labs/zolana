//! Build-script half of `zolana-gnark-prover`, kept dependency-free so it adds
//! nothing to the build-dependency graph. An example prover's `build.rs` is
//! `fn main() { zolana_gnark_prover_build::build_prover_archive() }`.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

/// Build the calling crate's `circuits/` Go `main` package into a C archive
/// and link it. The archive exports the `zolana/gnarkprover` bridge that
/// `zolana_gnark_prover::prover!` declares.
pub fn build_prover_archive() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let go_dir = manifest_dir.join("circuits");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let archive = out_dir.join("libprover.a");

    // The archive compiles the example's circuits, the shared bridge, and the
    // pool gadgets the circuits import, so a change to any of them must
    // rebuild it: a stale archive proves a circuit the keys were not made for.
    let helper_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for dir in [
        go_dir.clone(),
        helper_dir.join("../go"),
        helper_dir.join("../../../prover/server/circuits"),
    ] {
        println!("cargo:rerun-if-changed={}", dir.display());
    }

    go(&go_dir, &["mod", "tidy"]);
    go(
        &go_dir,
        &[
            "build",
            "-buildmode=c-archive",
            "-o",
            archive.to_str().expect("OUT_DIR is not valid UTF-8"),
            ".",
        ],
    );

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=prover");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=resolv");
    }
}

fn go(dir: &Path, args: &[&str]) {
    let status = Command::new("go")
        .current_dir(dir)
        .env("CGO_ENABLED", "1")
        .env("CC", "clang")
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run go {}: {e}", args.join(" ")));
    assert!(status.success(), "go {} failed", args.join(" "));
}
