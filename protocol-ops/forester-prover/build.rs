use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=GO");
    if env::var_os("CARGO_FEATURE_GNARK").is_none() {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let mut build = Command::new(env::var_os("GO").unwrap_or_else(|| "go".into()));
    build
        .current_dir(root.join("go"))
        .args([
            "build",
            "-mod=readonly",
            "-trimpath",
            "-buildmode=c-archive",
            "-o",
        ])
        .arg(out.join("libforester_prover.a"))
        .arg(".")
        .env("CGO_ENABLED", "1");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo sets target architecture");
    build.env(
        "GOARCH",
        match arch.as_str() {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => other,
        },
    );
    let os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo sets target OS");
    build.env("GOOS", if os == "macos" { "darwin" } else { &os });
    let status = build.status().expect("run Go compiler for forester prover");
    assert!(
        status.success(),
        "Go forester prover archive failed to build"
    );
    for path in [
        "go",
        "../../prover/server/go.mod",
        "../../prover/server/go.sum",
        "../../prover/server/prover",
        "../../prover/server/circuits",
        "../../prover/server/merkle-tree",
        "../../prover/server/logging",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=forester_prover");
    if os == "macos" {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=resolv");
    } else if os == "linux" {
        for lib in ["pthread", "dl", "m", "resolv"] {
            println!("cargo:rustc-link-lib={lib}");
        }
    }
}
