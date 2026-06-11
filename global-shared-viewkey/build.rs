use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=go/shamir_ffi.go");
    println!("cargo:rerun-if-changed=go/go.mod");
    println!("cargo:rerun-if-changed=go/go.sum");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let go_dir = manifest_dir.join("go");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let lib_out = out_dir.join("libshamir_ffi.a");

    let status = Command::new("go")
        .current_dir(&go_dir)
        .env("CGO_ENABLED", "1")
        .env("CC", "clang")
        .args([
            "build",
            "-buildmode=c-archive",
            "-o",
            lib_out.to_str().expect("OUT_DIR path is valid UTF-8"),
            ".",
        ])
        .status()
        .expect("failed to run `go build`; is the Go toolchain installed?");
    assert!(status.success(), "go build -buildmode=c-archive failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=shamir_ffi");

    match env::var("CARGO_CFG_TARGET_OS").unwrap_or_default().as_str() {
        "macos" => {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=resolv");
        }
        "linux" => {
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=dl");
        }
        _ => {}
    }
}
