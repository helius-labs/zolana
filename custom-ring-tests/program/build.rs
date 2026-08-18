//! The program id is a build-time input so a generated ring can pin its own
//! deploy address without editing sources: `CUSTOM_RING_PROGRAM_ID` (Cargo
//! `[env]` reaches build scripts) overrides the example's default. The sdk
//! re-exports the same constant, so one value serves every builder of a build.

use std::{env, fs, path::PathBuf};

const DEFAULT_PROGRAM_ID: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";

fn main() {
    println!("cargo:rerun-if-env-changed=CUSTOM_RING_PROGRAM_ID");
    let program_id = env::var("CUSTOM_RING_PROGRAM_ID")
        .ok()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| DEFAULT_PROGRAM_ID.to_owned());
    if !program_id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        panic!("CUSTOM_RING_PROGRAM_ID must be a base58 address, got {program_id:?}");
    }
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(
        out.join("program_id.rs"),
        format!("pinocchio::address::declare_id!(\"{program_id}\");\n"),
    )
    .expect("write program_id.rs");
}
