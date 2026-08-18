//! The program id is a build-time input so a generated ring can pin its own
//! deploy address without editing sources: `CUSTOM_RING_PROGRAM_ID` (Cargo
//! `[env]` reaches build scripts) overrides the example's default. The sdk
//! re-exports the same constant, so one value serves every builder of a build.

use std::{env, fs, path::PathBuf};

const DEFAULT_PROGRAM_ID: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CUSTOM_RING_PROGRAM_ID");
    let program_id = env::var("CUSTOM_RING_PROGRAM_ID")
        .ok()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| DEFAULT_PROGRAM_ID.to_owned());
    // Anything else would still fail in `declare_id!`, but with a worse message
    // and, for a quote, inside the generated source.
    let decoded = bs58::decode(&program_id)
        .into_vec()
        .unwrap_or_else(|_| panic!("CUSTOM_RING_PROGRAM_ID is not base58: {program_id:?}"));
    assert_eq!(
        decoded.len(),
        32,
        "CUSTOM_RING_PROGRAM_ID must decode to 32 bytes: {program_id:?}"
    );
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(
        out.join("program_id.rs"),
        format!("pinocchio::address::declare_id!(\"{program_id}\");\n"),
    )
    .expect("write program_id.rs");
}
