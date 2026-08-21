use std::{env, fs, io, path::PathBuf};

const DEFAULT_PROGRAM_ID: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CUSTOM_RING_PROGRAM_ID");
    let program_id = env::var("CUSTOM_RING_PROGRAM_ID")
        .ok()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| DEFAULT_PROGRAM_ID.to_owned());
    let decoded = bs58::decode(&program_id).into_vec()?;
    if decoded.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CUSTOM_RING_PROGRAM_ID must decode to 32 bytes",
        )
        .into());
    }
    let out = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(
        out.join("program_id.rs"),
        format!("pinocchio::address::declare_id!(\"{program_id}\");\n"),
    )?;
    Ok(())
}
