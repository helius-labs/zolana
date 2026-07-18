use std::path::PathBuf;

use timelock_escrow_prover::{setup, CircuitId};

fn main() {
    let mut args = std::env::args().skip(1);
    let circuit_arg = args
        .next()
        .unwrap_or_else(|| usage_and_exit("missing <circuit>"));
    let build_dir = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage_and_exit("missing <build-dir>"));

    let mut rust_vk_path: Option<PathBuf> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--rust-vk" => {
                let rust_vk_arg = args
                    .next()
                    .unwrap_or_else(|| usage_and_exit("--rust-vk missing value"));
                rust_vk_path = Some(PathBuf::from(rust_vk_arg));
            }
            other => usage_and_exit(&format!("unexpected arg {other:?}")),
        }
    }

    let circuit = match circuit_arg.to_lowercase().as_str() {
        "escrow" => CircuitId::Escrow,
        "withdraw" => CircuitId::Withdraw,
        other => usage_and_exit(&format!("unknown circuit {other:?}")),
    };

    let rust_vk_path = rust_vk_path.unwrap_or_else(|| {
        let circuit_name = match circuit {
            CircuitId::Escrow => "escrow",
            CircuitId::Withdraw => "withdraw",
        };
        build_dir.join(format!("{circuit_name}_verifying_key.rs"))
    });

    println!("running setup for {circuit:?}");
    println!("  build dir : {}", build_dir.display());
    println!("  rust vk   : {}", rust_vk_path.display());
    setup(circuit, &build_dir).expect("setup failed");

    let vk_bin = build_dir.join("vk.bin");
    println!("emitting Rust VK source from {}", vk_bin.display());

    let out_dir = rust_vk_path
        .parent()
        .expect("rust-vk path has no parent directory");
    let out_filename = rust_vk_path
        .file_name()
        .expect("rust-vk path has no file name")
        .to_str()
        .expect("rust-vk filename is not valid UTF-8");
    groth16_solana::vk::gnark::generate_bsb22_vk_file(
        &vk_bin,
        out_dir,
        out_filename,
        "VERIFYINGKEY",
    )
    .expect("failed to emit Rust verifying key source");
    let _ = std::process::Command::new("rustfmt")
        .arg("--edition")
        .arg("2021")
        .arg(&rust_vk_path)
        .status();
    println!("done");
}

fn usage_and_exit(msg: &str) -> ! {
    eprintln!("error: {msg}");
    eprintln!("usage: timelock-escrow-prover-setup <circuit> <build-dir> [--rust-vk <path>]");
    eprintln!("  circuit: escrow | withdraw");
    eprintln!("  build-dir: where pk.bin / vk.bin are written");
    eprintln!("  --rust-vk: optional override for the generated Rust source path");
    std::process::exit(2);
}
