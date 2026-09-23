use std::path::PathBuf;

use compression_example_prover::setup;

fn main() {
    let mut args = std::env::args().skip(1);
    let build_dir = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage_and_exit("missing <build-dir>"));
    let rust_vk_path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage_and_exit("missing <rust-vk>"));
    if let Some(other) = args.next() {
        usage_and_exit(&format!("unexpected arg {other:?}"));
    }

    println!("running setup for the read circuit");
    println!("  build dir : {}", build_dir.display());
    println!("  rust vk   : {}", rust_vk_path.display());
    setup(&build_dir).expect("setup failed");

    let vk_bin = build_dir.join("vk.bin");
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
    eprintln!("usage: compression-example-prover-setup <build-dir> <rust-vk>");
    eprintln!("  build-dir: where pk.bin / vk.bin are written");
    eprintln!("  rust-vk: path of the generated Rust verifying key source");
    std::process::exit(2);
}
