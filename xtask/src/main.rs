use std::{env, fs, path::PathBuf};

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("create-verifying-keys") => create_verifying_keys(),
        Some("--help") | Some("-h") | None => print_help(),
        Some(command) => {
            eprintln!("unknown xtask command: {command}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn create_verifying_keys() {
    let out_dir = env::var("ZOLANA_VERIFYING_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/verifying-keys"));
    fs::create_dir_all(&out_dir).expect("failed to create verifying key output directory");
    fs::write(
        out_dir.join("README.md"),
        "Verifying key generation is scaffolded for the initial monorepo.\n",
    )
    .expect("failed to write verifying key scaffold marker");
}

fn print_help() {
    println!("xtask <command>");
    println!();
    println!("Commands:");
    println!("  create-verifying-keys    Create verifying key artifacts");
}
