use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use groth16_solana_bsb22::gnark_vk_parser::{bsb22_vk_to_rust_const, parse_gnark_vk_bytes};
use sha2::{Digest, Sha256};

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("create-verifying-keys") => {
            let options = CreateVerifyingKeysOptions::parse(args.collect());
            create_verifying_keys(options);
        }
        Some("generate-vkey-rs") => {
            let options = GenerateVkeyRsOptions::parse(args.collect());
            generate_vkey_rs(options);
        }
        Some("--help") | Some("-h") | None => print_help(),
        Some(command) => {
            eprintln!("unknown xtask command: {command}");
            print_help();
            std::process::exit(2);
        }
    }
}

#[derive(Debug)]
struct GenerateVkeyRsOptions {
    input_path: PathBuf,
    output_path: PathBuf,
    // When set, emit a standard groth16-solana verifying key (no bsb22
    // commitment) — used by circuits verified via light_verifier, e.g. the
    // nullifier batch-update tree.
    standard: bool,
}

impl GenerateVkeyRsOptions {
    fn parse(args: Vec<String>) -> Self {
        let mut input_path = None;
        let mut output_path = None;
        let mut standard = false;

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--input-path" => {
                    input_path = Some(
                        args.next()
                            .map(PathBuf::from)
                            .unwrap_or_else(|| usage_and_exit("--input-path missing value")),
                    );
                }
                "--output-path" => {
                    output_path = Some(
                        args.next()
                            .map(PathBuf::from)
                            .unwrap_or_else(|| usage_and_exit("--output-path missing value")),
                    );
                }
                "--standard" => standard = true,
                "--help" | "-h" => {
                    print_generate_vkey_rs_help();
                    std::process::exit(0);
                }
                other => usage_and_exit(&format!("unexpected arg {other:?}")),
            }
        }

        Self {
            input_path: input_path.unwrap_or_else(|| usage_and_exit("--input-path is required")),
            output_path: output_path.unwrap_or_else(|| usage_and_exit("--output-path is required")),
            standard,
        }
    }
}

#[derive(Debug)]
struct CreateVerifyingKeysOptions {
    keys_dir: PathBuf,
    out_dir: PathBuf,
    limit: Option<usize>,
}

impl CreateVerifyingKeysOptions {
    fn parse(args: Vec<String>) -> Self {
        let mut keys_dir = PathBuf::from("prover/server/proving-keys");
        let mut out_dir = env::var("ZOLANA_VERIFYING_KEYS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("target/verifying-keys"));
        let mut limit = env::var("ZOLANA_VERIFYING_KEYS_LIMIT")
            .ok()
            .map(|value| parse_limit(&value));

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--keys-dir" => {
                    keys_dir = args
                        .next()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| usage_and_exit("--keys-dir missing value"));
                }
                "--out-dir" => {
                    out_dir = args
                        .next()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| usage_and_exit("--out-dir missing value"));
                }
                "--limit" => {
                    let value = args
                        .next()
                        .unwrap_or_else(|| usage_and_exit("--limit missing value"));
                    limit = Some(parse_limit(&value));
                }
                "--help" | "-h" => {
                    print_create_verifying_keys_help();
                    std::process::exit(0);
                }
                other => usage_and_exit(&format!("unexpected arg {other:?}")),
            }
        }

        Self {
            keys_dir,
            out_dir,
            limit,
        }
    }
}

fn create_verifying_keys(options: CreateVerifyingKeysOptions) {
    let workspace_root = env::current_dir().expect("failed to resolve current directory");
    let keys_dir = absolute_path(&workspace_root, &options.keys_dir);
    let out_dir = absolute_path(&workspace_root, &options.out_dir);
    let prover_server_dir = workspace_root.join("prover/server");

    if !keys_dir.is_dir() {
        eprintln!(
            "proving key directory does not exist: {}",
            keys_dir.display()
        );
        std::process::exit(1);
    }
    if !prover_server_dir.is_dir() {
        eprintln!(
            "prover server directory does not exist: {}",
            prover_server_dir.display()
        );
        std::process::exit(1);
    }

    fs::create_dir_all(&out_dir).expect("failed to create verifying key output directory");

    let mut proving_keys = read_proving_keys(&keys_dir);
    if let Some(limit) = options.limit {
        proving_keys.truncate(limit);
    }
    if proving_keys.is_empty() {
        eprintln!("no proving keys found in {}", keys_dir.display());
        std::process::exit(1);
    }

    let mut manifest = String::from("# Generated verifying keys\n# sha256  bytes  filename\n");
    for key_path in proving_keys {
        let stem = key_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("proving key filename is not valid UTF-8");
        let output_path = out_dir.join(format!("{stem}.vkey"));

        println!(
            "exporting verifying key {} -> {}",
            key_path.display(),
            output_path.display()
        );
        export_verifying_key(&prover_server_dir, &key_path, &output_path);

        let metadata = fs::metadata(&output_path).unwrap_or_else(|error| {
            panic!(
                "failed to read generated verifying key {}: {error}",
                output_path.display()
            )
        });
        if metadata.len() == 0 {
            panic!(
                "generated verifying key is empty: {}",
                output_path.display()
            );
        }

        let hash = sha256_file(&output_path);
        manifest.push_str(&format!(
            "{hash}  {}  {}\n",
            metadata.len(),
            output_path
                .file_name()
                .expect("output filename missing")
                .to_string_lossy()
        ));
    }

    fs::write(out_dir.join("MANIFEST.txt"), manifest)
        .expect("failed to write verifying key manifest");
}

fn read_proving_keys(keys_dir: &Path) -> Vec<PathBuf> {
    let mut keys = fs::read_dir(keys_dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", keys_dir.display()))
        .map(|entry| {
            entry
                .expect("failed to read proving key directory entry")
                .path()
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("key"))
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn export_verifying_key(prover_server_dir: &Path, key_path: &Path, output_path: &Path) {
    let go = env::var("GO").unwrap_or_else(|_| "go".to_string());
    let status = Command::new(go)
        .current_dir(prover_server_dir)
        .args(["run", ".", "export-vk", "--keys-file"])
        .arg(key_path)
        .arg("--output")
        .arg(output_path)
        .status()
        .unwrap_or_else(|error| panic!("failed to run go export-vk: {error}"));

    if !status.success() {
        panic!("go export-vk failed with status {status}");
    }
}

fn generate_vkey_rs(options: GenerateVkeyRsOptions) {
    let input_path = options.input_path;
    let output_path = options.output_path;
    let bytes = read_vkey_bytes(&input_path);
    let code = if options.standard {
        standard_vk_to_rust_const(&bytes)
    } else {
        let vk = parse_gnark_vk_bytes(&bytes).expect("failed to parse gnark verifying key");
        bsb22_vk_to_rust_const(&vk, "VERIFYINGKEY").replace(
            "use groth16_solana::groth16::Groth16Verifyingkey;",
            "use groth16_solana_bsb22::groth16::Groth16Verifyingkey;",
        )
    };

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("failed to create vkey output directory");
    }
    let mut file = fs::File::create(&output_path).expect("failed to create vkey rs file");
    file.write_all(code.as_bytes())
        .expect("failed to write vkey rs");
    run_rustfmt(&output_path);
}

fn read_vkey_bytes(path: &Path) -> Vec<u8> {
    let bytes = fs::read(path)
        .unwrap_or_else(|error| panic!("failed to read verifying key {}: {error}", path.display()));
    if bytes.first() != Some(&b'[') {
        return bytes;
    }
    let text = String::from_utf8(bytes).expect("text vkey is not UTF-8");
    text.trim_matches(|p| p == '[' || p == ']')
        .split_whitespace()
        .map(|s| {
            s.parse::<u8>()
                .unwrap_or_else(|_| panic!("invalid vkey byte {s:?}"))
        })
        .collect()
}

/// Emits a standard groth16-solana `Groth16Verifyingkey` (no bsb22 commitment)
/// from gnark verifying-key bytes. Mirrors light-protocol's
/// `create_vkeyrs_from_gnark_key`, for circuits verified via `light_verifier`
/// such as the nullifier batch-update tree.
fn standard_vk_to_rust_const(gnark_vk_bytes: &[u8]) -> String {
    // gnark groth16 VerifyingKey.WriteTo layout (what WriteProvingSystem
    // serializes). groth16-solana skips [β]1/[δ]1, so we read at fixed offsets:
    //   [α]1: 0..64, [β]1: 64..128, [β]2: 128..256, [γ]2: 256..384,
    //   [δ]1: 384..448, [δ]2: 448..576, nr_ic: 576..580, IC: 580.. (64 bytes each)
    let alpha_g1 = &gnark_vk_bytes[0..64];
    let beta_g2 = &gnark_vk_bytes[128..256];
    let gamma_g2 = &gnark_vk_bytes[256..384];
    let delta_g2 = &gnark_vk_bytes[448..576];
    let nr_ic = u32::from_be_bytes(
        gnark_vk_bytes[576..580]
            .try_into()
            .expect("gnark vk too short for IC count"),
    ) as usize;
    let ic_start = 580;
    let ic: Vec<&[u8]> = (0..nr_ic)
        .map(|i| &gnark_vk_bytes[ic_start + i * 64..ic_start + (i + 1) * 64])
        .collect();
    // nr_pubinputs is the IC vector length minus the constant term.
    let nr_pubinputs = nr_ic - 1;

    let fmt_bytes = |b: &[u8]| {
        b.iter()
            .map(|x| format!("{x}u8"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let ic_arrays = ic
        .iter()
        .map(|slice| format!("[{}]", fmt_bytes(slice)))
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        "// This file is generated by xtask. Do not edit it manually.\n\n\
use groth16_solana::groth16::Groth16Verifyingkey;\n\
pub const VERIFYINGKEY: Groth16Verifyingkey = Groth16Verifyingkey {{\n\
nr_pubinputs: {nr_pubinputs}usize,\n\
vk_alpha_g1: [{alpha}],\n\
vk_beta_g2: [{beta}],\n\
vk_gamma_g2: [{gamma}],\n\
vk_delta_g2: [{delta}],\n\
vk_ic: &[{ic_arrays}],\n\
}};\n",
        alpha = fmt_bytes(alpha_g1),
        beta = fmt_bytes(beta_g2),
        gamma = fmt_bytes(gamma_g2),
        delta = fmt_bytes(delta_g2),
    )
}

fn run_rustfmt(path: &Path) {
    let status = Command::new("rustfmt")
        .arg(path)
        .status()
        .unwrap_or_else(|error| panic!("failed to run rustfmt: {error}"));
    if !status.success() {
        panic!("rustfmt failed with status {status}");
    }
}

fn sha256_file(path: &Path) -> String {
    let mut file = fs::File::open(path)
        .unwrap_or_else(|error| panic!("failed to open {}: {error}", path.display()));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    format!("{:x}", hasher.finalize())
}

fn absolute_path(workspace_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    }
}

fn parse_limit(value: &str) -> usize {
    value
        .parse::<usize>()
        .unwrap_or_else(|_| usage_and_exit("--limit must be a positive integer"))
}

fn usage_and_exit(msg: &str) -> ! {
    eprintln!("error: {msg}");
    print_create_verifying_keys_help();
    std::process::exit(2);
}

fn print_help() {
    println!("xtask <command>");
    println!();
    println!("Commands:");
    println!("  create-verifying-keys    Export prover-server verifying key artifacts");
    println!("  generate-vkey-rs         Convert a gnark verifying key into Rust constants");
}

fn print_create_verifying_keys_help() {
    println!("xtask create-verifying-keys [--keys-dir <dir>] [--out-dir <dir>] [--limit <n>]");
    println!();
    println!("Defaults:");
    println!("  --keys-dir prover/server/proving-keys");
    println!("  --out-dir  $ZOLANA_VERIFYING_KEYS_DIR or target/verifying-keys");
}

fn print_generate_vkey_rs_help() {
    println!("xtask generate-vkey-rs --input-path <path> --output-path <path> [--standard]");
    println!("  --standard  emit a standard groth16-solana key (no bsb22 commitment),");
    println!("              e.g. for the nullifier batch-update tree verified via light_verifier");
}
