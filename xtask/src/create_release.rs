use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::CreateTree, pda, state::tree_account_size, DEFAULT_TREE_ADDRESS,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::ZolanaProgramTest;

const DEFAULT_SURFPOOL_TAG: &str = "v1.1.1-light";
const DEFAULT_SURFPOOL_VERSION: &str = "1.1.1";

// Cross-compile photon for linux-x64 inside a matching-toolchain container
// (see rust-toolchain.toml). linux/amd64 builds the x86_64-linux binary natively
// in the container, avoiding a host cross-linker.
const PHOTON_LINUX_BUILDER_IMAGE: &str = "rust:1.97-bookworm";

pub struct Options {
    tag: String,
    deploy_dir: PathBuf,
    staging_dir: PathBuf,
    lock_path: PathBuf,
    upload: bool,
    prerelease: bool,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut tag = None;
        let mut deploy_dir = PathBuf::from("target/deploy");
        let mut staging_dir = PathBuf::from("target/release-staging");
        let mut lock_path = PathBuf::from("cli/release-artifacts.lock");
        let mut upload = false;
        let mut prerelease = false;

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let mut next = |flag: &str| {
                args.next()
                    .unwrap_or_else(|| usage_and_exit(&format!("{flag} missing value")))
            };
            match arg.as_str() {
                "--tag" => tag = Some(next("--tag")),
                "--deploy-dir" => deploy_dir = PathBuf::from(next("--deploy-dir")),
                "--staging-dir" => staging_dir = PathBuf::from(next("--staging-dir")),
                "--lock-path" => lock_path = PathBuf::from(next("--lock-path")),
                "--upload" => upload = true,
                "--prerelease" => prerelease = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => usage_and_exit(&format!("unexpected arg {other:?}")),
            }
        }

        Self {
            tag: tag.unwrap_or_else(|| usage_and_exit("--tag is required")),
            deploy_dir,
            staging_dir,
            lock_path,
            upload,
            prerelease,
        }
    }
}

struct ProgramSource {
    role: &'static str,
    file: &'static str,
    asset_stem: &'static str,
}

const PROGRAM_SOURCES: [ProgramSource; 3] = [
    ProgramSource {
        role: "shielded_pool",
        file: "shielded_pool_program.so",
        asset_stem: "shielded_pool_program",
    },
    ProgramSource {
        role: "user_registry",
        file: "zolana_user_registry.so",
        asset_stem: "zolana_user_registry",
    },
    ProgramSource {
        role: "smart_account",
        file: "squads_smart_account_program.so",
        asset_stem: "squads_smart_account_program",
    },
];

pub fn run(options: Options) -> Result<()> {
    let (os, arch) = current_platform()?;

    // Fail early with actionable guidance if any source artifact is missing.
    let program_paths = PROGRAM_SOURCES
        .iter()
        .map(|source| {
            let path = options.deploy_dir.join(source.file);
            require_file(
                &path,
                "run `just build-programs` (and `just fetch-smart-account`) first",
            )?;
            Ok((source, path))
        })
        .collect::<Result<Vec<_>>>()?;

    let staging = &options.staging_dir;
    reset_dir(staging)?;
    let accounts_dir = staging.join("accounts");
    fs::create_dir_all(&accounts_dir)
        .with_context(|| format!("failed to create {}", accounts_dir.display()))?;

    generate_account_snapshots(&options, &accounts_dir)?;

    // Bundle the snapshot directory; the CLI extracts it into --account-dir.
    let accounts_asset = format!("accounts-{}.tar.gz", options.tag);
    let accounts_archive = staging.join(&accounts_asset);
    tar_gz(&accounts_dir, &accounts_archive)?;

    let mut programs_json = Vec::new();
    for (source, path) in &program_paths {
        let asset = format!("{}-{}.so", source.asset_stem, options.tag);
        let staged = stage_file(path, &staging.join(&asset))?;
        programs_json.push(json!({
            "role": source.role,
            "asset": asset,
            "size": staged.size,
            "sha256": staged.sha256,
        }));
    }

    let accounts_staged = checksum_file(&accounts_archive)?;
    let accounts_json = json!({
        "asset": accounts_asset,
        "size": accounts_staged.size,
        "sha256": accounts_staged.sha256,
    });

    let binaries_json = build_binaries(&options, staging, (os, arch))?;

    let (surfpool_tag, surfpool_version) = existing_surfpool_fields(&options.lock_path);
    let lock = json!({
        "release_tag": options.tag,
        "surfpool_tag": surfpool_tag,
        "surfpool_version": surfpool_version,
        "programs": programs_json,
        "accounts": accounts_json,
        "binaries": binaries_json,
    });
    let mut serialized = serde_json::to_string_pretty(&lock)?;
    serialized.push('\n');
    fs::write(&options.lock_path, serialized)
        .with_context(|| format!("failed to write {}", options.lock_path.display()))?;
    println!("wrote lockfile {}", options.lock_path.display());

    let assets = staged_asset_paths(staging, &lock);
    if options.upload {
        upload_release(&options.tag, &assets, options.prerelease, &git_head()?)?;
    } else {
        println!(
            "dry run (pass --upload to publish). Assets staged in {}:",
            staging.display()
        );
        for asset in &assets {
            println!("  {}", asset.display());
        }
    }

    Ok(())
}

/// Build the prover (Go) and photon (Rust) binaries for the host platform and,
/// when the host is not already linux-x64, cross-build the linux-x64 pair. The
/// Go prover cross-compiles natively; photon-linux-x64 builds in a Docker
/// container so no host cross-linker is required.
fn build_binaries(options: &Options, staging: &Path, host: (&str, &str)) -> Result<Vec<Value>> {
    let mut targets = vec![host];
    if host != ("linux", "x64") {
        targets.push(("linux", "x64"));
    }

    let repo = repo_root()?;
    let mut out = Vec::new();
    for (os, arch) in targets {
        let prover_asset = format!("prover-{os}-{arch}-{}", options.tag);
        let prover_path = staging.join(&prover_asset);
        build_prover(&repo, os, arch, &prover_path)?;
        out.push(binary_json(
            "prover",
            os,
            arch,
            &prover_asset,
            &prover_path,
        )?);

        let photon_asset = format!("photon-{os}-{arch}-{}", options.tag);
        let photon_path = staging.join(&photon_asset);
        if (os, arch) == host {
            build_photon_host(&repo, &photon_path)?;
        } else if (os, arch) == ("linux", "x64") {
            build_photon_linux_x64(&repo, &photon_path)?;
        } else {
            bail!("no photon builder for {os}-{arch}");
        }
        out.push(binary_json(
            "photon",
            os,
            arch,
            &photon_asset,
            &photon_path,
        )?);
    }
    Ok(out)
}

fn binary_json(role: &str, os: &str, arch: &str, asset: &str, path: &Path) -> Result<Value> {
    let staged = checksum_file(path)?;
    Ok(json!({
        "role": role,
        "os": os,
        "arch": arch,
        "asset": asset,
        "size": staged.size,
        "sha256": staged.sha256,
    }))
}

fn build_prover(repo: &Path, os: &str, arch: &str, out: &Path) -> Result<()> {
    let goos = match os {
        "linux" => "linux",
        "darwin" => "darwin",
        other => bail!("unsupported prover OS {other}"),
    };
    let goarch = match arch {
        "x64" => "amd64",
        "arm64" => "arm64",
        other => bail!("unsupported prover arch {other}"),
    };
    println!("building prover {os}-{arch}");
    // `go build` runs in prover/server, so the -o path must be absolute or it
    // would resolve relative to that dir instead of the repo-root staging dir.
    let out_abs = if out.is_absolute() {
        out.to_path_buf()
    } else {
        repo.join(out)
    };
    let status = Command::new("go")
        .current_dir(repo.join("prover/server"))
        .env("CGO_ENABLED", "0")
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .arg("build")
        .arg("-o")
        .arg(&out_abs)
        .arg(".")
        .status()
        .context("failed to run go build for prover")?;
    if !status.success() {
        bail!("go build failed for prover {os}-{arch}");
    }
    Ok(())
}

fn build_photon_host(repo: &Path, out: &Path) -> Result<()> {
    println!("building photon (host)");
    let status = Command::new("cargo")
        .current_dir(repo)
        .args([
            "build",
            "--release",
            "-p",
            "photon-indexer",
            "--bin",
            "photon",
        ])
        .status()
        .context("failed to run cargo build for photon")?;
    if !status.success() {
        bail!("cargo build failed for photon (host)");
    }
    fs::copy(repo.join("target/release/photon"), out)
        .with_context(|| format!("failed to stage host photon to {}", out.display()))?;
    Ok(())
}

fn build_photon_linux_x64(repo: &Path, out: &Path) -> Result<()> {
    println!("building photon linux-x64 (docker {PHOTON_LINUX_BUILDER_IMAGE})");
    let mount = format!("{}:/work", path_str(repo)?);
    let build = "set -e; apt-get update -qq && apt-get install -y -qq pkg-config libssl-dev protobuf-compiler cmake clang build-essential >/dev/null 2>&1; cargo build --release -p photon-indexer --bin photon --target-dir /work/target-linux-x64";
    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "-v",
            &mount,
            "-w",
            "/work",
        ])
        .arg(PHOTON_LINUX_BUILDER_IMAGE)
        .args(["bash", "-c", build])
        .status()
        .context("failed to run docker for photon linux-x64 build")?;
    if !status.success() {
        bail!("docker photon linux-x64 build failed");
    }
    fs::copy(repo.join("target-linux-x64/release/photon"), out)
        .with_context(|| format!("failed to stage linux photon to {}", out.display()))?;
    Ok(())
}

fn repo_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to run git rev-parse --show-toplevel")?;
    if !output.status.success() {
        bail!("git rev-parse --show-toplevel failed");
    }
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}

fn git_head() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .context("failed to run git rev-parse HEAD")?;
    if !output.status.success() {
        bail!("git rev-parse HEAD failed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Build the initialized account set fully in-process with LiteSVM. No maintainer
/// keypairs and no running validator are needed: every authority is generated
/// here, and the pool tree is pre-allocated directly at DEFAULT_TREE_ADDRESS so
/// its baked-in `hashed_pubkey` stays correct without the tree keypair.
fn generate_account_snapshots(options: &Options, accounts_dir: &Path) -> Result<()> {
    let shielded_so = options.deploy_dir.join("shielded_pool_program.so");
    let mut test = ZolanaProgramTest::with_program_path(&shielded_so)
        .map_err(|e| anyhow!("failed to boot litesvm: {e:?}"))?;

    let authority = Keypair::new();
    test.create_protocol_config_permissionless(&authority)
        .map_err(|e| anyhow!("create_protocol_config failed: {e:?}"))?;
    test.create_asset_counter(&authority)
        .map_err(|e| anyhow!("create_asset_counter failed: {e:?}"))?;

    // Pre-allocate the tree at the canonical address, then initialize it. The
    // program requires the tree account to be program-owned and correctly sized
    // but not a signer, so no tree keypair is required.
    let tree: Pubkey = DEFAULT_TREE_ADDRESS
        .parse()
        .context("parsing DEFAULT_TREE_ADDRESS")?;
    let size = tree_account_size();
    let rent = test.svm.minimum_balance_for_rent_exemption(size);
    test.svm
        .set_account(
            tree,
            Account {
                lamports: rent,
                data: vec![0u8; size],
                owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
                executable: false,
                rent_epoch: u64::MAX,
            },
        )
        .map_err(|e| anyhow!("failed to pre-allocate tree account: {e:?}"))?;
    let create_tree_ix = CreateTree {
        authority: authority.pubkey(),
        tree,
        owner: authority.pubkey(),
    }
    .instruction();
    test.create_and_send_default_payer_transaction(&[create_tree_ix], &[&authority])
        .map_err(|e| anyhow!("create_tree failed: {e:?}"))?;

    for (label, pubkey) in [
        ("protocol_config", pda::protocol_config()),
        ("spl_asset_counter", pda::spl_asset_counter()),
        ("tree", tree),
    ] {
        let account = test
            .svm
            .get_account(&pubkey)
            .ok_or_else(|| anyhow!("{label} account {pubkey} missing after init"))?;
        write_account_json(accounts_dir, &pubkey, &account)?;
        println!("snapshot {label} {pubkey}");
    }

    Ok(())
}

fn write_account_json(dir: &Path, pubkey: &Pubkey, account: &Account) -> Result<()> {
    let json = account_json(pubkey, account);
    let path = dir.join(format!("{pubkey}.json"));
    fs::write(&path, serde_json::to_string(&json)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn account_json(pubkey: &Pubkey, account: &Account) -> Value {
    json!({
        "pubkey": pubkey.to_string(),
        "account": {
            "lamports": account.lamports,
            "data": [STANDARD.encode(&account.data), "base64"],
            "owner": account.owner.to_string(),
            "executable": account.executable,
            "rentEpoch": account.rent_epoch,
        }
    })
}

struct Checksum {
    size: u64,
    sha256: String,
}

fn stage_file(src: &Path, dest: &Path) -> Result<Checksum> {
    fs::copy(src, dest)
        .with_context(|| format!("failed to copy {} -> {}", src.display(), dest.display()))?;
    checksum_file(dest)
}

fn checksum_file(path: &Path) -> Result<Checksum> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(Checksum {
        size: bytes.len() as u64,
        sha256: sha256_hex(&bytes),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn staged_asset_paths(staging: &Path, lock: &Value) -> Vec<PathBuf> {
    let mut names = Vec::new();
    if let Some(programs) = lock.get("programs").and_then(Value::as_array) {
        names.extend(programs.iter().filter_map(asset_name));
    }
    if let Some(name) = lock.get("accounts").and_then(asset_name) {
        names.push(name);
    }
    if let Some(binaries) = lock.get("binaries").and_then(Value::as_array) {
        names.extend(binaries.iter().filter_map(asset_name));
    }
    names.iter().map(|name| staging.join(name)).collect()
}

fn asset_name(value: &Value) -> Option<String> {
    value
        .get("asset")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn existing_surfpool_fields(lock_path: &Path) -> (String, String) {
    let fallback = (
        DEFAULT_SURFPOOL_TAG.to_string(),
        DEFAULT_SURFPOOL_VERSION.to_string(),
    );
    let Ok(contents) = fs::read_to_string(lock_path) else {
        return fallback;
    };
    let Ok(value) = serde_json::from_str::<Value>(&contents) else {
        return fallback;
    };
    let tag = value
        .get("surfpool_tag")
        .and_then(Value::as_str)
        .map(str::to_string);
    let version = value
        .get("surfpool_version")
        .and_then(Value::as_str)
        .map(str::to_string);
    match (tag, version) {
        (Some(tag), Some(version)) => (tag, version),
        _ => fallback,
    }
}

fn upload_release(tag: &str, assets: &[PathBuf], prerelease: bool, target: &str) -> Result<()> {
    // Delete any existing release + tag so the re-publish is clean and the tag is
    // recreated at the released commit. Best-effort: ignore "not found".
    let _ = Command::new("gh")
        .args(["release", "delete", tag, "--yes", "--cleanup-tag"])
        .status();

    let mut args = vec![
        "release".to_string(),
        "create".to_string(),
        tag.to_string(),
        "--target".to_string(),
        target.to_string(),
        "--title".to_string(),
        tag.to_string(),
        "--notes".to_string(),
        format!("Zolana localnet artifacts {tag}"),
    ];
    if prerelease {
        args.push("--prerelease".to_string());
    }
    for asset in assets {
        args.push(path_str(asset)?);
    }
    let status = Command::new("gh")
        .args(&args)
        .status()
        .context("failed to run gh release create")?;
    if !status.success() {
        bail!("gh release create failed with status {status}");
    }
    println!("published release {tag} at {target}");
    Ok(())
}

fn current_platform() -> Result<(&'static str, &'static str)> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => bail!("unsupported OS: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => bail!("unsupported architecture: {other}"),
    };
    Ok((os, arch))
}

fn tar_gz(source_dir: &Path, archive: &Path) -> Result<()> {
    let status = Command::new("tar")
        .arg("-czf")
        .arg(archive)
        .arg("-C")
        .arg(source_dir)
        .arg(".")
        .status()
        .with_context(|| format!("failed to tar {}", source_dir.display()))?;
    if !status.success() {
        bail!("tar failed for {}", source_dir.display());
    }
    Ok(())
}

fn reset_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| format!("failed to clean {}", dir.display()))?;
    }
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(())
}

fn require_file(path: &Path, hint: &str) -> Result<()> {
    if !path.is_file() {
        bail!("missing artifact {}: {hint}", path.display());
    }
    Ok(())
}

fn path_str(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", path.display()))
}

fn usage_and_exit(msg: &str) -> ! {
    eprintln!("error: {msg}");
    print_help();
    std::process::exit(2);
}

fn print_help() {
    println!("xtask create-release --tag <tag> [options]");
    println!();
    println!("Builds the localnet release: version-suffixed program .so files, an");
    println!("account-snapshot bundle generated in-process with LiteSVM (no keypairs");
    println!("or running validator needed), and the prover/photon binaries for the host");
    println!("platform plus linux-x64 (Go cross-compile for the prover; Docker for the");
    println!("linux photon), then regenerates cli/release-artifacts.lock.");
    println!();
    println!("Requires: go, cargo, and docker (for the linux-x64 photon build).");
    println!();
    println!("Options:");
    println!("  --deploy-dir <dir>      Program .so directory (default target/deploy)");
    println!("  --staging-dir <dir>     Asset staging dir (default target/release-staging)");
    println!(
        "  --lock-path <path>      Lockfile to regenerate (default cli/release-artifacts.lock)"
    );
    println!("  --upload                Publish via `gh release create` (default: dry run)");
    println!(
        "  --prerelease            Mark the GitHub release as a pre-release (e.g. alpha tags)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn account_json_uses_solana_dump_format() {
        let pubkey = Pubkey::new_from_array([7u8; 32]);
        let account = Account {
            lamports: 42,
            data: vec![1, 2, 3],
            owner: Pubkey::new_from_array([9u8; 32]),
            executable: false,
            rent_epoch: u64::MAX,
        };
        let value = account_json(&pubkey, &account);
        assert_eq!(value["pubkey"], pubkey.to_string());
        assert_eq!(value["account"]["lamports"], 42);
        assert_eq!(value["account"]["data"][0], STANDARD.encode([1, 2, 3]));
        assert_eq!(value["account"]["data"][1], "base64");
        assert_eq!(value["account"]["owner"], account.owner.to_string());
        assert_eq!(value["account"]["executable"], false);
        assert_eq!(value["account"]["rentEpoch"], u64::MAX);
    }

    #[test]
    fn staged_asset_paths_lists_every_asset() {
        let lock = json!({
            "programs": [{"asset": "a.so"}, {"asset": "b.so"}],
            "accounts": {"asset": "accounts.tar.gz"},
            "binaries": [{"asset": "prover"}, {"asset": "photon"}],
        });
        let paths = staged_asset_paths(Path::new("/stage"), &lock);
        let names: Vec<_> = paths
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(
            names,
            ["a.so", "b.so", "accounts.tar.gz", "prover", "photon"]
        );
    }
}
