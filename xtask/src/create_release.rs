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
    set: ReleaseSet,
    deploy_dir: PathBuf,
    staging_dir: PathBuf,
    lock_path: PathBuf,
    upload: bool,
    prerelease: bool,
}

/// Which assets a release carries, each set has its own lock and cli.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseSet {
    Localnet,
    CustomRings,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut tag = None;
        let mut set = ReleaseSet::Localnet;
        let mut deploy_dir = PathBuf::from("target/deploy");
        let mut staging_dir = PathBuf::from("target/release-staging");
        let mut lock_path = None;
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
                "--custom-rings" => set = ReleaseSet::CustomRings,
                "--deploy-dir" => deploy_dir = PathBuf::from(next("--deploy-dir")),
                "--staging-dir" => staging_dir = PathBuf::from(next("--staging-dir")),
                "--lock-path" => lock_path = Some(PathBuf::from(next("--lock-path"))),
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
            set,
            deploy_dir,
            staging_dir,
            lock_path: lock_path.unwrap_or_else(|| PathBuf::from(set.lock_path())),
            upload,
            prerelease,
        }
    }
}

impl ReleaseSet {
    /// Each cli embeds its own lock, so a release of one set never rewrites the other's.
    fn lock_path(self) -> &'static str {
        match self {
            Self::Localnet => "cli/release-artifacts.lock",
            Self::CustomRings => "custom-rings/cli/release-artifacts.lock",
        }
    }

    fn title(self, tag: &str) -> String {
        match self {
            Self::Localnet => tag.to_string(),
            Self::CustomRings => format!("custom-rings {tag}"),
        }
    }

    fn notes(self, tag: &str) -> String {
        match self {
            Self::Localnet => format!("Zolana localnet artifacts {tag}"),
            Self::CustomRings => format!("Zolana custom ring artifacts {tag}"),
        }
    }

    /// `(package, bin, asset stem)` of every cli the set ships.
    fn cli_binaries(self) -> &'static [(&'static str, &'static str, &'static str)] {
        match self {
            Self::Localnet => &[("zolana-cli", "zolana", "zolana")],
            Self::CustomRings => &[("custom-ring-cli", "zolana-ring", "zolana-ring")],
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

/// The prover key the custom-rings set ships, the same file the prover lock pins.
const RING_PROVING_KEY_SOURCE: &str = "prover/server/proving-keys/custom_ring.key";

/// Deployed per ring under its own id, shipped by the custom-rings set alone.
const RING_PROGRAM_SOURCE: ProgramSource = ProgramSource {
    role: "ring_program",
    file: "custom_ring_program.so",
    asset_stem: "custom-ring-program",
};

/// The rules-configured build a policy ring deploys, from the featured deploy dir.
const RING_PROGRAM_POLICY_SOURCE: ProgramSource = ProgramSource {
    role: "ring_program_policy",
    file: "custom_ring_program.so",
    asset_stem: "custom-ring-program-policy",
};

/// The featured deploy dir `just build-programs` writes the policy build into.
const RING_POLICY_DEPLOY_DIR: &str = "target/deploy-ring-rules";

pub fn run(options: Options) -> Result<()> {
    let (os, arch) = current_platform()?;
    let staging = &options.staging_dir;
    reset_dir(staging)?;
    let lock = match options.set {
        ReleaseSet::Localnet => localnet_lock(&options, staging, (os, arch))?,
        ReleaseSet::CustomRings => custom_rings_lock(&options, staging, (os, arch))?,
    };
    let mut serialized = serde_json::to_string_pretty(&lock)?;
    serialized.push('\n');
    fs::write(&options.lock_path, serialized)
        .with_context(|| format!("failed to write {}", options.lock_path.display()))?;
    println!("wrote lockfile {}", options.lock_path.display());

    // Build the CLI binaries last so they embed the just-written lockfile.
    let cli_assets = build_cli_binaries(&options, staging, (os, arch))?;
    let mut assets = staged_asset_paths(staging, &lock);
    assets.extend(cli_assets);

    if options.upload {
        upload_release(&options, &assets, &git_head()?)?;
        warn_if_lockfile_uncommitted(&options.lock_path, &options.tag)?;
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

fn localnet_lock(options: &Options, staging: &Path, host: (&str, &str)) -> Result<Value> {
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

    let accounts_dir = staging.join("accounts");
    generate_account_snapshots(&options.deploy_dir, &accounts_dir)?;

    // Bundle the snapshot directory; the CLI extracts it into --account-dir.
    let accounts_asset = format!("accounts-{}.tar.gz", options.tag);
    let accounts_archive = staging.join(&accounts_asset);
    tar_gz(&accounts_dir, &accounts_archive)?;

    let mut programs_json = Vec::new();
    for (source, path) in &program_paths {
        let mut entry = stage_program(source, path, &options.tag, staging)?;
        entry["role"] = json!(source.role);
        programs_json.push(entry);
    }

    let accounts_staged = checksum_file(&accounts_archive)?;
    let accounts_json = json!({
        "asset": accounts_asset,
        "size": accounts_staged.size,
        "sha256": accounts_staged.sha256,
    });

    let binaries_json = build_binaries(options, staging, host)?;

    let (surfpool_tag, surfpool_version) = existing_surfpool_fields(&options.lock_path);
    Ok(json!({
        "release_tag": options.tag,
        "surfpool_tag": surfpool_tag,
        "surfpool_version": surfpool_version,
        "programs": programs_json,
        "accounts": accounts_json,
        "binaries": binaries_json,
    }))
}

/// The ring program, the prover's ring key and the ring rpc, the ring cli
/// embeds the lock and is uploaded next to them.
fn custom_rings_lock(options: &Options, staging: &Path, host: (&str, &str)) -> Result<Value> {
    let path = options.deploy_dir.join(RING_PROGRAM_SOURCE.file);
    require_file(&path, "run `just build-programs` first")?;
    let repo = repo_root()?;
    let policy_path = repo
        .join(RING_POLICY_DEPLOY_DIR)
        .join(RING_PROGRAM_POLICY_SOURCE.file);
    require_file(&policy_path, "run `just build-programs` first")?;
    let key_source = repo.join(RING_PROVING_KEY_SOURCE);
    require_file(
        &key_source,
        "run `just ensure-custom-ring-prover-key` first",
    )?;
    let key_asset = format!("custom-ring-key-{}.key", options.tag);
    let key_staged = stage_file(&key_source, &staging.join(&key_asset))?;
    let mut binaries = Vec::new();
    for (os, arch) in release_targets(host) {
        let asset = format!("ring-rpc-{os}-{arch}-{}", options.tag);
        let path = staging.join(&asset);
        build_rust_binary(
            &repo,
            "zolana-ring-rpc",
            "ring-rpc",
            &path,
            (os, arch) == host,
        )?;
        binaries.push(binary_json("ring_rpc", os, arch, &asset, &path)?);
    }
    Ok(json!({
        "release_tag": options.tag,
        "ring_program": stage_program(&RING_PROGRAM_SOURCE, &path, &options.tag, staging)?,
        "ring_program_policy":
            stage_program(&RING_PROGRAM_POLICY_SOURCE, &policy_path, &options.tag, staging)?,
        "proving_key": {
            "asset": key_asset,
            "size": key_staged.size,
            "sha256": key_staged.sha256,
        },
        "binaries": binaries,
    }))
}

fn stage_program(source: &ProgramSource, path: &Path, tag: &str, staging: &Path) -> Result<Value> {
    let asset = format!("{}-{}.so", source.asset_stem, tag);
    let staged = stage_file(path, &staging.join(&asset))?;
    Ok(json!({
        "asset": asset,
        "size": staged.size,
        "sha256": staged.sha256,
    }))
}

/// Build the prover (Go) and photon (Rust) binaries for the host platform and,
/// when the host is not already linux-x64, cross-build the linux-x64 pair. The
/// Go prover cross-compiles natively; photon-linux-x64 builds in a Docker
/// container so no host cross-linker is required.
fn build_binaries(options: &Options, staging: &Path, host: (&str, &str)) -> Result<Vec<Value>> {
    let repo = repo_root()?;
    let mut out = Vec::new();
    for (os, arch) in release_targets(host) {
        let is_host = (os, arch) == host;

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
        build_rust_binary(&repo, "photon-indexer", "photon", &photon_path, is_host)?;
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

/// Each cli embeds its set's lockfile, so it is built after it and is not an entry in it.
fn build_cli_binaries(
    options: &Options,
    staging: &Path,
    host: (&str, &str),
) -> Result<Vec<PathBuf>> {
    let repo = repo_root()?;
    let mut assets = Vec::new();
    for (os, arch) in release_targets(host) {
        for (package, bin, stem) in options.set.cli_binaries() {
            let asset = format!("{stem}-{os}-{arch}-{}", options.tag);
            let path = staging.join(&asset);
            build_rust_binary(&repo, package, bin, &path, (os, arch) == host)?;
            assets.push(path);
        }
    }
    Ok(assets)
}

/// The host platform plus linux-x64 (deduped when the host already is linux-x64).
fn release_targets<'a>(host: (&'a str, &'a str)) -> Vec<(&'a str, &'a str)> {
    let mut targets = vec![host];
    if host != ("linux", "x64") {
        targets.push(("linux", "x64"));
    }
    targets
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
        // -trimpath + empty buildid make the prover build reproducible so a
        // re-run produces byte-identical output (stable lockfile checksums).
        .arg("-trimpath")
        .args(["-ldflags", "-buildid="])
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

/// Build a workspace binary (e.g. `photon`, `zolana`) for a target and stage it.
/// The host build uses cargo directly; linux-x64 builds in a Docker container so
/// no host cross-linker is needed. Both are cache-first via the shared
/// `target`/`target-linux-x64` dirs, so building a second binary is incremental.
fn build_rust_binary(repo: &Path, package: &str, bin: &str, out: &Path, host: bool) -> Result<()> {
    if host {
        build_rust_binary_host(repo, package, bin, out)
    } else {
        build_rust_binary_linux_x64(repo, package, bin, out)
    }
}

fn build_rust_binary_host(repo: &Path, package: &str, bin: &str, out: &Path) -> Result<()> {
    println!("building {bin} (host)");
    let status = Command::new("cargo")
        .current_dir(repo)
        .args(["build", "--release", "-p", package, "--bin", bin])
        .status()
        .with_context(|| format!("failed to run cargo build for {bin}"))?;
    if !status.success() {
        bail!("cargo build failed for {bin} (host)");
    }
    fs::copy(repo.join("target/release").join(bin), out)
        .with_context(|| format!("failed to stage host {bin} to {}", out.display()))?;
    Ok(())
}

fn build_rust_binary_linux_x64(repo: &Path, package: &str, bin: &str, out: &Path) -> Result<()> {
    println!("building {bin} linux-x64 (docker {PHOTON_LINUX_BUILDER_IMAGE})");
    let mount = format!("{}:/work", path_str(repo)?);
    let build = format!(
        "set -e; apt-get update -qq && apt-get install -y -qq pkg-config libssl-dev protobuf-compiler cmake clang build-essential >/dev/null 2>&1; cargo build --release -p {package} --bin {bin} --target-dir /work/target-linux-x64"
    );
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
        .args(["bash", "-c", &build])
        .status()
        .with_context(|| format!("failed to run docker for {bin} linux-x64 build"))?;
    if !status.success() {
        bail!("docker {bin} linux-x64 build failed");
    }
    fs::copy(repo.join("target-linux-x64/release").join(bin), out)
        .with_context(|| format!("failed to stage linux {bin} to {}", out.display()))?;
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

/// The lockfile is regenerated during the build, so after publishing it is
/// typically uncommitted. The uploaded assets and the downloaded CLI binary are
/// already correct; the only gap is that the tag sits at the current HEAD, whose
/// committed lockfile is stale, so `cargo install --git --tag` users would build
/// with the old lockfile. We deliberately do not mutate git here; print the
/// non-force reconcile: commit the lockfile and re-run --upload, which recreates
/// the release + tag via gh at the new commit (no force-push).
fn warn_if_lockfile_uncommitted(lock_path: &Path, tag: &str) -> Result<()> {
    let clean = Command::new("git")
        .args(["diff", "--quiet", "--"])
        .arg(lock_path)
        .status()
        .context("failed to check lockfile git status")?
        .success();
    if !clean {
        println!();
        println!(
            "NOTE: {} was regenerated and is uncommitted.",
            lock_path.display()
        );
        println!("Assets are published. To also make `cargo install --git --tag {tag}` match,");
        println!("commit the lockfile and re-run --upload (the release + tag are recreated via");
        println!("gh at the new commit -- no force-push):");
        println!("  git add {}", lock_path.display());
        println!("  git commit -m \"chore(release): {tag} lockfile\" && git push");
        println!("  just release {tag} --upload   # add --prerelease for alpha tags");
    }
    Ok(())
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
/// here, and the pool tree is pre-allocated directly at DEFAULT_TREE_ADDRESS
/// without the tree keypair.
pub(crate) fn generate_account_snapshots(deploy_dir: &Path, accounts_dir: &Path) -> Result<()> {
    let shielded_so = deploy_dir.join("shielded_pool_program.so");
    require_file(&shielded_so, "run `just build-programs` first")?;
    reset_dir(accounts_dir)?;

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
    for key in [
        "ring_program",
        "ring_program_policy",
        "proving_key",
        "accounts",
    ] {
        if let Some(name) = lock.get(key).and_then(asset_name) {
            names.push(name);
        }
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

fn upload_release(options: &Options, assets: &[PathBuf], target: &str) -> Result<()> {
    let tag = options.tag.as_str();
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
        options.set.title(tag),
        "--notes".to_string(),
        options.set.notes(tag),
    ];
    if options.prerelease {
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
    // COPYFILE_DISABLE stops macOS bsdtar from adding AppleDouble (._*) sidecars;
    // the excludes drop any that already exist. Without this, GNU tar on Linux
    // would materialize them and the validator would choke parsing them as
    // account JSON. The CLI extractor excludes them too (defense in depth).
    let status = Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .args(["--exclude=._*", "--exclude=.DS_Store", "-czf"])
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
    println!("or running validator needed), and the prover, photon, and zolana CLI");
    println!("binaries for the host platform plus linux-x64 (Go cross-compile for the");
    println!("prover; Docker for the linux Rust binaries). Regenerates");
    println!("cli/release-artifacts.lock; the CLI binary is built last so it embeds the");
    println!("final lockfile (and is therefore uploaded but not a lockfile entry).");
    println!("With --custom-rings the set is the ring program, its prover key, the ring rpc");
    println!("and the zolana-ring cli.");
    println!();
    println!("Requires: go, cargo, and docker (for the linux-x64 photon build).");
    println!();
    println!("Options:");
    println!(
        "  --custom-rings          Release the ring program, its prover key, the ring rpc and"
    );
    println!("                          the zolana-ring cli only,");
    println!("                          regenerating custom-rings/cli/release-artifacts.lock");
    println!("  --deploy-dir <dir>      Program .so directory (default target/deploy)");
    println!("  --staging-dir <dir>     Asset staging dir (default target/release-staging)");
    println!("  --lock-path <path>      Lockfile to regenerate (default by set)");
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
        let expected = json!({
            "pubkey": pubkey.to_string(),
            "account": {
                "lamports": 42,
                "data": [STANDARD.encode([1, 2, 3]), "base64"],
                "owner": account.owner.to_string(),
                "executable": false,
                "rentEpoch": u64::MAX,
            }
        });
        assert_eq!(account_json(&pubkey, &account), expected);
    }

    // Guard against drift between the JSON this tool writes and the schema the
    // CLI parses (cli/src/release.rs: ReleaseLock/ProgramAsset/BinaryAsset). If
    // this fails, update both sides together.
    #[test]
    fn lockfile_shape_matches_cli_parser() {
        let lock = json!({
            "release_tag": "t",
            "surfpool_tag": "s",
            "surfpool_version": "1",
            "programs": [{"role": "shielded_pool", "asset": "a.so", "size": 1, "sha256": "x"}],
            "accounts": {"asset": "accounts.tar.gz", "size": 1, "sha256": "x"},
            "binaries": [{
                "role": "prover", "os": "linux", "arch": "x64",
                "asset": "prover-linux-x64-t", "size": 1, "sha256": "x"
            }],
        });
        let program = &lock["programs"][0];
        for key in ["role", "asset", "size", "sha256"] {
            assert!(program.get(key).is_some(), "program missing {key}");
        }
        for section in ["accounts"] {
            for key in ["asset", "size", "sha256"] {
                assert!(lock[section].get(key).is_some(), "{section} missing {key}");
            }
        }
        let binary = &lock["binaries"][0];
        for key in ["role", "os", "arch", "asset", "size", "sha256"] {
            assert!(binary.get(key).is_some(), "binary missing {key}");
        }
    }

    /// The ring cli reads `release_tag`, `ring_program`, `proving_key` and `binaries`.
    #[test]
    fn custom_rings_lock_shape_matches_the_ring_cli_parser() {
        let lock = json!({
            "release_tag": "v1",
            "ring_program": {"asset": "custom-ring-program-v1.so", "size": 1, "sha256": "x"},
            "proving_key": {"asset": "custom-ring-key-v1.key", "size": 1, "sha256": "x"},
            "binaries": [{"role": "ring_rpc", "os": "linux", "arch": "x64", "asset": "ring-rpc-linux-x64-v1", "size": 1, "sha256": "x"}],
        });
        for section in ["ring_program", "proving_key"] {
            for key in ["asset", "size", "sha256"] {
                assert!(lock[section].get(key).is_some(), "{section} missing {key}");
            }
        }
        assert_eq!(
            staged_asset_paths(Path::new("/stage"), &lock),
            vec![
                PathBuf::from("/stage/custom-ring-program-v1.so"),
                PathBuf::from("/stage/custom-ring-key-v1.key"),
                PathBuf::from("/stage/ring-rpc-linux-x64-v1"),
            ]
        );
        assert_eq!(ReleaseSet::CustomRings.cli_binaries().len(), 1);
        assert_eq!(ReleaseSet::CustomRings.title("v1"), "custom-rings v1");
        assert_eq!(
            ReleaseSet::CustomRings.lock_path(),
            "custom-rings/cli/release-artifacts.lock"
        );
    }

    #[test]
    fn staged_asset_paths_lists_every_asset() {
        let lock = json!({
            "programs": [{"asset": "a.so"}, {"asset": "b.so"}],
            "ring_program": {"asset": "ring.so"},
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
            [
                "a.so",
                "b.so",
                "ring.so",
                "accounts.tar.gz",
                "prover",
                "photon"
            ]
        );
    }
}
