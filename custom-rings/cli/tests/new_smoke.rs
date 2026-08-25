//! `new` against a template checkout named by ZOLANA_RING_TEMPLATE_DIR, the
//! source stage clones the enclosing zolana checkout at HEAD and sees only
//! committed changes, needs cargo-generate and git on PATH.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct AdvertisedHead {
    repository: PathBuf,
    name: String,
    commit: String,
}

impl AdvertisedHead {
    fn create(repository: &Path) -> Self {
        let head = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("git rev-parse");
        assert!(head.status.success());
        let commit = String::from_utf8_lossy(&head.stdout).trim().to_owned();
        let name = format!("refs/heads/ring-new-smoke-source-{}", std::process::id());
        let zero = "0".repeat(commit.len());
        let status = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["update-ref", &name, &commit, &zero])
            .status()
            .expect("git update-ref");
        assert!(status.success());
        Self {
            repository: repository.to_path_buf(),
            name,
            commit,
        }
    }
}

impl Drop for AdvertisedHead {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repository)
            .args(["update-ref", "-d", &self.name, &self.commit])
            .status();
    }
}

/// The scratch copy provides the HEAD `--template-path` resolves.
fn stage_template(dest: &Path) -> PathBuf {
    let source = PathBuf::from(
        std::env::var("ZOLANA_RING_TEMPLATE_DIR")
            .expect("set ZOLANA_RING_TEMPLATE_DIR to a zolana-ring template checkout"),
    );
    let staged = dest.join("template");
    copy_tree(&source, &staged);
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["add", "-A"],
        vec![
            "-c",
            "user.name=smoke",
            "-c",
            "user.email=smoke@invalid",
            "commit",
            "-q",
            "-m",
            "template",
        ],
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(&staged)
            .args(args)
            .status()
            .expect("git");
        assert!(status.success());
    }
    staged
}

fn copy_tree(source: &Path, dest: &Path) {
    fs::create_dir_all(dest).expect("dest dir");
    for entry in fs::read_dir(source).expect("read template") {
        let entry = entry.expect("entry");
        if entry.file_name() == ".git" {
            continue;
        }
        let target = dest.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

#[test]
#[ignore = "drives cargo generate, run with --ignored"]
fn new_generates_a_committed_ring_from_the_local_template() {
    let dest = std::env::temp_dir().join(format!("ring-new-smoke-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dest);
    fs::create_dir_all(&dest).expect("dest");
    let template = stage_template(&dest);

    let zolana_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = AdvertisedHead::create(&zolana_root);

    let status = Command::new(env!("CARGO_BIN_EXE_zolana-ring"))
        .args(["new", "smoke-ring", "--silent", "--template-path"])
        .arg(&template)
        .arg("--zolana-git")
        .arg(format!(
            "file://{}",
            zolana_root.canonicalize().expect("root").display()
        ))
        .args(["--zolana-rev", &source.commit])
        .arg("--dest")
        .arg(&dest)
        .status()
        .expect("run zolana-ring new");
    assert!(status.success());

    let ring = dest.join("smoke-ring");
    let config: custom_ring_cli::RingConfig =
        toml::from_str(&fs::read_to_string(ring.join("ring.toml")).expect("read ring.toml"))
            .expect("ring.toml parses raw");
    let keypair = solana_keypair::read_keypair_file(ring.join("keys/program-keypair.json"))
        .expect("program keypair");
    assert_eq!(
        config.program_id,
        solana_signer::Signer::pubkey(&keypair),
        "recorded program id is the generated keypair"
    );
    assert!(ring.join("program/src/instructions/transact.rs").is_file());
    assert!(ring.join("Cargo.lock").is_file());
    assert!(ring.join("sdk/src/transfer.rs").is_file());
    assert!(!ring.join("cli").exists());
    assert!(!ring.join("interface").exists());
    for file in ["README.md", "ring.toml", "Cargo.toml"] {
        let text = fs::read_to_string(ring.join(file)).expect("read rendered file");
        assert!(!text.contains("{{"), "unrendered liquid in {file}");
    }
    let log = Command::new("git")
        .arg("-C")
        .arg(&ring)
        .args(["log", "--oneline", "main"])
        .output()
        .expect("git log");
    assert!(log.status.success());
    let lines: Vec<String> = String::from_utf8_lossy(&log.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("ring: generate smoke-ring for program"));
    fs::remove_dir_all(&dest).expect("cleanup");
}
