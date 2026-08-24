//! `new` against a template checkout named by ZOLANA_RING_TEMPLATE_DIR, the
//! source stage clones the enclosing zolana checkout at HEAD and sees only
//! committed changes, needs cargo-generate and git on PATH.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

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
    let head = Command::new("git")
        .arg("-C")
        .arg(&zolana_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse");
    assert!(head.status.success());
    let head = String::from_utf8_lossy(&head.stdout).trim().to_owned();

    let status = Command::new(env!("CARGO_BIN_EXE_zolana-ring"))
        .args(["new", "smoke-ring", "--silent", "--template-path"])
        .arg(&template)
        .arg("--zolana-git")
        .arg(format!(
            "file://{}",
            zolana_root.canonicalize().expect("root").display()
        ))
        .args(["--zolana-rev", &head])
        .arg("--dest")
        .arg(&dest)
        .status()
        .expect("run zolana-ring new");
    assert!(status.success());

    let ring = dest.join("smoke-ring");
    assert!(ring.join("ring.toml").is_file());
    assert!(ring.join("keys/program-keypair.json").is_file());
    assert!(ring.join("program/src/instructions/transact.rs").is_file());
    assert!(ring.join("Cargo.lock").is_file());
    assert!(ring.join("sdk/src/transfer.rs").is_file());
    assert!(!ring.join("cli").exists());
    assert!(!ring.join("interface").exists());
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
