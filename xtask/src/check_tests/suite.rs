//! Structural rules over the test suites themselves.
//!
//! Two groups: bans on terminology and harness shapes retired by earlier
//! refactors, and layout rules keeping the shielded-pool suite's
//! one-`[[test]]`-per-leaf mapping honest.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;
use walkdir::WalkDir;

use super::{Findings, Repo};

/// The shielded-pool suite: one `[[test]]` binary per leaf under
/// `tests/<domain>/<intent>.rs`, shared setup in the `src/support` library.
const SHIELDED_POOL_TESTS: &str = "program-tests/shielded-pool";

/// Paths every search below depends on. A renamed or deleted directory would
/// otherwise shrink the search surface to nothing and report success — the
/// failure mode that let a stale `--exclude` silently stop matching.
const REQUIRED_PATHS: &[&str] = &[
    "Cargo.toml",
    "justfile",
    "program-tests",
    "sdk-libs/client",
    "sdk-libs/client/tests",
    "sdk-libs/keypair/tests",
    "sdk-libs/transaction/tests",
    "sdk-tests/zk-program-swap/test",
    "program-tests/spp-test-validator",
    "program-tests/spp-test-validator/tests",
    "program-tests/ring-test-program",
    "program-tests/ring-test-program/tests",
    "program-tests/shielded-pool/invariants",
    "program-tests/shielded-pool/invariants/README.md",
];

/// A banned source pattern, its explanation, and where it applies.
struct BannedPattern {
    message: &'static str,
    pattern: &'static str,
    roots: &'static [&'static str],
}

const BANNED: &[BannedPattern] = &[
    BannedPattern {
        message: "legacy scenario-test terminology or dependencies are not allowed",
        pattern: r"(?i)(cucumber|gherkin|\bbdd\b)",
        roots: &[
            "Cargo.toml",
            "justfile",
            "program-tests",
            "sdk-libs/client/tests",
            "sdk-libs/keypair/tests",
            "sdk-libs/transaction/tests",
            "sdk-tests/zk-program-swap/test",
        ],
    },
    BannedPattern {
        message: "program tests must use the standard Rust test harness",
        pattern: r"harness\s*=\s*false",
        roots: &[
            "program-tests",
            "sdk-libs/client",
            "sdk-tests/zk-program-swap/test",
        ],
    },
    BannedPattern {
        message: "validator failures must inspect typed errors, not formatted strings",
        pattern: r"(?i)(assert_rpc_custom_error|expected custom program error.*got:|contains\(&code\.to_string\(\)\))",
        roots: &[
            "program-tests/spp-test-validator/tests",
            "program-tests/ring-test-program/tests",
        ],
    },
    BannedPattern {
        message: "test fixtures use Harness naming; World is a removed scenario-framework remnant",
        pattern: r"(?i)(LifecycleWorld|TransferWorld|MergeWorld|RingTransferWorld|RingAuthorityWorld|mod\s+world|_world\s*:)",
        roots: &[
            "program-tests/spp-test-validator",
            "program-tests/ring-test-program",
            "sdk-libs",
        ],
    },
];

pub fn check(repo: &Repo, findings: &mut Findings) -> Result<()> {
    check_required_paths(repo, findings);
    check_banned_patterns(repo, findings)?;
    check_scenario_files(repo, findings)?;
    check_orphan_leaves(repo, findings)?;
    check_obsolete_wrapper_tree(repo, findings);
    check_tracked_artifacts(repo, findings)?;
    Ok(())
}

fn check_required_paths(repo: &Repo, findings: &mut Findings) {
    for relative in REQUIRED_PATHS {
        if !repo.path(relative).exists() {
            findings.push(format!(
                "searched path is missing (renamed or deleted?): {relative}"
            ));
        }
    }
}

fn check_banned_patterns(repo: &Repo, findings: &mut Findings) -> Result<()> {
    for banned in BANNED {
        let regex = Regex::new(banned.pattern)
            .with_context(|| format!("invalid banned pattern: {}", banned.pattern))?;
        let mut hits = Vec::new();
        for root in banned.roots {
            for file in rust_and_config_files(&repo.path(root)) {
                let Ok(source) = std::fs::read_to_string(&file) else {
                    continue;
                };
                for (number, line) in source.lines().enumerate() {
                    if regex.is_match(line) {
                        hits.push(format!(
                            "{}:{}: {}",
                            repo.display(&file),
                            number + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
        if !hits.is_empty() {
            findings.push_with_details(banned.message, hits);
        }
    }
    Ok(())
}

/// Scenario-framework leftovers: `features/` and `steps/` trees and `.feature`
/// files, which the explicit-suite refactor removed.
fn check_scenario_files(repo: &Repo, findings: &mut Findings) -> Result<()> {
    const ROOTS: &[&str] = &[
        "program-tests",
        "sdk-libs/client/tests",
        "sdk-libs/keypair/tests",
        "sdk-libs/transaction/tests",
        "sdk-tests/zk-program-swap/test",
    ];
    let mut hits = Vec::new();
    for root in ROOTS {
        for entry in WalkDir::new(repo.path(root))
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let is_scenario = path.extension().is_some_and(|ext| ext == "feature")
                || path
                    .components()
                    .any(|c| matches!(c.as_os_str().to_str(), Some("features") | Some("steps")));
            if is_scenario {
                hits.push(repo.display(path));
            }
        }
    }
    if !hits.is_empty() {
        findings.push_with_details("legacy scenario-test files are not allowed", hits);
    }
    Ok(())
}

/// Every `.rs` leaf under the shielded-pool `tests/` tree must be a declared
/// `[[test]]` target or a module some target includes. An undeclared leaf is
/// never compiled: cargo and clippy ignore it silently, so a suite that never
/// runs is indistinguishable from one that passes.
///
/// Declared paths come from `cargo_metadata`, not from grepping the manifest —
/// the shell version matched every `path = "tests/…"` line in the file with no
/// idea which `[[test]]`, `[[bench]]`, or `[[bin]]` block it belonged to.
fn check_orphan_leaves(repo: &Repo, findings: &mut Findings) -> Result<()> {
    let package_dir = repo.path(SHIELDED_POOL_TESTS);
    let declared = declared_test_paths(repo, SHIELDED_POOL_TESTS)?;

    let mut orphans = Vec::new();
    for entry in WalkDir::new(package_dir.join("tests"))
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        if declared.iter().any(|declared| declared == path) {
            continue;
        }
        if is_included_as_module(path) {
            continue;
        }
        orphans.push(repo.display(path));
    }

    if !orphans.is_empty() {
        orphans.sort();
        findings.push_with_details(
            "orphan test leaf (neither a [[test]] target nor included by one)",
            orphans,
        );
    }
    Ok(())
}

/// Absolute paths of a package's integration-test targets.
fn declared_test_paths(repo: &Repo, package_name_suffix: &str) -> Result<Vec<PathBuf>> {
    let package = repo
        .metadata
        .workspace_packages()
        .into_iter()
        .find(|p| {
            p.manifest_path
                .parent()
                .is_some_and(|dir| dir.ends_with(package_name_suffix))
        })
        .with_context(|| format!("no workspace package rooted at {package_name_suffix}"))?;

    Ok(package
        .targets
        .iter()
        .filter(|target| target.is_test())
        .map(|target| target.src_path.clone().into_std_path_buf())
        .collect())
}

/// Whether some sibling declares this file as a module. The reference must live
/// in the leaf's own directory or its parent (the `<domain>.rs` that declares
/// the module); a same-stem module elsewhere does not include this leaf.
fn is_included_as_module(leaf: &Path) -> bool {
    let Some(file_name) = leaf.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(stem) = leaf.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let mod_decl = format!("mod {stem};");
    let path_attr = format!("{file_name}\"");

    let mut search_dirs = Vec::new();
    if let Some(dir) = leaf.parent() {
        search_dirs.push(dir.to_path_buf());
        if let Some(parent) = dir.parent() {
            search_dirs.push(parent.to_path_buf());
        }
    }

    for dir in search_dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path == leaf || path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in source.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with(&mod_decl)
                    || trimmed.starts_with(&format!("pub {mod_decl}"))
                    || (trimmed.contains("#[path") && trimmed.contains(&path_attr))
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Shared setup lives in the `src/support` library; the old `tests/common`
/// `#[path]`-wrapper tree must not come back.
fn check_obsolete_wrapper_tree(repo: &Repo, findings: &mut Findings) {
    let wrapper = repo.path(SHIELDED_POOL_TESTS).join("tests/common");
    if wrapper.exists() {
        findings.push(format!(
            "obsolete tests/common wrapper module tree is present: {}",
            repo.display(&wrapper)
        ));
    }
}

/// Ledger and log artifacts are gitignored; this catches an accidental
/// `git add -f`. `*.proptest-regressions` corpora are deliberately committed
/// regression guards, not artifacts.
fn check_tracked_artifacts(repo: &Repo, findings: &mut Findings) -> Result<()> {
    let output = std::process::Command::new("git")
        .current_dir(&repo.root)
        .args([
            "ls-files",
            "--",
            "program-tests/**/test-ledger/**",
            "program-tests/**/*.log",
        ])
        .output()
        .context("git ls-files failed")?;
    anyhow::ensure!(
        output.status.success(),
        "git ls-files exited with {}",
        output.status
    );

    let tracked: Vec<&str> = std::str::from_utf8(&output.stdout)
        .context("git ls-files emitted invalid UTF-8")?
        .lines()
        .filter(|line| !line.is_empty())
        .collect();
    if !tracked.is_empty() {
        findings.push_with_details(
            "generated runtime artifacts must not be committed under source test packages",
            tracked,
        );
    }
    Ok(())
}

/// Files worth scanning for banned patterns: Rust sources plus the manifests
/// and recipes that can reintroduce a retired dependency.
fn rust_and_config_files(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .filter(|path| {
            let is_rust = path.extension().is_some_and(|ext| ext == "rs");
            let is_config = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| name == "Cargo.toml" || name == "justfile");
            is_rust || is_config
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_banned_pattern_compiles() {
        for banned in BANNED {
            Regex::new(banned.pattern).unwrap_or_else(|e| panic!("{}: {e}", banned.pattern));
        }
    }

    #[test]
    fn banned_patterns_match_what_they_describe() {
        let scenario = Regex::new(BANNED[0].pattern).unwrap();
        assert!(scenario.is_match("cucumber = { workspace = true }"));
        assert!(scenario.is_match("// a BDD scenario"));
        // `bdd` is word-bounded: a longer identifier containing it is fine.
        assert!(!scenario.is_match("let embedded = 1;"));

        let harness = Regex::new(BANNED[1].pattern).unwrap();
        assert!(harness.is_match("harness = false"));
        assert!(harness.is_match("harness=false"));

        let typed_errors = Regex::new(BANNED[2].pattern).unwrap();
        assert!(typed_errors.is_match("assert_rpc_custom_error(&err, 7009);"));
        assert!(!typed_errors.is_match("Rejection::pool(err).assert_litesvm(e);"));
    }

    #[test]
    fn module_inclusion_ignores_commented_out_declarations() {
        let dir = std::env::temp_dir().join(format!("xtask-check-tests-{}", std::process::id()));
        let nested = dir.join("domain");
        std::fs::create_dir_all(&nested).unwrap();
        let leaf = nested.join("intent.rs");
        std::fs::write(&leaf, "// leaf\n").unwrap();

        let sibling = nested.join("other.rs");
        std::fs::write(&sibling, "// mod intent;\n").unwrap();
        assert!(
            !is_included_as_module(&leaf),
            "a commented-out `mod` must not count as inclusion"
        );

        std::fs::write(&sibling, "mod intent;\n").unwrap();
        assert!(is_included_as_module(&leaf));

        std::fs::remove_dir_all(&dir).ok();
    }
}
