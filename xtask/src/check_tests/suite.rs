//! Structural rules over the test suites.
//!
//! Deliberately small: only rules that catch something the compiler cannot, and
//! that a diff would not make obvious on its own. `shielded-pool-proofs`
//! auto-discovers its targets, so nothing there can be orphaned;
//! `shielded-pool-tests` keeps `autotests = false` to name its tiers, so it
//! still needs the reachability rule below.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;
use walkdir::WalkDir;

use super::{Findings, Repo};

/// Packages whose `tests/` trees must not contain unreachable files.
const TEST_PACKAGES: &[&str] = &[
    "program-tests/shielded-pool",
    "program-tests/shielded-pool-proofs",
];

/// Paths the searches below depend on. A renamed directory would otherwise
/// shrink the search surface to nothing and report success.
const REQUIRED_PATHS: &[&str] = &[
    "program-tests/shielded-pool",
    "program-tests/shielded-pool-proofs",
    "program-tests/spp-test-validator/tests",
    "program-tests/ring-test-program/tests",
    "program-tests/shielded-pool/invariants/README.md",
];

/// A banned source pattern, its explanation, and where it applies.
///
/// Only rules that still bite. The scenario-framework bans (`cucumber`,
/// `gherkin`, `World` fixtures, `.feature` files) retired with #165: those are
/// dependency and file additions that a diff makes obvious, unlike the two
/// below, which look like ordinary test code.
struct BannedPattern {
    message: &'static str,
    pattern: &'static str,
    roots: &'static [&'static str],
}

const BANNED: &[BannedPattern] = &[
    BannedPattern {
        // A harness override silently changes what `cargo test` runs and how
        // failures are reported, and reads as an ordinary manifest key.
        message: "program tests must use the standard Rust test harness",
        pattern: r"harness\s*=\s*false",
        roots: &[
            "program-tests",
            "sdk-libs/client",
            "sdk-tests/zk-program-swap/test",
        ],
    },
    BannedPattern {
        // Matching an error by its formatted string passes for the wrong
        // reason as soon as the message changes; `Rejection` compares the
        // typed error.
        message: "validator failures must inspect typed errors, not formatted strings",
        pattern: r"(?i)(assert_rpc_custom_error|expected custom program error.*got:|contains\(&code\.to_string\(\)\))",
        roots: &[
            "program-tests/spp-test-validator/tests",
            "program-tests/ring-test-program/tests",
        ],
    },
];

pub fn check(repo: &Repo, findings: &mut Findings) -> Result<()> {
    check_required_paths(repo, findings);
    check_banned_patterns(repo, findings)?;
    for package in TEST_PACKAGES {
        check_unreachable_leaves(repo, package, findings)?;
    }
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

/// Every `.rs` file under a package's `tests/` tree must be reachable: a target
/// cargo knows about, or a module some target includes.
///
/// An unreachable file is never compiled, linted, or run: cargo and clippy both
/// ignore it, so a suite that never executes looks exactly like one that passes.
/// That is how a four-case F-07 security suite sat dormant in #175.
///
/// In `shielded-pool-proofs` this is vacuous by construction — auto-discovery
/// reaches every `tests/*.rs`. It earns its keep in `shielded-pool-tests`, which
/// declares targets explicitly so CI can select tiers by name.
///
/// Targets come from `cargo_metadata`, so auto-discovered and declared ones are
/// treated alike without parsing the manifest.
fn check_unreachable_leaves(repo: &Repo, package_dir: &str, findings: &mut Findings) -> Result<()> {
    let declared = test_target_paths(repo, package_dir)?;
    let tests_dir = repo.path(package_dir).join("tests");

    let mut unreachable = Vec::new();
    for entry in WalkDir::new(&tests_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        if declared.iter().any(|target| target == path) || is_included_as_module(path) {
            continue;
        }
        unreachable.push(repo.display(path));
    }

    if !unreachable.is_empty() {
        unreachable.sort();
        findings.push_with_details(
            "unreachable test file (no cargo target builds it, and no target includes it)",
            unreachable,
        );
    }
    Ok(())
}

/// Absolute paths of a package's integration-test targets, auto-discovered or declared.
fn test_target_paths(repo: &Repo, package_dir: &str) -> Result<Vec<PathBuf>> {
    let package = repo
        .metadata
        .workspace_packages()
        .into_iter()
        .find(|p| {
            p.manifest_path
                .parent()
                .is_some_and(|dir| dir.ends_with(package_dir))
        })
        .with_context(|| format!("no workspace package rooted at {package_dir}"))?;

    Ok(package
        .targets
        .iter()
        .filter(|target| target.is_test())
        .map(|target| target.src_path.clone().into_std_path_buf())
        .collect())
}

/// Whether some sibling declares this file as a module. The reference must live
/// in the leaf's own directory or its parent (the file that declares the
/// module); a same-stem module elsewhere does not include this leaf.
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
/// that can reintroduce a harness override.
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
            path.extension().is_some_and(|ext| ext == "rs")
                || path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| name == "Cargo.toml")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banned_patterns_compile_and_match_what_they_describe() {
        let harness = Regex::new(BANNED[0].pattern).unwrap();
        assert!(harness.is_match("harness = false"));
        assert!(harness.is_match("harness=false"));
        assert!(!harness.is_match("harness = true"));

        let typed_errors = Regex::new(BANNED[1].pattern).unwrap();
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
