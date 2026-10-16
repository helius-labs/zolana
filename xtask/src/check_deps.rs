//! Enforces the dependency rules of the zk crates (see the `zk/` section of the
//! root CLAUDE.md):
//!
//! - a crate under `zk/` depends on no zolana crate other than another
//!   `zolana-zk-*` crate and `zolana-hasher`;
//! - `zolana-keypair` and `zolana-transaction` reach the zk crates only through
//!   optional dependencies (their `circuit` feature);
//! - outside the zk crates and the crates that build zolana-program, no crate
//!   depends on both `zolana-program` and a `zolana-zk-*` crate: ZK programs go
//!   through `zolana-program`, standalone circuits use the zk crates directly.
//!
//! The first rule covers every dependency kind; the other two cover the normal
//! and build graph, so tests may pull in what they need.

use std::{path::Path, process::Command};

use anyhow::{bail, Context, Result};
use serde_json::Value;

const ZK_PREFIX: &str = "zolana-zk-";
const ZK_ALLOWED: &[&str] = &["zolana-hasher"];
const OPTIONAL_ZK: &[&str] = &["zolana-keypair", "zolana-transaction"];
const PROGRAM_LAYER: &[&str] = &[
    "zolana-program",
    "zolana-macros",
    "zolana-keypair",
    "zolana-transaction",
];

struct Dependency {
    name: String,
    optional: bool,
    dev: bool,
}

struct Package {
    name: String,
    in_zk: bool,
    dependencies: Vec<Dependency>,
}

pub fn run(root: &Path) -> Result<()> {
    let violations = violations(&packages(root)?);
    if violations.is_empty() {
        println!("check-deps: ok");
        return Ok(());
    }
    for violation in &violations {
        eprintln!("check-deps: {violation}");
    }
    bail!("{} dependency rule violation(s)", violations.len())
}

fn packages(root: &Path) -> Result<Vec<Package>> {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .context("running cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let metadata: Value = serde_json::from_slice(&output.stdout).context("cargo metadata json")?;
    // Compare against cargo's own canonical root: the caller's path may go
    // through a symlink, and then no manifest path would start with it.
    let zk_dir = Path::new(
        metadata
            .get("workspace_root")
            .and_then(Value::as_str)
            .context("cargo metadata has no workspace_root")?,
    )
    .join("zk");
    metadata
        .get("packages")
        .and_then(Value::as_array)
        .context("cargo metadata has no packages")?
        .iter()
        .map(|package| {
            let field = |key: &str| {
                package
                    .get(key)
                    .and_then(Value::as_str)
                    .with_context(|| format!("a package without {key}"))
            };
            let dependencies = package
                .get("dependencies")
                .and_then(Value::as_array)
                .context("a package without dependencies")?
                .iter()
                .map(|dependency| {
                    Ok(Dependency {
                        name: dependency
                            .get("name")
                            .and_then(Value::as_str)
                            .context("a dependency without a name")?
                            .to_string(),
                        optional: dependency
                            .get("optional")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        dev: dependency.get("kind").and_then(Value::as_str) == Some("dev"),
                    })
                })
                .collect::<Result<_>>()?;
            Ok(Package {
                name: field("name")?.to_string(),
                in_zk: Path::new(field("manifest_path")?).starts_with(&zk_dir),
                dependencies,
            })
        })
        .collect()
}

fn violations(packages: &[Package]) -> Vec<String> {
    let mut violations = Vec::new();
    for package in packages {
        let zk_dependencies: Vec<&Dependency> = package
            .dependencies
            .iter()
            .filter(|dependency| !dependency.dev && dependency.name.starts_with(ZK_PREFIX))
            .collect();
        if package.in_zk {
            violations.extend(
                package
                    .dependencies
                    .iter()
                    .filter(|dependency| {
                        dependency.name.starts_with("zolana-")
                            && !dependency.name.starts_with(ZK_PREFIX)
                            && !ZK_ALLOWED.contains(&dependency.name.as_str())
                    })
                    .map(|dependency| {
                        format!(
                            "{} is a zk crate and depends on {}",
                            package.name, dependency.name
                        )
                    }),
            );
        }
        if OPTIONAL_ZK.contains(&package.name.as_str()) {
            violations.extend(
                zk_dependencies
                    .iter()
                    .filter(|dependency| !dependency.optional)
                    .map(|dependency| {
                        format!(
                            "{} depends on {} without its circuit feature",
                            package.name, dependency.name
                        )
                    }),
            );
        }
        let program = package
            .dependencies
            .iter()
            .any(|dependency| !dependency.dev && dependency.name == "zolana-program");
        if !package.in_zk
            && !PROGRAM_LAYER.contains(&package.name.as_str())
            && program
            && !zk_dependencies.is_empty()
        {
            violations.push(format!(
                "{} depends on zolana-program and on {}: a ZK program uses the zolana-program re-exports",
                package.name,
                zk_dependencies
                    .iter()
                    .map(|dependency| dependency.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    violations
}
