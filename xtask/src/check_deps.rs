//! Enforces the dependency rules on the zk crates, which live in
//! helius-labs/zk-tools (see the root CLAUDE.md):
//!
//! - `spr-keypair` and `spr-transaction` reach the zk crates only through
//!   optional dependencies (their `circuit` feature);
//! - outside the crates that build spr-program, no crate
//!   depends on both `spr-program` and a `spr-zk-*` crate: ZK programs go
//!   through `spr-program`, standalone circuits use the zk crates directly.
//!
//! These rules cover the normal and build graph, so tests may pull in what they
//! need. Crates under `protocol-ops/` must also keep those graphs free of `sdk-libs`.

use std::{path::Path, process::Command};

use anyhow::{bail, Context, Result};
use serde_json::Value;

const ZK_PREFIX: &str = "spr-zk-";
const OPTIONAL_ZK: &[&str] = &["spr-keypair", "spr-transaction"];
const PROGRAM_LAYER: &[&str] = &[
    "spr-program",
    "spr-macros",
    "spr-keypair",
    "spr-transaction",
];

struct Dependency {
    name: String,
    optional: bool,
    dev: bool,
    sdk: bool,
}

struct Package {
    name: String,
    dependencies: Vec<Dependency>,
    protocol: bool,
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
                        sdk: dependency
                            .get("path")
                            .and_then(Value::as_str)
                            .is_some_and(|path| path.contains("/sdk-libs/")),
                    })
                })
                .collect::<Result<_>>()?;
            Ok(Package {
                name: field("name")?.to_string(),
                protocol: field("manifest_path")?.contains("/protocol-ops/"),
                dependencies,
            })
        })
        .collect()
}

fn violations(packages: &[Package]) -> Vec<String> {
    let mut violations = Vec::new();
    for package in packages {
        if package.protocol {
            for dependency in package
                .dependencies
                .iter()
                .filter(|dependency| !dependency.dev && dependency.sdk)
            {
                violations.push(format!("{} depends on SDK crate {}: protocol operations use program-libs and protocol crates", package.name, dependency.name));
            }
        }
        let zk_dependencies: Vec<&Dependency> = package
            .dependencies
            .iter()
            .filter(|dependency| !dependency.dev && dependency.name.starts_with(ZK_PREFIX))
            .collect();
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
            .any(|dependency| !dependency.dev && dependency.name == "spr-program");
        if !PROGRAM_LAYER.contains(&package.name.as_str()) && program && !zk_dependencies.is_empty()
        {
            violations.push(format!(
                "{} depends on spr-program and on {}: a ZK program uses the spr-program re-exports",
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_crates_reject_sdk_dependencies_including_optional_ones() {
        let packages = [Package {
            name: "forester".into(),
            protocol: true,
            dependencies: vec![Dependency {
                name: "spr-client".into(),
                optional: true,
                dev: false,
                sdk: true,
            }],
        }];
        assert_eq!(violations(&packages), vec!["forester depends on SDK crate spr-client: protocol operations use program-libs and protocol crates"]);
    }
}
