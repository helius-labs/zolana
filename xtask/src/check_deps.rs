//! Enforces the dependency rules on the Xark circuit framework (see the root
//! CLAUDE.md):
//!
//! - on-chain crates (`programs/`, `program-libs/`) never link Xark or
//!   `spr-circuit`;
//! - the wallet SDK crates (`spr-keypair`, `spr-transaction`, `spr-instruction`)
//!   stay free of them: circuit types live in `spr-circuit`;
//! - `spr-program` reaches them only through optional dependencies, so its
//!   on-chain features (`cpi`, `compression`, `verifier`) do not pull them in.
//!
//! These rules cover the normal and build graph, so tests may pull in what they
//! need. Crates under `protocol-ops/` must also keep those graphs free of `sdk-libs`.

use std::{path::Path, process::Command};

use anyhow::{bail, Context, Result};
use serde_json::Value;

const CIRCUIT_CRATES: &[&str] = &[
    "spr-circuit",
    "xark",
    "xark-cli",
    "xark-groth16",
    "xark-wasm",
];
const CIRCUIT_FREE_SDK: &[&str] = &["spr-keypair", "spr-transaction", "spr-instruction"];
const OPTIONAL_CIRCUIT: &[&str] = &["spr-program"];

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
    onchain: bool,
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
            let manifest = field("manifest_path")?;
            Ok(Package {
                name: field("name")?.to_string(),
                protocol: manifest.contains("/protocol-ops/"),
                onchain: manifest.contains("/programs/") || manifest.contains("/program-libs/"),
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
        for dependency in package.dependencies.iter().filter(|dependency| {
            !dependency.dev && CIRCUIT_CRATES.contains(&dependency.name.as_str())
        }) {
            let name = package.name.as_str();
            if package.onchain {
                violations.push(format!(
                    "{name} depends on {}: on-chain crates do not link the circuit framework",
                    dependency.name
                ));
            } else if CIRCUIT_FREE_SDK.contains(&name) {
                violations.push(format!(
                    "{name} depends on {}: circuit types live in spr-circuit",
                    dependency.name
                ));
            } else if OPTIONAL_CIRCUIT.contains(&name) && !dependency.optional {
                violations.push(format!(
                    "{name} depends on {} unconditionally: keep it behind a client feature",
                    dependency.name
                ));
            }
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
            onchain: false,
            dependencies: vec![Dependency {
                name: "spr-client".into(),
                optional: true,
                dev: false,
                sdk: true,
            }],
        }];
        assert_eq!(violations(&packages), vec!["forester depends on SDK crate spr-client: protocol operations use program-libs and protocol crates"]);
    }

    fn package(name: &str, onchain: bool, dependency: &str, optional: bool) -> Package {
        Package {
            name: name.into(),
            protocol: false,
            onchain,
            dependencies: vec![Dependency {
                name: dependency.into(),
                optional,
                dev: false,
                sdk: false,
            }],
        }
    }

    #[test]
    fn onchain_crates_reject_the_circuit_framework() {
        let packages = [package("shielded-pool-program", true, "spr-circuit", true)];
        assert_eq!(violations(&packages), vec!["shielded-pool-program depends on spr-circuit: on-chain crates do not link the circuit framework"]);
    }

    #[test]
    fn wallet_sdk_crates_reject_the_circuit_framework() {
        let packages = [package("spr-transaction", false, "xark", true)];
        assert_eq!(
            violations(&packages),
            vec!["spr-transaction depends on xark: circuit types live in spr-circuit"]
        );
    }

    #[test]
    fn spr_program_reaches_the_circuit_framework_only_optionally() {
        let required = [package("spr-program", false, "xark-groth16", false)];
        assert_eq!(violations(&required), vec!["spr-program depends on xark-groth16 unconditionally: keep it behind a client feature"]);
        let optional = [package("spr-program", false, "xark-groth16", true)];
        assert!(violations(&optional).is_empty());
    }

    #[test]
    fn circuit_crates_and_dev_dependencies_are_allowed() {
        let mut packages = [package("timelock-escrow-program", false, "xark", false)];
        assert!(violations(&packages).is_empty());
        packages[0].onchain = true;
        packages[0].dependencies[0].dev = true;
        assert!(violations(&packages).is_empty());
    }
}
