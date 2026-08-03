//! `cargo xtask check-tests` — structural invariants over the test suites.
//!
//! These checks answer questions the compiler cannot. A test file that no
//! `[[test]]` target declares is never compiled, linted, or run: `cargo check
//! --all-targets` and clippy both ignore it completely, so an orphaned suite
//! looks exactly like a passing one. The invariants ledger has the same
//! property in reverse — a `Covered by:` citation naming a test that was since
//! renamed still reads as a green checkmark against a Critical invariant.
//!
//! Replaces `tools/check-test-hygiene.sh`. The shell version derived its facts
//! by grepping `Cargo.toml` and the source tree, which drifts silently: a
//! pattern that stops matching reports success. Target data now comes from
//! `cargo_metadata` and cited symbols from a parsed syntax tree, so the
//! structural checks fail loudly instead of quietly passing.

mod ledger;
mod suite;
mod symbols;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Collected violations. Every check appends rather than short-circuiting, so
/// one run reports the whole picture instead of only the first problem.
#[derive(Default)]
pub struct Findings {
    items: Vec<String>,
}

impl Findings {
    pub fn push(&mut self, finding: impl Into<String>) {
        self.items.push(finding.into());
    }

    /// Append a finding with an indented list of offending items beneath it.
    pub fn push_with_details<I, S>(&mut self, headline: impl Into<String>, details: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut message = headline.into();
        for detail in details {
            message.push_str("\n    ");
            message.push_str(detail.as_ref());
        }
        self.items.push(message);
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
}

/// The workspace under inspection, resolved once so checks share it.
pub struct Repo {
    pub root: PathBuf,
    pub metadata: cargo_metadata::Metadata,
}

impl Repo {
    fn discover() -> Result<Self> {
        let metadata = cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .context("cargo metadata failed; run from inside the workspace")?;
        Ok(Self {
            root: metadata.workspace_root.clone().into_std_path_buf(),
            metadata,
        })
    }

    pub fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative)
    }

    /// Repo-relative display form, for findings that name a file.
    pub fn display(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .display()
            .to_string()
    }
}

pub fn run() -> Result<()> {
    let repo = Repo::discover()?;
    let mut findings = Findings::default();

    suite::check(&repo, &mut findings)?;
    ledger::check(&repo, &mut findings)?;

    if findings.is_empty() {
        println!("test hygiene checks passed");
        return Ok(());
    }

    for item in &findings.items {
        eprintln!("{item}");
    }
    anyhow::bail!("{} test hygiene check(s) failed", findings.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_render_details_indented_under_the_headline() {
        let mut findings = Findings::default();
        assert!(findings.is_empty());
        findings.push_with_details("headline", ["first", "second"]);
        assert_eq!(findings.items, vec!["headline\n    first\n    second"]);
        assert_eq!(findings.len(), 1);
    }
}
