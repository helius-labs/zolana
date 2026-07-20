//! Deterministic lint for `docs/spec.md`.
//!
//! Catches the mechanical spec defects an LLM pass should never spend judgment
//! on: dead intra-document anchors, relative links that do not resolve, and
//! vocabulary banned by `docs/CLAUDE.md`. `TODO`/`TBD` markers are reported as
//! warnings (SPEC_GUIDE forbids them in normative sections, but converting one
//! is a review judgment, not a lint fix).
//!
//! Exit codes: 0 = clean (warnings allowed), 1 = violations, 2 = cannot read.

use std::{collections::BTreeSet, fs, path::PathBuf};

const DEFAULT_SPEC: &str = "docs/spec.md";

/// Banned by docs/CLAUDE.md ("Language"). Case-insensitive substring match.
const BANNED_PHRASES: [&str; 3] = ["the wire", "wall time", "folded into"];

#[derive(Debug)]
pub struct Options {
    spec: PathBuf,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut spec = PathBuf::from(DEFAULT_SPEC);
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--spec" => {
                    spec = args.next().map(PathBuf::from).unwrap_or_else(|| {
                        eprintln!("spec-lint: --spec requires a path");
                        std::process::exit(2);
                    });
                }
                "--help" | "-h" => {
                    println!("xtask spec-lint [--spec <path>]");
                    println!();
                    println!("Checks {DEFAULT_SPEC} for dead intra-doc anchors, unresolvable");
                    println!("relative links, and banned vocabulary. TODO/TBD are warnings.");
                    println!();
                    println!("Exit codes: 0 clean, 1 violations, 2 cannot read");
                    std::process::exit(0);
                }
                other => {
                    eprintln!("spec-lint: unknown argument {other:?}");
                    std::process::exit(2);
                }
            }
        }
        Self { spec }
    }
}

pub fn run(options: Options) -> i32 {
    let path = &options.spec;
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("spec-lint: cannot read {}: {error}", path.display());
            return 2;
        }
    };
    let base_dir = path.parent().map(PathBuf::from).unwrap_or_default();

    let report = lint(&text, &base_dir);

    let out = crate::term::Style::stdout();
    let err = crate::term::Style::stderr();
    for warning in &report.warnings {
        println!("spec-lint: {}: {warning}", out.yellow("warning"));
    }
    if report.violations.is_empty() {
        println!(
            "spec-lint: {}: {} anchors, {} intra-doc links, {} warnings ({})",
            out.green("pass"),
            report.anchor_count,
            report.link_count,
            report.warnings.len(),
            path.display()
        );
        0
    } else {
        eprintln!(
            "spec-lint: {}: {} violations in {}:",
            err.red("fail"),
            report.violations.len(),
            path.display()
        );
        for violation in &report.violations {
            eprintln!("  {violation}");
        }
        1
    }
}

struct Report {
    violations: Vec<String>,
    warnings: Vec<String>,
    anchor_count: usize,
    link_count: usize,
}

/// GitHub heading slug: lowercase; keep alphanumerics, `-`, `_`, spaces; drop
/// the rest; spaces become `-`. Repeated slugs get `-1`, `-2`, ... suffixes in
/// document order.
fn github_slug(heading: &str) -> String {
    let mut out = String::new();
    let mut text = String::new();
    // Strip HTML tags from the heading text before slugging.
    let mut in_tag = false;
    for ch in heading.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => text.push(c),
            _ => {}
        }
    }
    for ch in text.trim().chars() {
        match ch {
            c if c.is_alphanumeric() => out.extend(c.to_lowercase()),
            ' ' | '-' => out.push('-'),
            '_' => out.push('_'),
            _ => {}
        }
    }
    out
}

fn lint(text: &str, base_dir: &std::path::Path) -> Report {
    let mut violations = Vec::new();
    let mut warnings = Vec::new();

    // Pass 1: collect anchors (headings outside code fences, plus <a id="...">).
    let mut anchors: BTreeSet<String> = BTreeSet::new();
    let mut slug_counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut in_fence = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if let Some(heading) = line.strip_prefix('#') {
            let heading = heading.trim_start_matches('#');
            if let Some(title) = heading.strip_prefix(' ') {
                let slug = github_slug(title);
                let n = *slug_counts
                    .entry(slug.clone())
                    .and_modify(|n| *n += 1)
                    .or_insert(0);
                anchors.insert(if n == 0 { slug } else { format!("{slug}-{n}") });
            }
        }
        let mut rest = line;
        while let Some(idx) = rest.find("<a id=\"") {
            let tail = &rest[idx + 7..];
            if let Some(end) = tail.find('"') {
                anchors.insert(tail[..end].to_string());
                rest = &tail[end..];
            } else {
                break;
            }
        }
    }

    // Pass 2: check links and vocabulary, skipping code fences.
    let mut link_count = 0usize;
    let mut in_fence = false;
    for (index, line) in text.lines().enumerate() {
        let lineno = index + 1;
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }

        let mut rest = line;
        while let Some(idx) = rest.find("](") {
            let tail = &rest[idx + 2..];
            let Some(end) = tail.find(')') else { break };
            let target = &tail[..end];
            if let Some(anchor) = target.strip_prefix('#') {
                link_count += 1;
                if !anchors.contains(anchor) {
                    violations.push(format!("line {lineno}: dead anchor #{anchor}"));
                }
            } else if target.starts_with("http://") || target.starts_with("https://") {
                warnings.push(format!(
                    "line {lineno}: external link {target} (spec should reference docs/ only)"
                ));
            } else {
                // Relative link; must resolve from the spec's directory.
                let path_part = target.split('#').next().unwrap_or("");
                if !path_part.is_empty() && !base_dir.join(path_part).exists() {
                    violations.push(format!(
                        "line {lineno}: relative link {path_part} does not resolve"
                    ));
                }
            }
            rest = &tail[end..];
        }

        let lower = line.to_lowercase();
        for phrase in BANNED_PHRASES {
            if lower.contains(phrase) {
                violations.push(format!(
                    "line {lineno}: banned phrase {phrase:?} (docs/CLAUDE.md Language rules)"
                ));
            }
        }
        if lower.contains("todo") || lower.contains("tbd") {
            warnings.push(format!("line {lineno}: TODO/TBD marker"));
        }
    }

    Report {
        violations,
        warnings,
        anchor_count: anchors.len(),
        link_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn slugs_match_github_rules() {
        assert_eq!(
            github_slug("SPP Proof - Solana Privacy ZK Proof"),
            "spp-proof---solana-privacy-zk-proof"
        );
        assert_eq!(github_slug("Versioning & Upgrades"), "versioning--upgrades");
        assert_eq!(github_slug("`zone_transact`"), "zone_transact");
        assert_eq!(
            github_slug("Concurrency & Balance Fragmentation"),
            "concurrency--balance-fragmentation"
        );
    }

    #[test]
    fn duplicate_headings_dedup_in_order() {
        let text = "# Transfer\n\n## Transfer\n\n### Transfer\n\n[a](#transfer)[b](#transfer-1)[c](#transfer-2)\n";
        let report = lint(text, Path::new("."));
        assert!(report.violations.is_empty(), "{:?}", report.violations);
    }

    #[test]
    fn dead_anchor_and_html_id_anchor() {
        let text = "# Title\n\n<a id=\"custom\"></a>\n\n[ok](#custom) [bad](#missing)\n";
        let report = lint(text, Path::new("."));
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].contains("#missing"));
    }

    #[test]
    fn links_inside_code_fences_ignored() {
        let text = "# T\n\n```rust\n// [not a link](#nope)\n```\n";
        let report = lint(text, Path::new("."));
        assert!(report.violations.is_empty());
    }

    #[test]
    fn banned_phrase_fails_todo_warns() {
        let text = "# T\n\nSent over the wire.\n\nTODO: later.\n";
        let report = lint(text, Path::new("."));
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].contains("the wire"));
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn unresolvable_relative_link_fails() {
        let text = "# T\n\n[x](no-such-dir/missing.md)\n";
        let report = lint(text, Path::new("/nonexistent-base"));
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].contains("does not resolve"));
    }
}
