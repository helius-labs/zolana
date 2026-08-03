//! Consistency of the invariants ledger.
//!
//! `program-tests/shielded-pool/invariants/` maps each program invariant to the
//! test that proves it. It is the substitute for coverage on the surface
//! llvm-cov cannot see: the on-chain program executes inside the SVM, so these
//! citations are what connect a Critical invariant to its proof.
//!
//! That makes rot actively misleading rather than merely absent. Rename the
//! test behind INV-DEPOSIT-03 and the entry still reads `- [x]` against an
//! invariant whose statement is "theft of third-party lamports". Three checks
//! keep the matrix honest: the README's tallies must match the files, every
//! citation must resolve, and an entry retired as "removed" must describe
//! something actually gone from the program.

use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result};
use regex::Regex;

use super::{symbols::SymbolIndex, Findings, Repo};

const LEDGER_DIR: &str = "program-tests/shielded-pool/invariants";

/// Ledger files, in README order. Named explicitly so a new file that nobody
/// tallies cannot slip in unnoticed.
const LEDGER_FILES: &[&str] = &[
    "transact",
    "deposit",
    "merge",
    "tree",
    "protocol-config",
    "ring-config",
    "spl",
    "event",
    "cross-cutting",
];

const NA_MARKER: &str = "Not applicable post-PR164";

/// Counts for one ledger file.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub total: usize,
    pub covered: usize,
    pub companion: usize,
    pub not_applicable: usize,
    pub pointer: usize,
}

impl Tally {
    /// Entries neither covered, companion-covered, nor retired.
    pub fn partial(&self) -> usize {
        self.total
            .saturating_sub(self.covered + self.companion + self.not_applicable)
    }
}

pub fn check(repo: &Repo, findings: &mut Findings) -> Result<()> {
    let dir = repo.path(LEDGER_DIR);
    if !dir.is_dir() {
        findings.push(format!(
            "invariants ledger directory is missing: {LEDGER_DIR}"
        ));
        return Ok(());
    }

    let mut tallies = BTreeMap::new();
    let mut sources = Vec::new();
    for name in LEDGER_FILES {
        let path = dir.join(format!("{name}.md"));
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading ledger file {}", repo.display(&path)))?;
        tallies.insert(*name, tally(&source));
        sources.push((*name, source));
    }

    let readme = std::fs::read_to_string(dir.join("README.md")).context("reading ledger README")?;
    check_tallies(&readme, &tallies, &sources, findings)?;
    check_citations(repo, &sources, findings)?;
    check_removal_claims(repo, &sources, findings)?;
    Ok(())
}

/// Count entries in one ledger file. An entry runs from its `- [x] **INV-…`
/// header to the next header; it counts as retired when the `Not applicable`
/// marker appears anywhere in that block.
pub fn tally(source: &str) -> Tally {
    let mut tally = Tally::default();
    let mut in_entry = false;
    let mut block = String::new();

    let flush = |block: &str, tally: &mut Tally, in_entry: bool| {
        if in_entry && block.contains(NA_MARKER) {
            tally.not_applicable += 1;
        }
    };

    for line in source.lines() {
        let marker = entry_marker(line);
        if let Some(marker) = marker {
            flush(&block, &mut tally, in_entry);
            block.clear();
            in_entry = true;
            tally.total += 1;
            match marker {
                'x' => tally.covered += 1,
                '~' => tally.companion += 1,
                _ => {}
            }
        } else {
            block.push_str(line);
            block.push('\n');
        }
    }
    flush(&block, &mut tally, in_entry);

    tally.pointer = source.matches("pointer entry").count();
    tally
}

/// The marker character of an invariant header line, if this is one.
fn entry_marker(line: &str) -> Option<char> {
    let rest = line.strip_prefix("- [")?;
    let mut chars = rest.chars();
    let marker = chars.next()?;
    if !matches!(marker, 'x' | ' ' | '~') {
        return None;
    }
    chars.as_str().strip_prefix("] **INV-").map(|_| marker)
}

fn check_tallies(
    readme: &str,
    tallies: &BTreeMap<&str, Tally>,
    sources: &[(&str, String)],
    findings: &mut Findings,
) -> Result<()> {
    let mut mismatch = |label: &str, claimed: String, computed: String| {
        if claimed != computed {
            findings.push(format!(
                "invariants tally mismatch ({label}): README claims {claimed}, ledger computes {computed}"
            ));
        }
    };

    // Per-file cells, e.g. `transact 55/3/0/1` = covered/partial/companion/N-A.
    let cell = Regex::new(r"(?m)\b([a-z-]+) (\d+)/(\d+)/(\d+)/(\d+)")?;
    let claimed_cells: BTreeMap<&str, [usize; 4]> = cell
        .captures_iter(readme)
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str();
            let nums = [2usize, 3, 4, 5].map(|i| {
                caps.get(i)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0)
            });
            Some((name, nums))
        })
        .collect();

    for (name, tally) in tallies {
        let computed = [
            tally.covered,
            tally.partial(),
            tally.companion,
            tally.not_applicable,
        ];
        match claimed_cells.get(name) {
            None => mismatch(name, "no per-file cell".into(), join(&computed)),
            Some(claimed) => mismatch(name, join(claimed), join(&computed)),
        }
    }

    let sum = |f: fn(&Tally) -> usize| tallies.values().map(f).sum::<usize>();
    let total = sum(|t| t.total);
    let covered = sum(|t| t.covered);
    let companion = sum(|t| t.companion);
    let not_applicable = sum(|t| t.not_applicable);
    let pointer: usize = sources
        .iter()
        .map(|(_, s)| s.matches("pointer entry").count())
        .sum();

    for (label, pattern, computed) in [
        ("Total invariants", r"(?m)^- Total invariants: (\d+)", total),
        ("Covered", r"(?m)^- Covered: (\d+)", covered),
        (
            "Companion",
            r"(?m)^- Covered on companion security branches[^:]*: (\d+)",
            companion,
        ),
        (
            "Not applicable",
            r"(?m)^- Not applicable post-PR164: (\d+)",
            not_applicable,
        ),
        ("Pointer", r"(?m)^- Pointer: (\d+)", pointer),
        (
            "Partial",
            r"(?m)^- Partial: (\d+)",
            total.saturating_sub(covered + companion + not_applicable + pointer),
        ),
    ] {
        let claimed = capture_number(readme, pattern)?;
        mismatch(
            label,
            claimed.map_or_else(|| "absent".to_string(), |n| n.to_string()),
            computed.to_string(),
        );
    }

    for severity in ["Critical", "High", "Medium"] {
        let computed: usize = sources
            .iter()
            .map(|(_, s)| {
                s.lines()
                    .filter(|l| {
                        l.trim_start()
                            .starts_with(&format!("- Severity: {severity}"))
                    })
                    .count()
            })
            .sum();
        let claimed = capture_number(readme, &format!(r"(?m)^- {severity}[^0-9]*: (\d+)"))?;
        mismatch(
            &format!("Severity {severity}"),
            claimed.map_or_else(|| "absent".to_string(), |n| n.to_string()),
            computed.to_string(),
        );
    }
    Ok(())
}

fn join(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join("/")
}

fn capture_number(haystack: &str, pattern: &str) -> Result<Option<usize>> {
    let regex = Regex::new(pattern).with_context(|| format!("invalid pattern {pattern}"))?;
    Ok(regex
        .captures(haystack)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse().ok()))
}

/// Every `Covered by:` citation must name something real. A cited file must
/// exist; a cited identifier must be a function defined somewhere in the tree.
/// `Cross-branch coverage:` lines are the explicit companion-branch label and
/// carry no resolvable citation.
fn check_citations(repo: &Repo, sources: &[(&str, String)], findings: &mut Findings) -> Result<()> {
    let index = SymbolIndex::build(&[
        &repo.path("program-tests"),
        &repo.path("programs"),
        &repo.path("program-libs"),
        &repo.path("sdk-libs"),
        &repo.path("sdk-tests"),
    ])?;
    anyhow::ensure!(
        index.len() > 100,
        "symbol index looks empty ({} functions); the source tree may have moved",
        index.len()
    );

    let backticked = Regex::new(r"`([^`]+)`")?;
    let identifier = Regex::new(r"^[a-z_][a-z0-9_]*$")?;
    let go_identifier = Regex::new(r"^Test[A-Za-z0-9]+$")?;

    let mut unresolved = Vec::new();
    let mut uncited = Vec::new();
    let mut stale_paths = Vec::new();

    for (name, source) in sources {
        for (number, line) in source.lines().enumerate() {
            if !line.contains("Covered by:") {
                continue;
            }
            let location = format!("{name}.md:{}", number + 1);
            let tokens: Vec<&str> = backticked
                .captures_iter(line)
                .filter_map(|c| c.get(1).map(|m| m.as_str()))
                .collect();
            if tokens.is_empty() {
                uncited.push(format!("{location}: {}", line.trim()));
                continue;
            }

            let mut current_file: Option<String> = None;
            for token in tokens {
                // Type paths, prose fragments, and call expressions are not citations.
                if token.contains("::") || token.contains(' ') || token.contains('(') {
                    continue;
                }
                if token.ends_with(".rs") || token.ends_with(".go") {
                    current_file = resolve_cited_file(repo, token);
                    // A cited path that resolves to nothing is a finding in its
                    // own right. Checking only the accompanying symbol lets a
                    // stale path survive a file move, because the function it
                    // names still exists somewhere else -- so the ledger points
                    // at a file that is not there while still reading `- [x]`.
                    if current_file.is_none() {
                        stale_paths.push(format!("{location}: `{token}`"));
                    }
                    continue;
                }
                if !identifier.is_match(token) && !go_identifier.is_match(token) {
                    continue;
                }
                // A token present in the cited file is satisfied there; this
                // keeps free-form citations of constants and fields honest
                // without demanding a test-function shape.
                if let Some(file) = &current_file {
                    if std::fs::read_to_string(file).is_ok_and(|s| s.contains(token)) {
                        continue;
                    }
                }
                if index.contains(token) || go_function_exists(repo, token) {
                    continue;
                }
                unresolved.push(format!("{location}: `{token}`"));
            }
        }
    }

    if !uncited.is_empty() {
        findings.push_with_details(
            "invariants Covered-by line has no backticked citation",
            uncited,
        );
    }
    if !stale_paths.is_empty() {
        findings.push_with_details(
            "invariants Covered-by cites a file that does not exist",
            stale_paths,
        );
    }
    if !unresolved.is_empty() {
        findings.push_with_details("invariants Covered-by references not found", unresolved);
    }
    Ok(())
}

/// Source trees a citation can name. Deliberately not the repo root: walking
/// that descends into `target/`, which dwarfs the source tree and turns each
/// unresolved citation into a multi-minute scan.
const SOURCE_ROOTS: &[&str] = &[
    "program-tests",
    "programs",
    "program-libs",
    "sdk-libs",
    "sdk-tests",
    "prover",
    "services",
    "cli",
    "forester",
];

/// Resolve a cited path, which may be repo-relative or a bare suffix.
fn resolve_cited_file(repo: &Repo, token: &str) -> Option<String> {
    let direct = repo.path(token);
    if direct.is_file() {
        return Some(direct.to_string_lossy().into_owned());
    }
    let suffix = format!("/{token}");
    SOURCE_ROOTS.iter().find_map(|root| {
        walkdir::WalkDir::new(repo.path(root))
            .into_iter()
            .filter_map(Result::ok)
            .find(|e| e.file_type().is_file() && e.path().to_string_lossy().ends_with(&suffix))
            .map(|e| e.path().to_string_lossy().into_owned())
    })
}

/// Go functions are matched textually: the ledger cites a handful of prover
/// symbols and a Go parser is not worth the dependency.
fn go_function_exists(repo: &Repo, name: &str) -> bool {
    let needle = format!("func {name}(");
    walkdir::WalkDir::new(repo.path("prover"))
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "go"))
        .any(|e| std::fs::read_to_string(e.path()).is_ok_and(|s| s.contains(&needle)))
}

/// An entry retired as removed must describe something actually gone from the
/// program. Only snake_case and `::`-path tokens are checked: bare CamelCase
/// names are types that legitimately still exist. Comment lines do not count as
/// a live reference. Catches a stale N/A that outlived the code it describes.
fn check_removal_claims(
    repo: &Repo,
    sources: &[(&str, String)],
    findings: &mut Findings,
) -> Result<()> {
    let backticked = Regex::new(r"`([^`]+)`")?;
    let removal = Regex::new(r"(?i)removed|deleted|retired|no longer|gone")?;
    let snake = Regex::new(r"^[a-z_][a-z0-9_]*$")?;

    let program_src = repo.path("programs/shielded-pool/src");
    let mut live = Vec::new();

    for (name, source) in sources {
        for (number, line) in source.lines().enumerate() {
            if !line.contains(NA_MARKER) {
                continue;
            }
            for caps in backticked.captures_iter(line) {
                let token = caps.get(1).map_or("", |m| m.as_str());
                if token.contains('*') || (!snake.is_match(token) && !token.contains("::")) {
                    continue;
                }
                // The removal verb must appear close after the token, so an
                // unrelated later sentence does not turn every token into a claim.
                let Some(after) = line.split_once(&format!("`{token}`")).map(|(_, a)| a) else {
                    continue;
                };
                let window = &after[..after.len().min(70)];
                if !removal.is_match(window) {
                    continue;
                }
                let hits = live_references(&program_src, token);
                if !hits.is_empty() {
                    live.push(format!(
                        "{name}.md:{}: `{token}` claimed removed, still in programs/shielded-pool/src ({})",
                        number + 1,
                        hits.join(", ")
                    ));
                }
            }
        }
    }

    if !live.is_empty() {
        findings.push_with_details("invariants N/A note contradicts the program source", live);
    }
    Ok(())
}

/// Non-comment references to `token` under `dir`, as `file:line` strings.
fn live_references(dir: &Path, token: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
    {
        let Ok(source) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        for (number, line) in source.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if line.contains(token) {
                hits.push(format!(
                    "{}:{}",
                    entry
                        .path()
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy(),
                    number + 1
                ));
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Heading

- [x] **INV-A-01: covered**
  - Covered by: `tests/a.rs` `test_one`
  - Severity: Critical
- [ ] **INV-A-02: partial**
  - Severity: High
- [~] **INV-A-03: companion**
  - Cross-branch coverage: `#175`
- [x] **INV-A-04: retired**
  - Not applicable post-PR164: `old_field` was removed.
  - Severity: Medium
";

    #[test]
    fn tally_classifies_each_marker_and_the_retired_block() {
        let tally = tally(SAMPLE);
        assert_eq!(
            tally,
            Tally {
                total: 4,
                covered: 2,
                companion: 1,
                not_applicable: 1,
                pointer: 0,
            }
        );
        // INV-A-04 is both `[x]` and retired; partial is what is left over.
        assert_eq!(tally.partial(), 0);
    }

    #[test]
    fn entry_marker_only_matches_invariant_headers() {
        assert_eq!(entry_marker("- [x] **INV-A-01: x**"), Some('x'));
        assert_eq!(entry_marker("- [ ] **INV-A-02: x**"), Some(' '));
        assert_eq!(entry_marker("- [~] **INV-A-03: x**"), Some('~'));
        assert_eq!(entry_marker("- [x] **NOT-AN-INV**"), None);
        assert_eq!(entry_marker("  - Severity: Critical"), None);
        assert_eq!(entry_marker("- [z] **INV-A-04: x**"), None);
    }

    #[test]
    fn partial_never_underflows_when_markers_overlap() {
        let tally = Tally {
            total: 1,
            covered: 1,
            companion: 1,
            not_applicable: 1,
            pointer: 0,
        };
        assert_eq!(tally.partial(), 0);
    }

    #[test]
    fn pointer_entries_are_counted_from_the_ledger_text() {
        let tally = tally("- [ ] **INV-X-01: x**\n  - pointer entry: defers to INV-X-02\n");
        assert_eq!(tally.pointer, 1);
    }
}
