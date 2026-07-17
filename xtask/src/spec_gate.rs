//! Deterministic gate over the spec-review findings ledger.
//!
//! Parses `docs/spec-review/findings.md` and fails while any finding is
//! `status: open`. The ledger grammar is specified in
//! `.claude/skills/spec-review/references/findings-format.md`; this parser is
//! the enforcement of that grammar. The ledger is gitignored local review
//! state, so a missing file is clean: the gate binds wherever a ledger exists.
//!
//! Exit codes: 0 = clean (or no ledger), 1 = open findings, 2 = grammar violation.

use std::{fs, path::PathBuf};

const DEFAULT_LEDGER: &str = "docs/spec-review/findings.md";

// Only `open` trips the gate. `auto-resolved` is set by `yolo-fix-spec` when it
// closes a finding in the spec: it passes CI (the fix landed) but stays distinct
// from operator-verified `resolved`.
const STATUS_VALUES: [&str; 4] = ["open", "acknowledged", "resolved", "auto-resolved"];
const SEVERITY_VALUES: [&str; 5] = ["critical", "high", "medium", "low", "info"];
const TYPE_VALUES: [&str; 4] = ["design-weakness", "spec-gap", "code-bug", "spec-quality"];
const REQUIRED_FIELDS: [&str; 6] = ["status", "severity", "type", "code", "spec", "opened"];
const OPTIONAL_FIELDS: [&str; 2] = ["resolved", "fix"];

#[derive(Debug)]
pub struct Options {
    ledger: PathBuf,
    syntax_only: bool,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut ledger = PathBuf::from(DEFAULT_LEDGER);
        let mut syntax_only = false;

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--ledger" => {
                    ledger = args.next().map(PathBuf::from).unwrap_or_else(|| {
                        eprintln!("spec-gate: --ledger requires a path");
                        std::process::exit(2);
                    });
                }
                "--syntax-only" => syntax_only = true,
                "--help" | "-h" => {
                    print_spec_gate_help();
                    std::process::exit(0);
                }
                other => {
                    eprintln!("spec-gate: unknown argument {other:?}");
                    print_spec_gate_help();
                    std::process::exit(2);
                }
            }
        }

        Self {
            ledger,
            syntax_only,
        }
    }
}

fn print_spec_gate_help() {
    println!("xtask spec-gate [--ledger <path>] [--syntax-only]");
    println!();
    println!("Parses the spec-review findings ledger and exits non-zero while any");
    println!("finding is `status: open`.");
    println!();
    println!("Defaults:");
    println!("  --ledger {DEFAULT_LEDGER}");
    println!();
    println!("Flags:");
    println!("  --syntax-only   Validate the ledger grammar only; open findings do not fail");
    println!();
    println!("Exit codes: 0 clean, 1 open findings, 2 grammar violation");
}

pub fn run(options: Options) -> i32 {
    let out = crate::term::Style::stdout();
    let err = crate::term::Style::stderr();
    let path = &options.ledger;
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "spec-gate: {}: no ledger at {}, nothing to gate",
                out.green("pass"),
                path.display()
            );
            return 0;
        }
        Err(error) => {
            eprintln!("spec-gate: cannot read {}: {error}", path.display());
            return 2;
        }
    };

    let findings = match parse_ledger(&text) {
        Ok(findings) => findings,
        Err(errors) => {
            eprintln!(
                "spec-gate: {}: ledger grammar violations in {}:",
                err.red("fail"),
                path.display()
            );
            for error in errors {
                eprintln!("  {error}");
            }
            return 2;
        }
    };

    let open: Vec<&Finding> = findings.iter().filter(|f| f.status == "open").collect();
    let count = |status: &str| findings.iter().filter(|f| f.status == status).count();
    let acknowledged = count("acknowledged");
    let resolved = count("resolved");
    let auto_resolved = count("auto-resolved");

    let passing = options.syntax_only || open.is_empty();
    let verdict = if passing {
        out.green("pass")
    } else {
        out.red("fail")
    };
    let mode = if options.syntax_only {
        " (syntax only)"
    } else {
        ""
    };
    println!(
        "spec-gate: {verdict}{mode}: {} open, {acknowledged} acknowledged, {resolved} resolved, \
         {auto_resolved} auto-resolved ({})",
        open.len(),
        path.display()
    );

    if options.syntax_only {
        return 0;
    }

    if !open.is_empty() {
        eprintln!("spec-gate: open findings require operator review:");
        for finding in &open {
            let severity = match finding.severity.as_str() {
                "critical" | "high" => err.red(&finding.severity),
                "medium" => err.yellow(&finding.severity),
                other => other.to_string(),
            };
            eprintln!("  ZSR-{:04} [{severity}] {}", finding.id, finding.title);
        }
        return 1;
    }

    0
}

#[derive(Debug)]
struct Finding {
    id: u32,
    title: String,
    status: String,
    severity: String,
}

struct PartialFinding {
    id: u32,
    title: String,
    header_line: usize,
    fields: Vec<(String, String, usize)>,
}

fn parse_ledger(text: &str) -> Result<Vec<Finding>, Vec<String>> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut current: Option<PartialFinding> = None;

    for (index, line) in text.lines().enumerate() {
        let lineno = index + 1;
        if let Some(header) = line.strip_prefix("## ") {
            if let Some(finding) = current.take() {
                finalize_entry(finding, &mut findings, &mut errors);
            }
            match parse_header(header) {
                Ok((id, title)) => {
                    current = Some(PartialFinding {
                        id,
                        title,
                        header_line: lineno,
                        fields: Vec::new(),
                    });
                }
                Err(reason) => {
                    errors.push(format!("line {lineno}: {reason}"));
                    current = None;
                }
            }
        } else if let Some(finding) = current.as_mut() {
            if let Some((key, value)) = parse_field_line(line) {
                finding.fields.push((key, value, lineno));
            }
        }
    }
    if let Some(finding) = current.take() {
        finalize_entry(finding, &mut findings, &mut errors);
    }

    let mut seen = std::collections::BTreeSet::new();
    for finding in &findings {
        if !seen.insert(finding.id) {
            errors.push(format!("duplicate finding id ZSR-{:04}", finding.id));
        }
    }

    if errors.is_empty() {
        Ok(findings)
    } else {
        Err(errors)
    }
}

fn parse_header(header: &str) -> Result<(u32, String), String> {
    let rest = header.strip_prefix("ZSR-").ok_or_else(|| {
        format!("entry heading must match `## ZSR-NNNN: <title>`, got {header:?}")
    })?;
    let (digits, title) = rest
        .split_once(": ")
        .ok_or_else(|| format!("entry heading missing `: <title>` separator: {header:?}"))?;
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("finding id must be four digits, got ZSR-{digits}"));
    }
    let title = title.trim();
    if title.is_empty() {
        return Err(format!("entry ZSR-{digits} has an empty title"));
    }
    Ok((digits.parse().expect("checked digits"), title.to_string()))
}

/// Field lines are `- key: value`; bullet lines whose key is not a known field
/// name are treated as prose and ignored. A trailing ` # ...` comment on the
/// value is stripped (so `spec: docs/spec.md#anchor` keeps its anchor).
fn parse_field_line(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("- ")?;
    let (key, value) = rest.split_once(':')?;
    let key = key.trim();
    if !REQUIRED_FIELDS.contains(&key) && !OPTIONAL_FIELDS.contains(&key) {
        return None;
    }
    let value = value.split(" #").next().unwrap_or("").trim();
    Some((key.to_string(), value.to_string()))
}

fn finalize_entry(entry: PartialFinding, findings: &mut Vec<Finding>, errors: &mut Vec<String>) {
    let status = required_field(&entry, "status", errors);
    let severity = required_field(&entry, "severity", errors);
    let kind = required_field(&entry, "type", errors);
    required_field(&entry, "code", errors);
    required_field(&entry, "spec", errors);
    let opened = required_field(&entry, "opened", errors);
    lookup_field(&entry, "resolved", errors);

    let id = entry.id;
    check_enum(id, "status", &status, &STATUS_VALUES, errors);
    check_enum(id, "severity", &severity, &SEVERITY_VALUES, errors);
    check_enum(id, "type", &kind, &TYPE_VALUES, errors);

    if !opened.is_empty() && !is_iso_date(&opened) {
        errors.push(format!(
            "ZSR-{id:04}: `opened: {opened}` must be a YYYY-MM-DD date"
        ));
    }

    findings.push(Finding {
        id,
        title: entry.title,
        status,
        severity,
    });
}

/// Returns the single value for `name`, recording a grammar error when the
/// field is repeated within one entry.
fn lookup_field(entry: &PartialFinding, name: &str, errors: &mut Vec<String>) -> Option<String> {
    let matches: Vec<&(String, String, usize)> = entry
        .fields
        .iter()
        .filter(|(key, _, _)| key == name)
        .collect();
    match matches.as_slice() {
        [] => None,
        [(_, value, _)] => Some(value.clone()),
        [_, (_, _, lineno), ..] => {
            errors.push(format!(
                "line {lineno}: ZSR-{:04} repeats field `{name}`",
                entry.id
            ));
            None
        }
    }
}

fn required_field(entry: &PartialFinding, name: &str, errors: &mut Vec<String>) -> String {
    match lookup_field(entry, name, errors) {
        Some(value) if !value.is_empty() => value,
        Some(_) => {
            errors.push(format!(
                "ZSR-{:04} (line {}): field `{name}` is empty",
                entry.id, entry.header_line
            ));
            String::new()
        }
        None => {
            errors.push(format!(
                "ZSR-{:04} (line {}): missing required field `{name}`",
                entry.id, entry.header_line
            ));
            String::new()
        }
    }
}

fn check_enum(id: u32, name: &str, value: &str, allowed: &[&str], errors: &mut Vec<String>) {
    if !value.is_empty() && !allowed.contains(&value) {
        errors.push(format!(
            "ZSR-{id:04}: `{name}: {value}` is not one of {allowed:?}"
        ));
    }
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7) || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "# Spec Review Findings Ledger\n\nProse preamble.\n\n";

    fn entry(id: &str, status: &str) -> String {
        format!(
            "## ZSR-{id}: Example finding title\n\
             - status: {status}\n\
             - severity: high\n\
             - type: design-weakness\n\
             - code: programs/shielded-pool/src/lib.rs:1\n\
             - spec: docs/spec.md#example\n\
             - opened: 2026-07-17\n\n\
             Prose description with a bullet:\n\
             - not a field, just prose\n\n"
        )
    }

    #[test]
    fn empty_ledger_is_clean() {
        let findings = parse_ledger(HEADER).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn spec_quality_type_and_fix_field_accepted() {
        let text = format!(
            "{HEADER}## ZSR-0001: Missing constants table\n\
             - status: open\n\
             - severity: low\n\
             - type: spec-quality\n\
             - code: program-libs/interface/src/constants.rs:1\n\
             - spec: docs/spec.md#constants\n\
             - opened: 2026-07-17\n\
             - fix: add a Constants section per SPEC_GUIDE item 25\n\n\
             Prose.\n"
        );
        let findings = parse_ledger(&text).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, "open");
    }

    #[test]
    fn valid_ledger_parses_statuses() {
        let text = format!(
            "{HEADER}{}{}{}",
            entry("0001", "resolved"),
            entry("0002", "acknowledged"),
            entry("0003", "open")
        );
        let findings = parse_ledger(&text).unwrap();
        assert_eq!(findings.len(), 3);
        assert_eq!(findings.iter().filter(|f| f.status == "open").count(), 1);
        assert_eq!(findings[2].id, 3);
        assert_eq!(findings[2].title, "Example finding title");
        assert_eq!(findings[2].severity, "high");
    }

    #[test]
    fn missing_field_is_grammar_error() {
        let text = format!("{HEADER}## ZSR-0001: Broken entry\n- status: open\n- severity: high\n");
        let errors = parse_ledger(&text).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("missing required field `type`")));
        assert!(errors
            .iter()
            .any(|e| e.contains("missing required field `code`")));
    }

    #[test]
    fn invalid_enum_is_grammar_error() {
        let text = format!("{HEADER}{}", entry("0001", "pending"));
        let errors = parse_ledger(&text).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("`status: pending`")));
    }

    #[test]
    fn auto_resolved_is_valid_and_not_open() {
        let text = format!("{HEADER}{}", entry("0001", "auto-resolved"));
        let findings = parse_ledger(&text).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, "auto-resolved");
        // A gate run over only auto-resolved findings has zero open, so it passes.
        assert_eq!(findings.iter().filter(|f| f.status == "open").count(), 0);
    }

    #[test]
    fn duplicate_id_is_grammar_error() {
        let text = format!(
            "{HEADER}{}{}",
            entry("0001", "resolved"),
            entry("0001", "open")
        );
        let errors = parse_ledger(&text).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("duplicate finding id ZSR-0001")));
    }

    #[test]
    fn malformed_header_is_grammar_error() {
        let text = format!("{HEADER}## Finding without id\n- status: open\n");
        let errors = parse_ledger(&text).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("must match `## ZSR-NNNN")));
    }

    #[test]
    fn spec_anchor_survives_comment_stripping() {
        let (key, value) = parse_field_line("- spec: docs/spec.md#merge # trailing note").unwrap();
        assert_eq!(key, "spec");
        assert_eq!(value, "docs/spec.md#merge");
    }
}
