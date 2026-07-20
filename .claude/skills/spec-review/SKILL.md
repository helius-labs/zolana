---
name: spec-review
description: Audit docs/spec.md against the code (the code is the more recent truth) and against the SPEC_GUIDE production checklist, recording gaps as actionable findings; the fix mode rewrites the spec to production grade. Use for spec-vs-code drift, spec security audits, and bringing a spec to release quality. Runs interactively or headless (claude -p).
argument-hint: "[full | diff [base] | fix]"
---

# Spec Review

`docs/spec.md` is the protocol source of truth, but code moves faster and a spec
can also be structurally incomplete. This skill measures the spec on two axes and
records every gap in the operator-reviewed ledger `docs/spec-review/findings.md`:

1. **Correctness** — does every claim match the code? (`spec-gap`, `code-bug`)
2. **Completeness** — does the spec satisfy the `docs/SPEC_GUIDE.md` production
   checklist? (`spec-quality`)

`just spec-gate` fails CI while any finding is `status: open`.

The default modes (`full`, `diff`) AUDIT only: the sole file they change is the
ledger. The `fix` mode is a separate, operator-triggered pass that rewrites
`docs/spec.md` to close the findings and lift the spec to production grade — see
the `fix` section at the end. CI and the pre-commit hook never invoke `fix`.

## Operating rules

- **Code is newer than the spec.** A disagreement is presumed spec drift unless
  the code looks wrong. Audit modes never touch code or `docs/spec.md`.
- **Audit modes edit only** `docs/spec-review/findings.md` (append entries;
  grammar in `references/findings-format.md`, new IDs = max existing + 1).
- **Never change an existing ledger entry** in an audit mode. Only the operator,
  or `fix` mode for findings it resolves, flips status.
- **Write findings the way you would write the spec:** maximum information
  density, no filler, no hedging. `references/spec-style.md` governs every word
  you write, in findings and in the summary.
- **Every finding is actionable.** It names the spec claim, the code truth with
  a `file:line`, and the reader/implementer consequence. Every `spec-gap` and
  `spec-quality` finding carries a `fix:` line stating the concrete correction —
  that line is what `yolo-fix-spec` applies, so make it precise enough to act on
  without re-reading the code.

## What counts as a finding (relevance bar)

Record a gap only when it changes what a reader would believe or build, or when
it leaves the spec short of the production checklist. Rank by consequence
(severity definitions in `references/findings-format.md`).

Report:

- A spec claim the code contradicts (wrong size, field name, order, derivation,
  authority, tag, constant) → `spec-gap`.
- A specified interface/instruction/field with no implementation, or an
  implemented one the spec omits, when it affects how the protocol is used →
  `spec-gap`.
- A security-relevant divergence (`references/security-checklist.md`): missing
  check, unbound input, broken invariant, over-broad authority, overclaimed
  privacy → `spec-gap` (or `design-weakness` if the design itself is at fault).
- A `SPEC_GUIDE` structural element the spec lacks (Trust Assumptions, Constants
  table, Permission Matrix, a wire struct's visibility table, a named-error
  table, an upgrade/versioning story, a recovery path) → `spec-quality`.
- Code that contradicts the spec and looks wrong → `code-bug` (never patch the
  spec to a bug).
- Spec code-block comments that fail the justification test in
  `references/spec-style.md` — comments that narrate a field, restate an
  encoding/size/derivation already given by the type or a linked definition, or
  were copied verbatim from the implementation → `spec-quality`. Report these
  together as one finding per section, not one per comment.

Do NOT report, and do NOT let these inflate the output:

- Cosmetic prose wording or ordering that misleads no one.
- Struct-field representation differences that yield the same on-chain bytes and
  the same reader understanding (mention once, briefly, only if load-bearing).
- Anything already in the ledger, at any status.
- Implementation detail the spec deliberately abstracts (per `docs/CLAUDE.md`,
  the spec links derivations instead of restating them — absence is not a gap).
- Speculation. If you cannot cite the code, do not raise it.

Merge findings that share a root cause into one entry. Ten load-bearing findings
beat fifty that bury them — but never drop a real gap to hit a number.

## Procedure

### Phase 0 — Setup

Read `docs/SPEC_GUIDE.md` (the house production checklist),
`references/spec-best-practices.md` (RFC / standards conventions),
`docs/CLAUDE.md`, `references/spec-style.md`, `references/security-checklist.md`,
`references/section-map.md`, and the current ledger (existing IDs and claims —
never re-report). `diff` mode: `git diff <base>...HEAD --name-only` (base
defaults to `origin/main`), map changed files to section groups via the section
map, restrict the audit to those groups; if no mapped code changed, report "no
spec-relevant changes" and stop after the self-check.

### Phase 1 — Correctness fan-out

Launch one read-only subagent per in-scope section group (six in `full` mode;
groups in `references/section-map.md`). Each subagent's contract:

- Extract the section's verifiable claims (constants, layouts, derivations, hash
  domains, account lists, validation rules, error conditions, state transitions,
  privacy assertions).
- Verify each against its code directories and return a row `claim | code
  citation (file:line) | verdict | corrected wording`, verdict ∈ `match`,
  `spec-stale`, `code-suspect`, `unclear`. Every non-`match` carries a
  `file:line`; every `spec-stale` carries a one-sentence corrected wording (this
  becomes the finding's `fix:` line).
- Note any `SPEC_GUIDE` structural element the section should have but lacks.
- Report a `MATCH_COUNT` and the list of what it verified as matching, so
  coverage is attestable. Subagents report; they do not edit.

### Phase 2 — Completeness sweep (orchestrator)

Walk both checklists — `docs/SPEC_GUIDE.md` (house structure) and
`references/spec-best-practices.md` (RFC / standards conventions) — against the
whole spec and open a `spec-quality` finding for each production element absent
or partial:

- SPEC_GUIDE structure: Trust Assumptions, Constants table, Permission Matrix,
  per-struct visibility tables, a named-error table, entry-point
  validate-and-execute lists, the upgrade/versioning story, extended-downtime
  recovery, failure-path diagrams, default-deny allow-lists.
- Standards conventions: a Conventions section stating RFC 2119/8174 keyword use;
  a Security Considerations section (RFC 3552 — threat model, what each mechanism
  protects, residual risks, out-of-scope, documented open weaknesses); explicit
  cryptographic-construction identification (proving system, BN254 field modulus,
  per-circuit public-input vector, trusted-setup assumption, every KDF/hash named
  with its label); a labeled-derivation registry; a References list of the
  external standards used; test-vector coverage (or a link to where vectors live)
  for the core derivations.

Each finding's `fix:` names the section to add and the code (or standard) the
content comes from. A documented residual risk is not bulk: prefer folding an
open `design-weakness` into Security Considerations over a standalone caveat. Also check cross-cutting consistency and record
as findings:

- A constant/size/field stated inconsistently in two places in the spec.
- A glossary term the code removed or renamed.
- Mechanical link/vocabulary defects: run `just spec-lint`. It is deterministic
  and authoritative for dead anchors, unresolvable relative links, and banned
  vocabulary — never hand-derive slug rules or grep for links yourself.
  Consolidate its violations into one finding. Judge its warnings: a TODO/TBD in
  a normative section is a finding; an external link is a finding when it
  duplicates in-repo content or points outside `docs/` for a protocol fact.

### Phase 3 — Triage and ledger update

Apply the relevance bar. Drop cosmetic and representation-only items. Merge by
root cause. Run `references/security-checklist.md` against the confirmed claims
and citations; each real weakness is a finding. Append the survivors to the
ledger per the grammar, each with `type`, severity by consequence, and a `fix:`
line for every `spec-gap`/`spec-quality`. Do not soften a finding to keep the
gate green. Run `just spec-gate --syntax-only`; it must exit 0.

Final terminal output, and nothing more:

1. **Coverage** — per section group, the `MATCH_COUNT` and the `SPEC_GUIDE`
   items confirmed present, so the operator can trust what was checked.
2. **Findings opened** — ID, severity, type, one-line claim-vs-code.
3. **Dropped at triage** — one line, so coverage shows without noise.

In headless mode this summary is the entire visible result. Keep it dense.

## `fix` mode (operator-triggered spec autofix)

Invoked manually via `just yolo-fix-spec` (`claude -p "/spec-review fix"`), never
by CI or the hook. The only mode that edits `docs/spec.md`. It closes the ledger
findings the spec can settle and lifts the spec to production grade.

Scope:

- Edit `docs/spec.md` and `docs/spec-review/findings.md` only. Never touch code.
- **`spec-gap`** — rewrite the spec text to the code's actual behavior, applying
  the finding's `fix:` line. Minimal, local edits; restructure a section only
  when a claim is unfixable in place.
- **`spec-quality`** — add the missing element (Trust Assumptions, Constants,
  Permission Matrix, visibility/error tables, Conventions, Security
  Considerations, cryptographic-assumptions/labels, References, …) built from the
  cited code and `references/spec-best-practices.md`, following
  `docs/SPEC_GUIDE.md` layout and `references/spec-style.md`. Wire it into the
  table of contents. For test vectors, do NOT fabricate values — add the section
  with a pointer to where vectors are generated from code, or leave the finding
  open if none exist.
- **`design-weakness` / `code-bug`** — do NOT rewrite the spec to hide these;
  they need a code change or a human decision. Leave them `open`. You MAY add a
  neutral normative note where the spec would mislead (e.g. state the actual
  privacy boundary), but never invent a guarantee the code does not provide.
- Dead anchors / broken links — fix the link, or add the missing section/anchor
  when the target content genuinely belongs.
- The spec references only files under `./docs/`. If a fix would link elsewhere,
  inline the fact instead.
- Unimplemented-but-specified interfaces get a one-line **Status:** marker
  (`interface specification; not implemented in this repository`), not deletion,
  unless the finding says to remove them.

Discipline for production quality:

- **Definition-site rule.** Never write a number, size, field name, order, tag,
  or derivation into the spec without having read its definition site in the
  code during THIS run. A `fix:` line is direction, not evidence — cite-check it
  before applying. If code and `fix:` disagree, the code wins; note the
  discrepancy in the report.
- **Net-line discipline.** A correction replaces text; it does not append beside
  it. Target zero net prose growth for corrections. A new section earns each
  line: every sentence and table row must carry a fact stated nowhere else. When
  a rewrite lets you delete a now-redundant passage elsewhere, delete it.
- Preserve the normative voice: MUST/SHOULD/MAY (RFC 2119), define-once-and-link,
  no restated derivations, no review-process language in the spec.
- Comment justification pass: over every code block you touch (and, in `full`
  scope, every code block in the spec), apply the justification test in
  `references/spec-style.md` — delete any comment that narrates a field, restates
  an encoding/size/derivation already given by the type or a linked definition,
  or was copied from the implementation. A comment present in the source code is
  not thereby justified in the spec.
- Change-justification annotations: every passage this mode edits or adds gets
  one adjacent markdown comment, `<!-- ZSR-NNNN: why -->` — a single brief
  sentence stating why the change appeared (the code truth or checklist gap
  behind it), so the commit diff reviews itself. Invisible when rendered; the
  operator may strip them after review. One comment per contiguous edit site,
  not per line; never restate the finding body — compress it to its point.
  Coverage is over the whole working diff: run `git diff HEAD -- docs/spec.md`
  and annotate every un-annotated change site left by prior runs too, matching
  each site to its ledger finding (skip the TOC and pure link-slug repairs —
  those justify themselves). Place comments outside code fences and separated
  from tables by a blank line; correct any existing annotation that misstates
  its site.
- Table cells hold at most two short sentences. Longer rationale moves to a
  notes list after the table (SPEC_GUIDE pattern 30); a cell that needs a
  paragraph is a section, not a row.
- Every new number is named with a unit and a source; every new struct that
  crosses a trust boundary gets a visibility note.

Self-review before finishing (adversarial, on your own diff):

1. Run `just spec-lint` — it must exit 0. Never hand-check links; the lint is
   authoritative.
2. Check no edit contradicts another section (a constant you changed in one
   place is consistent everywhere — grep the old value).
3. Re-read each edited passage against `references/spec-style.md` — no filler,
   copula over inflated verbs, comments justified, dense table cells.
4. **Independent verification.** For every heavy rewrite (a layout, a byte-size
   arithmetic, a public-input list, a permission row), launch one read-only
   subagent with ONLY the edited spec text and the code paths, asking it to
   refute each concrete claim. Fix what it refutes; do not argue with it. Your
   own re-read is not verification — a fresh context is.

Then, for every finding you fully closed in the spec, set `status: auto-resolved`
and add `resolved: <YYYY-MM-DD> spec updated`. Use `auto-resolved`, never
`resolved`: these edits are machine-applied and unverified, so the status must
record that provenance while still passing the gate (the fix ships through a
reviewed PR). Leave `design-weakness` and `code-bug` findings `open`. Run
`just spec-gate`; it passes once no finding is `open` — the auto-resolved ones do
not trip it. Report the sections edited (with the finding ID each closes) and the
findings left open with why.

`--permission-mode acceptEdits` means this mode does not stop to ask — it does
not mean the edits skip human review. Review `git diff docs/spec.md` before
committing.
