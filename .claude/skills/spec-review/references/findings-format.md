# Findings Ledger Format

Single source of truth for the grammar of `docs/spec-review/findings.md`.
Enforced by `xtask spec-gate` (`xtask/src/spec_gate.rs`); change them together.

## File layout

A free-form preamble (the `# Spec Review Findings Ledger` heading and prose),
followed by zero or more entries. Every `## ` heading in the file must be an
entry heading.

## Entry grammar

```markdown
## ZSR-0001: <short title>
- status: open
- severity: high
- type: design-weakness
- code: programs/shielded-pool/src/instructions/transact/processor.rs:128
- spec: docs/spec.md#merge
- opened: 2026-07-17
- fix: <one line: the concrete correction, so the fix pass need not re-derive it>
- resolved: 2026-08-01 fixed by #241

Free-form prose: what the spec claims, what the code does (with the citation),
and the reader/implementer consequence. Bullet lines whose key is not a field
name are treated as prose.
```

Rules:

- Entry heading must match `## ZSR-NNNN: <title>` (exactly four digits,
  non-empty title). IDs must be unique; new entries use max existing ID + 1.
- Required fields, each exactly once per entry, non-empty:
  - `status`: `open` | `acknowledged` | `resolved` | `auto-resolved`
  - `severity`: `critical` | `high` | `medium` | `low` | `info`
  - `type`: `design-weakness` | `spec-gap` | `code-bug` | `spec-quality`
  - `code`: `path[:line]` of the most relevant code location (for a
    `spec-quality` structural gap, cite the code the missing section would
    document, or `docs/SPEC_GUIDE.md:<line>` for the requirement)
  - `spec`: `docs/spec.md#<anchor>` of the affected (or missing) spec section
  - `opened`: `YYYY-MM-DD`
- Optional fields:
  - `fix`: one line stating the concrete correction. Strongly recommended for
    every `spec-gap` / `spec-quality` finding — it is what `yolo-fix-spec`
    applies, so a precise `fix` line makes the autofix deterministic.
  - `resolved`: date plus short note; set when status becomes `resolved`.
- A trailing ` # comment` on a field line is stripped before validation.
- Entries are never deleted; the operator (or `yolo-fix-spec`) flips `status`
  and fills `resolved`.

## Lifecycle

- `open` — recorded by the skill, unreviewed. Fails `spec-gate` (and CI). The
  only status that fails the gate.
- `acknowledged` — operator has reviewed; accepted risk or tracked elsewhere.
  Passes the gate.
- `auto-resolved` — closed in the spec by `yolo-fix-spec`, machine-applied and
  not yet human-verified. Passes the gate (the fix landed and ships through a
  reviewed PR), but stays distinct from `resolved` so an operator can spot-check
  the autofix. Only `yolo-fix-spec` sets this.
- `resolved` — addressed and human-verified (operator confirmed the spec edit,
  or the code fix for a `code-bug`/`design-weakness` landed). Passes the gate;
  kept as history.

## Types

- `design-weakness` — the protocol design itself has a weakness (security,
  liveness, privacy); fixing it means changing the design, not the prose.
- `spec-gap` — the spec disagrees with the code, is silent about implemented
  behavior, or overclaims (privacy, restrictions). The correction is a spec
  rewrite (`yolo-fix-spec` handles these).
- `code-bug` — the code contradicts the spec and the code looks wrong; the
  spec was deliberately NOT patched to match the bug. Needs a code change.
- `spec-quality` — the spec is missing a structural element required for a
  production-grade spec by `docs/SPEC_GUIDE.md` (Trust Assumptions, Constants
  table, Permission Matrix, a wire struct's visibility table, a named-error
  table, an entry-point validate-and-execute list, an upgrade/versioning
  story, a recovery path, a failure-path diagram). Not a code disagreement;
  a completeness gap. `yolo-fix-spec` fills these.

Severity reflects reader/implementer consequence, not tone:

- `critical` — a reader acting on the spec loses funds or privacy, or an
  implementer ships an exploitable bug.
- `high` — an implementer builds the wrong behavior, or a real security
  weakness is undocumented.
- `medium` — a reader forms a materially wrong belief about the protocol.
- `low` — a precise reader is briefly misled or inconvenienced (stale number,
  dead link, missing minor field).
- `info` — worth recording, no reader is misled today.
