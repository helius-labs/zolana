# Spec Review Pipeline

Keeps `docs/spec.md` truthful against the code and at production grade. The
code moves faster than the spec; this pipeline measures the gap, records every
divergence as an operator-reviewed finding, and can rewrite the spec to close
it. CI stays red while a finding is unhandled, so drift cannot land silently.

## Parts

| Part | Role |
| --- | --- |
| `findings.md` (this directory) | The ledger: one entry per divergence, machine-parsed. Gitignored local review state — a clone without one gates nothing until an audit writes it. Grammar in `.claude/skills/spec-review/references/findings-format.md` |
| `.claude/skills/spec-review/` | The review skill: audit modes compare spec vs code and append findings; fix mode rewrites the spec |
| `xtask spec-gate` | Deterministic gate: exit 1 while any finding is `status: open` |
| `xtask spec-lint` | Deterministic lint: dead anchors, unresolvable links, banned vocabulary |
| `.github/workflows/spec-review.yml` | Runs gate + lint on every PR (no API key). A manual dispatch runs the headless review and uploads its edits as a patch artifact — it never writes to the repository |
| `.githooks/pre-commit` | Opt-in local gate (`just install-hooks`); bypass once with `--no-verify` |

## Use

```bash
just spec-gate            # fails while any finding is open
just spec-lint            # anchors, links, vocabulary; warnings don't fail
just spec-review          # headless audit: appends findings, never edits the spec
just spec-review-diff     # audit only sections whose mapped code changed since origin/main
just yolo-fix-spec        # operator-only: rewrite the spec to code truth, auto-resolve
just install-hooks        # enable the pre-commit gate
```

The audit recipes need the `claude` CLI (logged in, or `ANTHROPIC_API_KEY` —
see `.env.example`).

## Finding lifecycle

`open` trips the gate until someone acts. An operator flips it to
`acknowledged` (risk accepted) or `resolved` (verified fixed).
`yolo-fix-spec` flips the findings it settles to `auto-resolved` — passes the
gate, but records that the edit is machine-applied and unverified, so it still
ships through a reviewed PR. `design-weakness` and `code-bug` findings are
never auto-resolved: they need a code change or a human decision.

Every fix edit carries an adjacent `<!-- ZSR-NNNN: why -->` markdown comment —
invisible when rendered — so `git diff docs/spec.md` justifies itself row by
row. Strip them after review at will.
