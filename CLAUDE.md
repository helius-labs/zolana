# Zolana Contributor Notes

## Source Of Truth

`docs/spec.md` is the protocol source of truth. Do not edit it as part of
implementation cleanup unless that is the explicit task. If code, tests, and the
spec disagree, treat the code or tests as suspect first.

## Workspace Shape

- `programs/shielded-pool`: on-chain SPP program.
- `program-libs/interface`: shared instruction data, tags, constants, and layout
  helpers.
- `program-tests`: internal test crates and test-only SBF programs.
- `sdk-libs`: externally useful Rust SDK crates.
- `cli`: local developer/operator tooling.
- `forester`: compileable forester skeleton for future nullifier-tree
  maintenance work.
- `prover`: proof client and prover server.

## Common Commands

Use `just` recipes for normal workflows:

```bash
just check-all
just test-shielded-pool
just test-sdk-libs
just test-litesvm
just test-cli
just clippy
```

Program tests that load real SBF binaries need the local builds:

```bash
just build-programs
just test-localnet-proofless
```

`just test-localnet-proofless` intentionally leaves the validator running for
local inspection. Stop it with:

```bash
just stop-localnet
```

## Code Style

- Keep protocol math in one canonical implementation and reuse it from tests.
- Keep public SDK surface deliberate; test-only helpers belong under
  `program-tests` unless they are useful to external developers.
- Avoid compatibility shims for removed Light/legacy surfaces.
- Prefer small, explicit helpers over broad abstractions.
- Comments should explain invariants, security constraints, or non-obvious
  layout decisions. Remove comments that only narrate the code.

## Fixtures

Local validator account fixtures are built, verified, and optionally installed
through:

```bash
just build-fixtures
just verify-fixtures
just install-fixtures
```

## Git Hygiene

The worktree may contain user changes. Do not revert unrelated edits. Keep PRs
small when possible: protocol/program changes, tooling cleanup, and prover
renames should be split unless the task explicitly asks for a combined change.
