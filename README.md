# Zolana

## In scope

| Path | Role |
|---|---|
| `programs/` | On-chain SPP programs, including `shielded-pool` |
| `program-libs/` | Shared Rust interface crate |
| `program-tests/` | Internal test crates and test-only SBF programs |
| `sdk-libs/` | Rust SDK crates (`keypair`, `photon-api`, `program-test`, `transaction`) |
| `cli/` | Zolana developer and operator CLI |
| `forester/` | Off-chain nullifier-tree maintenance skeleton |
| `prover/` | Go prover server + Rust prover client |
| `xtask/` | Workspace dev tooling |
| `external/photon` | Submodule used to build Photon and regenerate `sdk-libs/photon-api` |

## Common entry points

All workflows go through `just`. Run `just` with no arguments for the full list.

```bash
just check-all         # cargo check across the workspace
just test-all          # Rust tests + litesvm program tests
just verify-rust       # check + Rust tests
just verify            # verify-rust + prover/server go tests
```

The Cargo workspace's `default-members` is deliberately narrow — `prover/client`,
`program-libs/interface`, and `programs/shielded-pool` — so a bare `cargo check` from the root
hits the production-critical surface quickly. For full-workspace coverage use `just check-all`.

## CI

Workflows under `.github/workflows/`:

- `rust.yml` — fmt, clippy, machete, check-all, per-area unit tests
- `forester.yml` — forester compile check
- `prover-server.yml` — Go test suite + xtask smoke
- `enforce-pr-only.yml` — fails direct pushes to `main`

Each workflow path-filters to its own area. Two composite actions back them:
`.github/actions/setup-rust` (toolchain + cache + just).

Direct push protection on `main` requires repo Settings → Branches → Branch protection rules.
The workflow is a backstop, not the enforcement.

## Local prerequisites

- Rust stable
- `just` — `cargo install just --locked`
- Go (for `prover/server` tests)
- Anza / Solana CLI 4.x for `cargo build-sbf` (only needed for SBF program builds)
- `just build-cli`, `just install-surfpool`, `just install-photon`,
  `just build-prover-server`, and `just build-programs` for local validator flows
- Proving keys in `prover/server/proving-keys/` only if you want to run
  `just xtask-create-verifying-keys-smoke` — the directory is gitignored; obtain the keys from
  upstream's `scripts/install.sh`.
