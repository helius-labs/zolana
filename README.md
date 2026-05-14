# Zolana

## In scope

| Path | Role |
|---|---|
| `forester/`, `forester-utils/` | Forester tree-maintenance service + helpers |
| `programs/`, `anchor-programs/` | On-chain programs (account-compression, registry, system, compressed-token, shielded-pool) |
| `program-libs/` | Shared crates (batched-merkle-tree, interface, heap) |
| `program-tests/` | Test fixtures + reference Merkle tree implementation |
| `sdk-libs/` | Rust SDK surface (`client`, `token-sdk`, `compressed-token-sdk`, `event`, `program-test`, `photon-api`, `cli`) |
| `prover/` | Go prover server + Rust prover client |
| `xtask/` | Workspace dev tooling |
| `external/photon` | Submodule — OpenAPI spec used by `sdk-libs/photon-api` codegen |

## Common entry points

All workflows go through `just`. Run `just` with no arguments for the full list.

```bash
just check-all         # cargo check across the workspace + SBF fixture crates
just test-all          # full Rust test suite (no validator required)
just verify-rust       # check + test + photon-api codegen check
just verify            # verify-rust + prover/server go tests
```

The Cargo workspace's `default-members` is deliberately narrow — `forester`, `forester-utils`,
`photon-api`, `prover/client`, `program-libs/interface`, and `programs/shielded-pool` — so a bare
`cargo check` from the root hits the production-critical surface quickly. For full-workspace
coverage use `just check-all`, which handles the two SBF fixture crates that must build with
`--features no-entrypoint` rather than their default feature set.

## CI

Workflows under `.github/workflows/`:

- `rust.yml` — fmt, clippy, machete, check-all, photon-api codegen, per-area unit tests
- `forester.yml` — compile/smoke (no infra) and bounded e2e + compressible (Redis + Light CLI + Anza CLI)
- `prover-server.yml` — Go test suite + xtask smoke
- `enforce-pr-only.yml` — fails direct pushes to `main`

Each workflow path-filters to its own area. Two composite actions back them:
`.github/actions/setup-rust` (toolchain + cache + just) and `.github/actions/setup-forester-e2e`
(adds Node + Anza CLI + Light CLI on top of setup-rust).

Direct push protection on `main` requires repo Settings → Branches → Branch protection rules.
The workflow is a backstop, not the enforcement.

## Local prerequisites

- Rust stable
- `just` — `cargo install just --locked`
- Go (for `prover/server` tests)
- Node 20+ and the [Light CLI](https://www.npmjs.com/package/@lightprotocol/zk-compression-cli)
  for forester e2e tests — install with `just install-light-cli`
- Anza / Solana CLI 2.3.x for `cargo build-sbf` (only needed for forester e2e / compressible /
  SBF fixture builds)
- Proving keys in `prover/server/proving-keys/` only if you want to run
  `just xtask-create-verifying-keys-smoke` — the directory is gitignored; obtain the keys from
  upstream's `scripts/install.sh`.