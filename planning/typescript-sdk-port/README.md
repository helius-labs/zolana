# TypeScript SDK port plan

This directory defines the implementation contract for a TypeScript port of the
Rust SDK. It does not authorize changes to `docs/spec.md` or the Rust
implementation.

## Current baseline

All current Rust claims and inventory rows use the selected `origin/main`
revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`). This revision is
frozen for the plan; later changes to `origin/main` do not change the baseline.
Its `sdk-libs` tree contains 182 tracked paths.

The repository worktree may be older than the frozen revision. Read current
evidence with revision-qualified commands:

```text
git show 43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f:<path>
git ls-tree -r --name-only 43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f sdk-libs
```

Do not derive current claims from the checked-out file at the same path.

## History and evidence

The plan passed through three Rust baselines:

1. The first inventory used local commit
   `2e1d7c815691054f79ac2cbfb372190e61747696` (`2e1d7c8`). It counted 170
   tracked `sdk-libs` paths and assigned wallet actions to `zolana-client`.
2. Public workflows were then inspected at
   [`helius-labs/zolana-examples@4d8c2d1`](https://github.com/helius-labs/zolana-examples/tree/4d8c2d16487a653d163d80b8c7f6e3702ebfdadc/rust-client/examples).
   That examples revision pins Zolana
   `2eba04498ab852e2c3135bf25e20f11e9d28bb2c` (`2eba044`). It provided
   concrete deposit, transfer, withdrawal, private-transaction signing, and
   confirmation workflows.
3. The selected parity baseline is current `origin/main`
   `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`), with 182 tracked
   `sdk-libs` paths. It separates wallet state and actions into
   `zolana-wallet` and includes `zolana-indexer-api` and
   `zolana-smart-account-client`.

The first plan became stale because it combined an older 170-path inventory
with names learned from examples pinned to a different Rust revision. It listed
exports and broad responsibilities but did not define complete callable
signatures or the create, prove, build, sign, submit, confirm, and sync stages.
It also retained the old `signTransaction` name and client-owned wallet
boundary after current Rust had changed both.

PR
[`helius-labs/zolana#111`](https://github.com/helius-labs/zolana/pull/111)
remains TypeScript implementation reference material. It does not define the
current package graph or override higher-precedence sources.

## Before and after

| Concern | First plan | Refreshed plan |
| --- | --- | --- |
| Rust baseline | Local `2e1d7c8` | Frozen `origin/main` `43fde8e4` |
| Tracked SDK paths | 170 | 182 |
| Wallet ownership | Folded into `@zolana/client` | Separate `@zolana/wallet` |
| Indexer schema | Folded into generated `@zolana/api` | `@zolana/indexer-api` schema and `@zolana/api` transport |
| Action contract | Export names and broad responsibilities | Exact functions, methods, types, stages, errors, and examples |
| Signing name | `signTransaction` | `signPrivateTransaction` |
| Instruction flow | Deferred to final examples | Defined before implementation and tested independently |

## Start here

Read the package in this order:

1. [Architecture and API contract](architecture-and-api.md) for package
   boundaries and dependency direction.
2. [Public export manifest](public-exports.md) for the exact callable surface.
3. [Action and instruction API](action-and-instruction-api.md) for complete
   action-level and instruction-level workflows.
4. Read the six inventories for frozen-path coverage and implementation
   disposition: [client](inventory-client.md),
   [wallet](inventory-wallet.md),
   [transaction](inventory-transaction.md),
   [keypair](inventory-keypair.md),
   [supporting crates](inventory-support.md), and
   [indexer and smart account](inventory-indexer-and-smart-account.md).
5. [Examples and PR #111 assessment](examples-and-pr111.md) maps the eight
   public workflows and prior TypeScript work to the current contracts.
6. [Testing and conformance](testing-and-conformance.md) defines parity
   fixtures and independent action-level and instruction-level tests, then
   [security, dependencies, and release](security-and-release.md) defines the
   security and release gates.
7. [Implementation work packets](work-packets.md) assigns ordered,
   non-overlapping implementation work.

## Planning documents

- [README](README.md): freezes the baseline, records evidence history, and
  defines navigation and source precedence.
- [Architecture and API contract](architecture-and-api.md): decides package
  ownership, dependencies, runtime boundaries, and deliberate TypeScript
  differences.
- [Public export manifest](public-exports.md): defines the checked root and
  subpath export allowlists with exact TypeScript declarations.
- [Action and instruction API](action-and-instruction-api.md): defines exact
  deposit, transfer, withdrawal, proving, signing, submission, confirmation,
  and sync call sequences.
- [Client inventory](inventory-client.md): maps current transport, RPC, prover,
  and confirmation paths and records moved wallet paths as history.
- [Wallet inventory](inventory-wallet.md): maps wallet state, actions,
  registry, authority, sync, and wallet tests.
- [Transaction inventory](inventory-transaction.md): maps transaction data,
  serialization, spend inputs, transfer construction, slots, and proof inputs.
- [Keypair inventory](inventory-keypair.md): maps shielded key material,
  encryption, hashing, signing, viewing, and keypair errors.
- [Supporting-crate inventory](inventory-support.md): maps merkle-tree,
  program-test, and Zolana API transport paths.
- [Indexer and smart-account inventory](inventory-indexer-and-smart-account.md):
  maps indexer schemas and smart-account instruction helpers.
- [Examples and PR #111 assessment](examples-and-pr111.md): decides how the
  eight pinned workflows and each PR component inform the current port.
- [Testing and conformance](testing-and-conformance.md): defines fixtures,
  byte-level parity, negative and property tests, integration and E2E tests,
  runtime coverage, and CI gates.
- [Security, dependencies, and release](security-and-release.md): defines
  authority boundaries, secret handling, dependency criteria, browser
  constraints, and release controls.
- [Implementation work packets](work-packets.md): defines prerequisites,
  disjoint file ownership, required evidence, and completion criteria.

## Inventory rules

The inventories must account for all 182 paths returned by:

```text
git ls-tree -r --name-only 43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f sdk-libs
```

Each current path must have exactly one active row or explicit exclusion. Each
active row records:

- Rust path and symbol;
- target TypeScript package/module;
- public symbol or test responsibility;
- observable behavior and invariants;
- primary dependencies;
- typed error mapping;
- fixtures and required unit, property, integration, or E2E tests;
- owning implementation packet;
- disposition: `port`, `reuse`, `internal`, `test-only`, or `not applicable`.

## Source precedence

Use sources in this order. A lower source cannot override a higher source:

1. [`docs/spec.md`](../../docs/spec.md) defines protocol behavior and Zolana
   terminology. For this frozen plan, inspect its `43fde8e4` revision.
2. Rust at frozen revision `43fde8e4` defines current SDK behavior, package
   ownership, and program/interface layouts where the spec does not decide a
   language-level detail.
3. Rust fixtures at `43fde8e4` define observable conformance vectors.
4. The workflows in `zolana-examples@4d8c2d1`, pinned to Zolana `2eba044`,
   define usability evidence. Record differences from current Rust instead of
   copying stale names or ownership.
5. PR #111 is implementation reference material only.

## Definition of complete

The port is complete only when:

- all `port` and `reuse` inventory rows have an implementation and mapped test;
- the public export snapshot matches the crosswalk;
- Rust-generated fixture bytes and TypeScript bytes match exactly;
- every example workflow passes against localnet, Photon, and the prover;
- Node and browser gates pass for packages marked browser-compatible;
- no core package imports `node:*`, reads `process.env`, or depends on `Buffer`;
- API Extractor (or an equivalent declaration snapshot), TypeScript strict
  checking, lint, unit, property, conformance, integration, and package-consumer
  tests pass;
- security and protocol reviewers approve the invariant checklist.

## Open questions

Only two repository-external choices remain:

1. NPM scope and publication owner. Default to `@zolana/*` until the owner
   confirms registry access.
2. Minimum supported browser versions. Default to browsers with Web Crypto,
   `BigInt`, ES2022 modules, and `fetch`; publish the exact Browserslist before
   the first release.

Everything else in this plan has a repository-derived default.
