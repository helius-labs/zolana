# Triaging the first CI run this branch has ever had

**Sixteen failures reduce to seven causes. Six are ours and fixed; one is a
collision with `main` that cannot be fixed from inside the scope rule. Two of
the seven "localnet photon" failures were runner infrastructure and never had a
code cause at all.**

PR #159 sat as a draft for its whole life and every job is gated on
`draft == false`, so nothing here had ever been measured. The failures are not
sixteen defects. They are a handful of defects multiplied by how many jobs each
one takes down, plus two infrastructure flakes that happened to land in the same
run.

The fixes are on `port/ci-green` as PR #162, targeting `ts-sdk-port`.

## What actually broke

### `cargo run -p xtask` became ambiguous, and five jobs died four minutes later

This is the most valuable finding and it was hiding behind a symptom that
pointed somewhere else entirely.

Five of the seven `tests / localnet photon / *` jobs failed with every cucumber
scenario panicking on its first step:

```
Step panicked. Captured output: SHIELDED_POOL_PROGRAM_ID must be set: NotPresent
```

The variable is not missing from the workflow. It is produced by the recipe
itself:

```
eval "$(cargo run -q -p xtask -- program-ids)"
export SHIELDED_POOL_PROGRAM_ID
```

`main` has no `xtask/src/bin/` directory, so `xtask` was a single binary and the
bare `cargo run -p xtask` was unambiguous. The port added seven binaries beside
it, and cargo now refuses to guess:

```
error: `cargo run` could not determine which binary to run.
available binaries: merkle-semantics, poseidon-parity, program-libs-parity,
ts-fixtures, ts-interface-oracle, wallet-actions, wallet-sync-tags, xtask
```

`eval "$(...)"` does not propagate that failure even under `set -euo pipefail`,
because the substitution's exit status is discarded and `eval ""` succeeds. So
the recipe continued with nothing exported, built the whole workspace, started a
validator, and only failed minutes later inside the tests, reporting a missing
environment variable rather than the `cargo run` that failed to set it.

Fixed by adding `default-run = "xtask"` to `xtask/Cargo.toml`, which restores
the behaviour every one of these recipes was written against.

The silent `eval` is a real fragility and it is why this cost so much diagnosis
time, but hardening it means editing roughly ten recipes and is not required to
get CI green. Worth doing separately.

### A dead function that was only dead in one of three test binaries

`eddsa_input_utxo` in `program-tests/shielded-pool/tests/common/transact_core.rs`
triggered `function is never used`, which `RUSTFLAGS: "-D warnings"` turns into a
build failure in CI and nowhere else.

Deleting it would have been wrong. That file is `#[path]`-included into three
test binaries and two of them use the function: `transact` calls it directly at
`transact/transact.rs:107`, and `bench_cu` and `localnet_photon_e2e` reach it
through the `common/transact.rs` re-export. Only `double_spend` compiles it
without calling it, so the warning is an artifact of how the targets are split.

Fixed with `#[allow(dead_code)]` on the function itself, carrying a comment that
names the three consumers. Not on the module and not on the crate: an
item-level allow still reports every other unused item in that file, where a
module-level one would have blanketed all of it.

This took down `tests / programs` and `tests / shielded-pool`. It did **not**
cascade into the localnet photon jobs, which failed for the unrelated reason
above, and it did not cause the clippy failure either.

### Clippy, and what was hiding behind the one line I could not touch

Clippy stops at the first crate that fails, and the first crate that fails is
`zolana-interface`:

```
error: useless use of `vec!`
   --> program-libs/interface/src/merge_utils.rs:167:33
```

`program-libs/**` is denylisted, so this is reported rather than fixed. See the
blocked section below.

Because clippy halts there, no one could see what was behind it. Applying the
one-line fix locally as a throwaway probe, running clippy, and reverting the
probe revealed six more errors in `xtask/src/bin/ts-interface-oracle.rs`, all
`using clone on type TransactWithdrawal which implements the Copy trait`. Those
are in scope and are fixed. With both applied, clippy is clean across the
workspace.

That probe is the difference between "one blocked line" and "one blocked line
plus six real errors nobody would have seen until it was unblocked".

### rustfmt disagreed with every local run for a boring reason

`rust-toolchain.toml` pins 1.97.0 and CI honours it. Local runs had been using a
newer default rustfmt, whose line-wrapping differs. Reformatting under the
pinned toolchain touches nine files in `sdk-libs/` and changes nothing but
whitespace.

### Two more, both trivial

`cargo-machete` correctly flagged `zolana-indexed-array` in
`tools/wasm-oracle/crate/Cargo.toml`; the crate is named in a doc comment and
never imported. Clippy also rejected a redundant `use wincode;` in
`sdk-libs/transaction/tests/ts_oracle.rs`.

### `typescript / merge gate` has no logic of its own

Confirmed by reading it: it is `needs: [gate-scope, planning, static, suites,
packaging, fixtures, e2e]` and a loop over `join(needs.*.result)`. It failed
because `fixtures` and `packaging` failed. Not a seventeenth problem.

Worth noting the adjacent `gate-scope` job does have real logic. It asserts the
workflow's job list matches `package.json`'s `check` script exactly, so a new
sub-script cannot be added to `check` without a job to run it. That one is
carrying weight and should not be confused with the aggregate.

## The two failures that were never code

`tests / localnet photon / rfq settlement` and `dynamic-swap lifecycle` both
died in the Anza toolchain install step, before any code ran:

```
agave-install-init: command failed: downloader
https://release.anza.xyz/v4.0.2/agave-install-init-x86_64-unknown-linux-gnu
```

Same runner batch, same minute. Infrastructure, not a defect, and they should
pass on a re-run. They are called out here because they are the two jobs most
likely to be misattributed to the `default-run` fix that legitimately explains
the other five.

## `check:packaging` could not run from a clean checkout

Inherited from `ts-sdk-port` rather than caused here. The same failure is in
that branch's own run `30177411202`, at the same path.

```
Error: ENOENT: no such file or directory, access
'.../sdk-libs/ts/interface/dist/index.d.ts'
```

`test:browser` and `pack:check` each begin with `npm run build`, but
`test:exports`, `test:dependencies`, and `api:check` read `dist/` without
building, and `check:packaging` runs those three first. Developers never saw it
because they build before checking; the CI job runs `npm ci` and then
`check:packaging` on a tree with no `dist` at all, and there is no `prepare`
script to fill one in.

Fixed by starting `check:packaging` with `npm run build`. This is worth more
than unblocking the job: it also removes the stale-artifact hazard that made the
local reproduction of the original `globalThis.process` failure disagree with
CI. The gate previously could pass locally against a `dist` built from source
that no longer existed. It now always inspects freshly built output, and it
still checks the same six things afterwards.

The one-line `scripts.check` string that `gate-scope` asserts against is
untouched, so that job keeps its meaning.

## Why PR #162 reported no checks at all

Worth knowing for the next person, because it looks exactly like a broken
workflow and is not one. After the fixes were pushed, `gh pr checks 162` kept
reporting "no checks reported" while runs plainly existed on the branch.

The cause was `mergeable: CONFLICTING`. `ts-sdk-port` had moved twenty commits
ahead and `sdk-libs/transaction/tests/ts_oracle.rs` conflicted. GitHub cannot
build the merge commit that `pull_request` workflows run against, so it starts
no jobs rather than reporting a failure. The PR looks untested and healthy at
the same time.

Merging `ts-sdk-port` in and resolving the one conflict flipped the PR to
`MERGEABLE` and every workflow started within a minute. On a branch this
long-lived, "no checks reported" should be read as a merge-state question
before it is read as a CI question.

## Blocked by the scope rule

### `cargo check (workspace)`: `main` and the port disagree about `CreateTree`

`main` commit `d6cc003e`, "remove dead fields from batched Merkle tree (#156)",
removed the `owner` field:

| | `CreateTree` fields |
| --- | --- |
| `main` | `authority`, `tree` |
| this branch | `authority`, `tree`, `owner` |

The branch's `xtask/src/bin/ts-interface-oracle.rs:583` sets `owner`. In the
merge commit CI builds for #159, `main`'s struct wins and the oracle fails to
compile with `E0560`.

This cannot be fixed from inside the scope rule. Dropping `owner` from the
oracle alone does not compile on this branch, because the branch's struct still
requires the field; making it compile means editing
`program-libs/interface/src/instruction/builders/create_tree.rs`, which is
denylisted. It is also not a mechanical choice. It is a ruling on whether the
port needs a field `main` judged dead.

It does not affect PR #162, which targets `ts-sdk-port` rather than `main`. It
will block #159 until someone with authority over `program-libs/` reconciles it.

### The clippy line in `merge_utils.rs`

Introduced by this port's own commit `d7d228c6`, "reuse canonical merge
ciphertext hash", so it is ours by provenance but not ours to edit. The file
does not exist on `main`. One character-level change inside a `#[cfg(test)]`
block:

```rust
assert!(ciphertext_hash(&[0; 193]).is_err());  // was &vec![0; 193]
```

Until it is applied, the clippy job stays red no matter what else is fixed.

## Gates: what changed and what it still catches

No gate was weakened. One pin was moved, which is what that gate exists to make
you do.

`ts-fixtures` pins fixture provenance per source group. Formatting `sdk-libs/`
touched `sdk-libs/transaction/tests` and `sdk-libs/client/src/prover`, both in
`BASELINE_SOURCE_PATHS`, so the gate correctly reported drift. `BASELINE_SHA`
moved to the formatting commit and the fixtures were regenerated. The diff is
revision stamps and their hashes only; no fixture content changed, which is the
expected signature of a whitespace-only change to a pinned source.

Afterwards the gate still catches exactly what it caught before: any edit to
those twelve source paths that is not accompanied by a re-pin and a
regeneration. `HISTORICAL_BASELINE_SHA`, which freezes the 182-row inventory,
`docs/spec.md`, and the proving-key lockfile, was not touched.

The browser check in `sdk-libs/ts/config/browser-check.mjs` was made *stricter*,
not looser. It now catches `process?.env` and the multi-line `globalThis.process`
form that let the original leak through a source-level scan. It continues to run
against the minified bundle.

## Local verification

Green under the pinned 1.97.0 toolchain: `cargo check --workspace --all-targets`
with `RUSTFLAGS="-D warnings"`, `cargo fmt --all --check`, `cargo machete`, and
`cargo clippy --workspace --all-targets -- -D warnings` (modulo the one blocked
line). Green on the TypeScript side: `build`, `typecheck`, `lint:packages`,
`test:unit` (1496 passing), `check:packaging`, and `fixtures:check` (58 fixtures,
182 inventory rows). All re-run after merging `ts-sdk-port`.

## Row note

`K13`: `ProverClient.local()` no longer reads `ZOLANA_PROVER_URL`. The
environment read was removed outright rather than stubbed, and Node callers who
need the offset-aware URL take it from `@zolana/test-kit`'s `localStackUrls` and
pass it to the constructor. This is a public change to `@zolana/client` and the
reason the browser bundle stopped containing `process`.
