# Verifying the WebAssembly Poseidon

Branch `port/wasm-verify`, merged onto the integration tip `03584e8e`. The
subject is the work that landed in `42867b15`: five hand-written TypeScript
Poseidons collapsed onto `zolana_hasher::Poseidon` compiled to WebAssembly.

**Verdict: the hasher agrees with Rust and is safe to depend on.** No wrong
digest was found in any environment. No hand-written Poseidon survives in
shipped code, and there is no fallback that could reintroduce one. One gap was
found in the tests rather than in the hasher, and it is closed here. One
unguarded staleness risk is left open for a ruling, because closing it means
touching CI, which this branch does not own.

## Where a divergence could hide

A digest is only as good as the weakest link between the Rust the program runs
and the bytes TypeScript hashes with. There are four links, and each was checked
separately rather than end to end, because an end-to-end pass hides which link
is load bearing.

### The artifact is the committed Rust

`artifact.ts` is a 1,503,358 byte base64 literal. Nothing in the build produces
it: `npm run build` runs `tsc`, and only `npm run embed -w @zolana/hasher`
regenerates it. So a stale artifact would ship in silence.

Forced a rebuild by touching both `sdk-libs/hasher-wasm/src/lib.rs` and
`program-libs/hasher/src/poseidon.rs`, then re-embedded:

```bash
touch sdk-libs/hasher-wasm/src/lib.rs program-libs/hasher/src/poseidon.rs
npm run embed -w @zolana/hasher
git diff --quiet -- sdk-libs/ts/hasher/src/artifact.ts   # clean
```

Byte identical. The wasm crate takes `zolana-hasher` by path into
`program-libs/hasher`, so the artifact in the tree is the Rust in the tree. The
build reproduced byte for byte four more times across the control edits below,
each time returning to the committed hash after a revert, so this is a
reproducible build and not a coincidence.

### The fixture is the current Rust

```bash
cargo run -q -p xtask --bin poseidon-parity -- --check
# verified sdk-libs/ts/vectors/poseidon-parity-v1.json
```

`poseidon-parity-v1.json` regenerates identically from `zolana-hasher`, so its
100 vectors, 6 rejections and 4 short-input cases describe the Rust hasher as it
stands today, covering arity 1 through 12.

### The fixture and the artifact could be wrong together

They share an origin. Both come from `zolana-hasher`, so a fault inside it would
be invisible to any test that compares one against the other, and the five
implementations that used to supply a second opinion were deleted.

Two independent checks close this.

The **parameters** are compared against constants nobody in this repo wrote.
`poseidon-parity.test.ts` regenerates the round constants and MDS matrix from
the Grain LFSR through `@noble/curves` and compares SHA-256 digests over their
canonical encodings against digests taken from the arkworks tables inside
`light-poseidon`. Because the test also asserts the generated count equals
`arkCount`, a wrong partial-round count changes the length and fails, so the
round schedule is pinned and not merely echoed back from the fixture.

The **permutation** is compared against a second implementation.
`poseidon-independent-implementation.test.ts` recovers the Poseidon deleted in
`ab2e2863`, which builds its constants from the Grain LFSR rather than reading
arkworks' tables, and replays arities 1 through 12 over the field edges, 64
pseudorandom elements per arity, and the order-sensitivity pairs. It shares
neither code nor data with the artifact. It passes.

### Rust and TypeScript refuse the same inputs

This is where the suite was weakest, and it is the gap closed here. See
"Rejections" below.

## Out-of-range inputs

Rust rejects rather than reducing. `light_poseidon` refuses a non-canonical
field element, `Poseidon::hashv` returns `Err`, and `HasherError::Poseidon`
converts to **7002**. The fixture records the reason as
`Poseidon(InputLargerThanModulus)` for both an input equal to the modulus and an
input of all `0xff`.

TypeScript does the same thing, and does it by delegation rather than by
imitation: `@zolana/hasher` copies the 32 bytes into the module's buffer and
returns whatever code Rust gives it. An input at or above the modulus comes back
7002 in Node and in Chrome. The boundary sits exactly at the modulus: `p - 1`
hashes, `p` does not.

Two deliberate divergences, both now pinned by tests:

| Input | Rust | TypeScript |
| --- | --- | --- |
| At or above the modulus | refuses, 7002 | refuses, 7002 from Rust |
| Shorter than 32 bytes | refuses, `InvalidInputLength` | accepts, right-aligned |
| Longer than 32 bytes | refuses, 7002 | refuses, 7005 in the wrapper |
| Arity 0 or above 12 | refuses, 7002 | refuses, 1 in the wrapper |

The short-input widening is intentional and checked: `shortInputs` pins each
short form to the Rust digest of the same value padded to 32 bytes, so it is a
wider domain and not a different digest. Callers rely on it, because
`ciphertext_hash` chunks 16 bytes at a time.

The two wrapper codes are inherent rather than sloppy. Thirteen elements do not
fit a twelve-slot buffer and a 33-byte input would overrun its neighbour, so
neither can reach Rust to be assigned 7002. Both are now pinned so the
divergence stays deliberate.

## Rejections: the gap that was open

`poseidon-parity.test.ts` asserted only that a refused input throws. A
TypeScript screen standing in front of the module satisfies that just as well as
the compiled hasher does, and a screen is exactly what would go wrong: one that
reduces mod p, or reads the modulus off by one, refuses almost the same set and
hashes the rest to digests no verifier reproduces.

`sdk-libs/ts/hasher/test/vectors/poseidon-rejection-parity.test.ts` asserts the
code the rejection carries, which says which side of the boundary refused. The
control edit below shows the difference is not theoretical.

## Control edits

Every conformance claim above was checked by breaking the implementation,
observing the failure, and reverting. The two Rust edits required re-embedding
the artifact and rebuilding, so they exercise the whole chain from Rust source
to TypeScript digest.

| Edit | What broke | What caught it |
| --- | --- | --- |
| wasm returns `ERROR_ARITY` instead of Rust's code | rejection provenance | the new test, 3 failures. **All 235 pre-existing tests stayed green** |
| `elements[..count].reverse()` in the wasm | input order | 59 of 111 fixture vectors, 23 of 25 independent-implementation cases, 17 merkle-tree tests |
| Left-align inputs instead of right-aligning | short-input placement | 48 shared-instance, 4 short-input vectors in each parity suite, 1 module-formats |
| Corrupt the artifact's wasm magic bytes | the load path | `initializePoseidon` threw `CompileError`, `poseidon` refused with code 2, no digest produced |
| Plant `globalThis.process?.env` in the loader | the browser gate | `test:browser` failed: `@zolana/hasher source contains process?.` |

The first row is the one that justifies the new test. A generic error code is
indistinguishable from Rust's to every test that existed before, and it is
precisely the shape a silently-wrong screen would take.

The reverted edits left the tree byte identical to HEAD, artifact included.

Cases that kept passing were checked for the right reason rather than waved
through: order reversal leaves the symmetric vectors, all-zero and all-max,
correct, and left-aligning leaves every full-width 32-byte input correct because
the two alignments coincide there.

## Surviving hand-written Poseidon

None in shipped code, and no fallback.

Searched `sdk-libs/ts/*/src/**` for round constants, MDS tables, sbox and Grain
terms. Every `poseidon` in shipped source is either the `@zolana/hasher` wrapper
or a call into one. Five packages import a hashing primitive and all five import
it from `@zolana/hasher`:

```
interface/src/merge-utils.ts   transaction/src/internal.ts
keypair/src/poseidon.ts        client/src/internal.ts
merkle-tree/src/hashers.ts
```

`@noble/curves/abstract/poseidon` appears in five files, all of them tests: the
four parameter-parity suites and the independent-implementation oracle. Those
are second opinions, not fallbacks, and nothing in `src/` can reach them.

There are exactly two `catch` blocks on the hashing path and neither substitutes
a digest. `hasher/src/index.ts` clears the cached promise and rethrows, so a
failed load is retryable rather than sticky. `keypair/src/poseidon.ts` wraps the
error as `KeypairError` and rethrows.

The corrupted-artifact control settles it empirically. With the module
unloadable, `initializePoseidon()` threw, `isPoseidonInitialized()` stayed false,
and `poseidon()` refused with code 2. No path produced a digest.

## Node and the browser

**Node.** `module-formats.test.ts` drives the CommonJS and ESM builds as two
distinct instances over all 100 vectors and the short inputs, and `pack:check`
repeats the parity from installed tarballs on Node 20 and 22. Both pass.

**Browser.** Bundled `@zolana/hasher` with esbuild for `platform: browser`,
served it over HTTP, and ran it in Chrome 144 through the IDE browser rather
than inferring from a static scan:

| Check | Result |
| --- | --- |
| Chrome | 144 |
| `initializePoseidon()` | resolved in 6 ms |
| `MAX_POSEIDON_INPUTS` read off the module | 12 |
| The 100 fixture vectors | 100 checked, 0 mismatches |
| The 4 short-input cases | all right-aligned to the Rust digest |
| Input equal to the modulus | refused, code 7002 |

The browser agrees with Rust, not merely with Node.

**How it loads.** The bytes are inlined, not fetched. The browser bundle is
2,008,037 bytes, contains the base64 artifact, imports nothing from `node:`, and
calls `atob` with no `fetch` anywhere in the graph. So there is no asset to
serve, no network dependency, and no bundler plugin required. Compiling the full
1.5 MB synchronously cost 6 ms, which confirms the correction recorded in
`42867b15`: the 4 KB synchronous-compile ceiling that the plan cited as decisive
is not a real constraint. The initializer is still justified, but by CommonJS
and runtime uniformity rather than by that limit.

**Packaging.** `npm run check:packaging` passes end to end at this commit,
including `test:browser` and `pack:check`. The planted-leak control confirms the
gate still fails on a `globalThis.process` leak, so it passes because the leak is
absent rather than because it stopped looking.

## Needs an owner ruling

**Nothing regenerates or verifies the artifact in CI.** This is the one that
matters. `poseidon-parity --check` is not run by any workflow, `ts-fixtures`
does not cover `poseidon-parity-v1.json`, and no job runs `embed.mjs`. A change
to `program-libs/hasher/src/poseidon.rs` would therefore leave both the embedded
artifact and the fixture untouched, with every gate green, and TypeScript would
keep hashing with the old Rust while the program used the new one. That is the
divergence the ruling was meant to end, displaced from "a hand-written copy
drifts" to "the compiled copy goes stale". Both are correct today; the risk is
the next hasher change.

Light Protocol does not face this, because `@lightprotocol/hasher.rs` ships the
`.wasm` as a separate versioned npm artifact built by the package's own release
pipeline, so it cannot lag its source. Zolana inlines the artifact instead, for
reasons `embed.mjs` states and this verification supports, which removes that
natural rebuild and makes an explicit gate the substitute. The recommended path
follows the discipline the repo already uses for fixtures:

```bash
node sdk-libs/ts/hasher/scripts/embed.mjs
git diff --exit-code sdk-libs/ts/hasher/src/artifact.ts
cargo run -p xtask --bin poseidon-parity -- --check
```

The build is byte-reproducible on `rustc 1.97.0`, verified five times here, so
such a gate would be stable rather than flaky. Not implemented, because it
means editing `.github/workflows/typescript.yml` and the `gate scope` assertion,
which `port/ci-green` owns.

**The browser gate misses bracket notation.** Verified directly against the
regex in `browser-check.mjs`:

| Source | Gate |
| --- | --- |
| `globalThis.process.env.X` | caught |
| `globalThis.process?.env` | caught |
| `process.env.X` | caught |
| `globalThis["process"].env` | **missed** |
| `p["process"].env` where `p = globalThis` | **missed** |

No such access exists today, and the stronger control is that the code was run
in a browser with no `process` defined. Recorded as a limit of a regex gate. It
belongs to whoever owns `browser-check.mjs`, not to this branch.

**Two agents worked this task in this worktree at once.** See below.

## A worktree collision, on the same branch

A second agent was verifying the same commit in `zolana-ts-keypair` on
`port/wasm-verify` concurrently with this one. It committed `6f85395c` at
01:40, adding `hasher/test/shared-instance.test.ts` and
`keypair/test/vectors/poseidon-independent-implementation.test.ts`, and rewrote
the second file while it was open here, which surfaced as an edit failing
against content that had changed underneath. It also ran builds in the tree and
wrote a parallel report at `row-updates/wasm-verification.md`.

The branch guard did not trip, because the branch name stayed correct
throughout; what changed was the tree, not the checkout. The guard as written
detects a stolen worktree, not a shared one. Work continued after confirming the
writer had gone quiet, HEAD was stable, and no process was left running in the
tree.

Both agents observed the other. Its report records this one as "a fourth
worktree collision" and notes the reversed-input mutation in flight at the time,
which was control edit two above and was reverted to a byte-identical tree.

The findings are independent and they agree: reproducible artifact, verified
fixture, an independent implementation with no mismatch, no fallback, Chrome 144
green, packaging green. The two sets of control edits differ and do not overlap,
so between them the mutation coverage is wider than either alone. The one gap
this branch closes that the other did not, rejection provenance, is the one its
own table shows the pre-existing suites could not see.

Someone should decide whether two agents on one branch is intended. The
duplicated effort was largely wasted, and the two reports will need reconciling
into a single checklist row.

## Gates

At `0596fbb0`, with the tree clean:

| Command | Result |
| --- | --- |
| `npm run build && rm -rf node_modules/.vite && npm run test:unit` | 94 files, 1,769 passed, 1 skipped |
| `npm run check:static` | pass |
| `npm run check:packaging` | pass |
| `cargo test -p zolana-keypair` | pass, including `committed_vectors_match_current_rust` |
| `cargo run -p xtask --bin poseidon-parity -- --check` | verified |

Every TypeScript result was taken after a rebuild and with the vitest cache
cleared, since `@zolana/hasher` resolves to `dist/` and a stale build would
otherwise report the previous artifact's digests.
