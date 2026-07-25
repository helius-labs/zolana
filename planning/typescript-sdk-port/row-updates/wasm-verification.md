# Independent verification of the WebAssembly Poseidon

Branch `port/wasm-verify`, from the integration tip at `515a2fb4`. This is a
second pair of eyes on the work reported in
[hashers-b.md](hashers-b.md) and
[poseidon-wasm-and-packaging.md](../poseidon-wasm-and-packaging.md), written by
someone who did not build it. Nothing in those two documents was taken as true.

**Verdict: the hasher is sound and I would sign it off for consensus-critical
use.** No wrong digest was found anywhere: not against the Rust oracle, not
against an implementation that shares no code with it, and not in any of the
five environments the SDK claims. Two gaps were found in the *tests*, not in the
hasher, and both are now closed. Three claims in the builder's own documents do
not reproduce as written, and each of the three is wrong in the direction that
does not hurt.

## What would have to be true for this to be wrong, and what was done about it

### The artifact might not be the committed Rust

This is the gap the builder names as "the one piece of this arrangement still
owed": nothing proves `artifact.ts` was generated from the Rust in the tree, so
a stale artifact would ship silently.

Rebuilt it and compared. Twice, on `rustc 1.97.0`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cp sdk-libs/ts/hasher/src/artifact.ts /tmp/artifact-head.ts
node sdk-libs/ts/hasher/scripts/embed.mjs
cmp /tmp/artifact-head.ts sdk-libs/ts/hasher/src/artifact.ts   # identical
```

1,503,358 bytes, byte-identical both times. The build is reproducible and the
committed artifact is the committed Rust. This does not install the CI gate,
which is still owed, but it removes the doubt for this commit.

### The fixture might not be the Rust hasher

```bash
cargo run -q -p xtask --bin poseidon-parity -- --check
# verified sdk-libs/ts/vectors/poseidon-parity-v1.json
```

The fixture regenerates byte-identically from `zolana-hasher`, so it describes
the Rust in the tree today. It covers arity 1 through 12 with eight families
each, the order-sensitivity pairs at arity 2, and six rejections: no inputs,
thirteen inputs, 31 bytes, 33 bytes, a value equal to the modulus, and a value
above it.

### The fixture and the artifact might be wrong together

They share an origin. Both come from `zolana-hasher`, so a fault in
`zolana-hasher` would be invisible to a test that compares one against the
other, and the five hand-written copies that used to supply the second opinion
were deleted in `ab2e2863`.

One of them was recovered from `ab2e2863^` and used as an oracle. It builds its
round constants from the Grain LFSR through `@noble/curves` rather than reading
arkworks' tables, so it shares neither code nor data with the artifact.

| Corpus | Compared | Mismatches |
| --- | --- | --- |
| Field edges, arity 1 to 12 (zero, one, modulus-1, modulus-2, `1 << 253`, alternating, indexed) | 84 | 0 |
| Pseudorandom field elements, 250 per arity | 3,000 | 0 |
| Short inputs of 1, 2, 8, 16 and 31 bytes, at first, last, and all positions, every arity | 180 | 0 |
| Zero-length inputs, every arity | 12 | 0 |
| Order sensitivity at arity 2 | 4 | 0 |

3,280 comparisons, no mismatch. A reduced form of this is now committed at
`sdk-libs/ts/keypair/test/vectors/poseidon-independent-implementation.test.ts`.

### The tests might be unable to fail

Five mutations, each applied to the implementation, run against the committed
suites, then reverted.

| Mutation | Committed suites |
| --- | --- |
| Left-align short inputs instead of right-aligning | red, 5 failures |
| Drop the input-buffer zeroing | red, 4 failures |
| Raise the TypeScript arity ceiling to 13 | red, refuses to load |
| Swap the first two field elements inside the wasm | red, 87 failures |
| Lower the wasm ABI arity ceiling to 11 | red, refuses to load |

The last two required rebuilding the artifact, so they exercise the whole chain
from Rust to digest. The arity mutations fail at `initializePoseidon`, which is
the ceiling check in `instantiate()` doing its job: the TypeScript constant and
the ABI cannot drift apart without the suite refusing to start.

## Two things the committed suites do not catch

Both were found by mutating the implementation in ways the fixture cannot see.
Neither is a defect in the shipped hasher, which is correct on both counts.

**Short inputs are only ever pinned at index 0.** The wrapper writes input `i`
at `(i + 1) * 32 - length`. All four `shortInputs` entries in the fixture are
single-input, so at `i = 0` the expression reduces to `32 - length` and a wrong
offset for every other index is indistinguishable. Left-aligning every input
except the first passes the committed fixture replays in both `hasher` and
`keypair`, and produces a wrong digest for any short input at index 1 or above.
Callers do pass short inputs: `ciphertext_hash` chunks 16 bytes at a time.

**A digest could alias the module's output buffer.** `poseidon` ends in
`.slice()`. Removing it also passes the committed fixture replays, because each
assertion reads its digest before the next hash overwrites it. In a consumer
that holds two digests it would rewrite the first one from under them.

| Mutation | Pre-existing fixture replays | Suites added here |
| --- | --- | --- |
| Right-align only the first input | green | red |
| Return the output buffer instead of a copy | green | red |
| Stop clearing the input buffer | red | red |
| No-op control | green | green |

`sdk-libs/ts/hasher/test/shared-instance.test.ts` closes both, plus the state a
shared instance could carry between calls: a wide call reaching a narrow one, a
refused call disturbing the next, a mutated digest reaching back into the
module, and interleaved arities drifting.

## Node, both module systems

Tarballs built with `npm pack`, installed into a scratch project outside the
workspace, so what runs is the published shape rather than the source tree.

| | Node 20.20.2 | Node 22.22.3 |
| --- | --- | --- |
| `import` from an ESM entry point | loads | loads |
| `require` from a CommonJS entry point | loads | loads |

All four runs produce identical digests for arity 1 through 12, and each one
matches the `poseidon-counter-N` vector in the Rust fixture.
`poseidon([1, 2])` is `115cc0f5…17189a` in all four, which is the value the
builder reports. Calling `poseidon` before the initializer throws
`HasherWasmError` with code 2 in every combination.

All six packages that re-export the initializer were installed from tarballs
and checked to drive one singleton: initializing through `@zolana/wallet` alone
makes hashing work through `@zolana/interface`, `keypair`, `merkle-tree`,
`transaction`, and `client`.

## Browser

Chrome 144, page served over HTTP, bundled with esbuild for `platform: browser`
against the packed tarballs rather than the source tree.

| Check | Result |
| --- | --- |
| The 100 fixture vectors and the 4 short-input cases | 104 checked, 0 mismatches |
| The rejections | all refused, with Rust's codes: 7002 non-canonical, 7005 over 32 bytes, 1 arity |
| `poseidon` called before the initializer | `HasherWasmError`, code 2, names the missing call, returns in 0 ms |
| Eight concurrent initializers | 7 ms, one instantiation |
| 600 interleaved mixed-arity hashes | every round identical |
| `process`, `Buffer`, `globalThis.process` present | none |
| Time to the last assertion | 317 ms |

The uninitialized path is the one worth stating plainly, because it is the
hazard the loading design creates: importing the module without awaiting the
initializer produces a named refusal immediately. Not a wrong digest, not a
promise where bytes were expected, and not a hang.

`ownerPkFieldCompressed` in Chrome is
`2fc92c040a721823aaab37fd012cf5013d89f0ccd2b6c00de044b52eeaec5005`, which is the
`pk-field-even` entry in the Rust fixture. The browser agrees with Rust, not
merely with Node. Every cross-package digest is also byte-identical to the same
computation run in Node against the same tarballs.

A bundle of all five hashing packages, with the test page's own probes removed,
contains no `process`, `Buffer`, `require(`, `node:` specifier, `__dirname`, or
`__filename`. The only host reference is `globalThis.crypto`, which is a web API.

## Concurrency and repeat use

Eleven probes against the packed ESM build, all passing: a returned digest
survives 197 later hashes, the 198 digests are distinct and none share a buffer
with the module, mutating a returned digest does not reach the module, a wide call
leaves nothing for a narrow one, a rejected call leaves the next one correct, a
digest can be fed back in as an input, 500 mixed-arity hashes in sequence hold,
re-initializing twenty times mid-flight keeps the digest, and 32 racing
initializers all produce the same digest.

## Bundle reality

Each package bundled alone with esbuild, minified, gzipped at level 9, against
the packed tarballs.

| Bundle | Gzipped |
| --- | --- |
| `hasher` | 571.2 KB |
| `interface` | 577.5 KB |
| `merkle-tree` | 581.8 KB |
| `keypair` | 603.2 KB |
| `transaction` | 617.8 KB |
| all five in one application | **625.9 KB** |
| the five summed as if each carried its own copy | 2,951.5 KB |

The claim that settled the design decision holds. An application importing all
five pays 625.9 KB, which is 54.7 KB more than `hasher` alone; the base64
artifact literal appears exactly once in the combined bundle. Duplication would
cost 2.4 MB more.

## Claims that did not reproduce

None of these is a defect. All three are the builder's own documents being
behind the tree or overstating what was measured.

**`check:packaging` no longer fails.** Both documents record it failing at
`test:browser` on the `globalThis.process` leak in
`client/src/prover/client.ts`, and hashers-b.md treats that as an open blocker
owned by another branch. It was fixed in `f1f612d7` and is merged into the
integration tip. At `515a2fb4`, `npm run check:packaging` passes end to end,
including `test:browser` and `pack:check`. Every downstream claim the builder
could only make with the leak "stubbed out locally" is now directly true.

**The size table is about 1 KB optimistic per row, and the artifact figure is
13 KB.** The builder reports the artifact at 584.1 KB gzipped; measured here at
571.2 KB. Per-package rows agree to within 1 KB. The difference is compression
level, not arithmetic, and it does not change any conclusion.

**Two of the three Chrome digests in the first report cannot be checked.** The
`MerkleTree(4)` root `0b953780…40656d` and `ownerPkFieldCompressed`
`2088d0e6…80cc68` are reported without the inputs that produced them, so they
are unverifiable as stated rather than wrong. `poseidon([1, 1])` is given with
its input and reproduces exactly: `007af346…401e81`, matching `poseidon-ones-2`
in the fixture. The `ownerPkFieldCompressed` claim was re-derived here from the
fixture's own compressed key and matches Rust.

The builder's *correction* in the second pass does reproduce, and is worth
confirming because it contradicts the plan's stated premise. Chrome 144 compiles
the full 1,503,358-byte artifact synchronously on the main thread in 1.6 ms.
There is no 4 KB ceiling in the way. The plan's decisive constraint is not a
constraint, and the builder is right that the initializer is justified by
runtime uniformity instead.

## Two observations that belong to someone else

**The browser gate misses bracket-notation access.** Its regexes match
`globalThis.process` but not `globalThis["process"]`. A property name assembled
at the source level (`"proc" + "ess"`) is folded by the minifier into
`globalThis["process"]?.env?.…` and passes both the source scan and the bundle
scan. The direct forms are caught, including the optional-chaining shape that
slipped through the first time. This is a limit of a regex gate rather than a
leak that exists today; the stronger control is that the code was run in a
browser with no `process` defined.

**One transient build failure.** `npm run build` failed once inside
`npm run test:browser`, with `tsc` exiting 2 on `indexer-api` and printing no
diagnostic. It did not reproduce in nine subsequent runs, standalone or through
the same script. Recorded rather than diagnosed.

## Gates

`npm run build`, `npm run typecheck`, `npm run lint:packages`, and
`npm run test:unit` pass, at `6f85395c`. 1,762 tests, up from 1,656 at the base.
`npm run check:packaging` passes, which the builder's documents say it does not.

## A fourth worktree collision

A second agent is working in `zolana-ts-keypair` on `port/wasm-verify` at the
same time as this verification, which the branch was not expected to be shared
with. It fast-forwarded the branch onto `03584e8e` mid-run and committed
`0596fbb0`, adding `hasher/test/vectors/poseidon-rejection-parity.test.ts`.

At the time of writing it also has an uncommitted `elements[..count].reverse()`
in `sdk-libs/hasher-wasm/src/lib.rs` and a rebuilt `artifact.ts` beside it,
which is a mutation experiment in flight rather than a defect. HEAD's Rust is
clean, and the working tree in that state fails 3 tests, all of them in the
other agent's own new file. Those edits were left in place rather than reverted.

The consequence for this report is only that its gate evidence is timestamped:
the four gates were green at `6f85395c` with the tree holding this verification's
changes and nothing else. Every measurement above was taken before the collision
and none of them depends on the other agent's work.
