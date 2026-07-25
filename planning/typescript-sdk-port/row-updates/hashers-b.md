# Hasher, Merkle, and keypair rows

Branch `port/hashers-b`. One section per row, plus the Poseidon consolidation,
which is not a row.

## Poseidon on WebAssembly

Ruled at [authority-rulings.md](authority-rulings.md), "How TypeScript gets its
Poseidon": compile the Rust Poseidon and have the TypeScript packages call it.
Done, in `f6d3ad57` and `14425225`. The five hand-written copies are deleted.

### What was built

`sdk-libs/hasher-wasm` is a wrapper crate depending on `zolana-hasher`, built
for `wasm32-unknown-unknown`. `program-libs/` is untouched. The crate is its own
Cargo workspace, because the artifact wants `opt-level = "z"`, fat LTO, and
`panic = "abort"`, and a profile only takes effect at a workspace root.

`sdk-libs/ts/hasher` is the `@zolana/hasher` package. It exports `poseidon`,
`MAX_POSEIDON_INPUTS`, `POSEIDON_ARTIFACT_BYTES`, and `HasherWasmError`, and it
has no dependencies.

Two design choices, both forced by the packaging rather than chosen:

The interface is raw C over two fixed buffers, not `wasm-bindgen`. There is no
allocator, no import object, and no JavaScript glue to keep in step.

The artifact is inlined as base64 rather than shipped as a sibling `.wasm`.
These packages emit plain `tsc` output with no bundler step, so a sibling file
would have to be located at runtime, and both ways of doing that are closed:
`fetch` does not read a `file:` URL in Node, and `node:fs` is the thing the
browser gate exists to keep out. This is the same fork Light takes, and they
ship both sides of it: `@lightprotocol/hasher.rs@0.2.1` carries a 4.39 MB
"browser-fat" bundle with the wasm inlined and a 20.6 KB "browser-slim" one that
loads a separate asset.

The arity ceiling now lives in the ABI. The defect that prompted the ruling was
a partial-round table listing widths the verifier cannot reproduce; a module
that accepts at most twelve inputs cannot carry that table.

### Does it load in Node and in a browser

Yes, both, verified by running it rather than by bundling it.

Node: `sdk-libs/ts/hasher/test/vectors/poseidon-parity.test.ts` runs 111
assertions against the artifact under `npm run test:unit`.

Browser: the packages were bundled with esbuild for `platform: browser` and
loaded over HTTP in Chrome 144. `MerkleTree` with `poseidonHasher`,
`ownerPkFieldCompressed`, and `@zolana/keypair/hash` all produce digests
identical to the same code in Node:

| Value | Node and Chrome |
| --- | --- |
| `MerkleTree(4)` root after one leaf | `0b953780…40656d` |
| `ownerPkFieldCompressed` | `2088d0e6…80cc68` |
| `poseidon([1, 1])` | `007af346…401e81` |

Decode, compile, instantiate, and two hashes cost 64 ms to `DOMContentLoaded`.

**Superseded by "Poseidon packaging, second pass" below, on both counts.** The
module-scope `await` is gone, and the 4 KB claim this paragraph rests on did not
reproduce when tested directly. The paragraph stands as written because the
owner's ruling was made on it.

The `await` at module scope is load bearing, not stylistic. A browser refuses to
compile a WebAssembly buffer larger than 4 KB synchronously on the main thread,
and this one is 1.5 MB, so the alternative is an asynchronous `poseidon` and an
asynchronous everything above it: every UTXO hash, every tree operation, every
key derivation. Keeping the synchronous surface costs a top-level `await`, and
that propagates. `@zolana/keypair` imports the module, so `transaction`,
`client`, and `wallet` inherit it. **A consumer bundling any of these to
CommonJS cannot express the graph.** All the packages are already
`"type": "module"`, so this narrows a set that was already narrow, but it is the
single change most likely to reach a consumer.

### The gates

`npm run build`, `npm run typecheck`, `npm run lint:packages`, and
`npm run test:unit` all pass. 1380 tests, up from 1269.

`workspace-check.mjs exports`, `workspace-check.mjs dependencies`, and
`inventory-check.mjs` pass.

`browser-check.mjs` and `pack-check.mjs` fail, for a reason that predates this
work and is not Poseidon. `sdk-libs/ts/client/src/prover/client.ts:400`
`localProverUrl` reads `(globalThis as {process?: …}).process?.env`, written
across two lines in a shape the source-level regex does not match; the minifier
collapses it to `globalThis.process`, which the bundle-level regex does catch.
Both gates fail identically on `HEAD` without any of this work. With that one
expression stubbed out locally, both gates pass for the whole workspace,
including the wasm package: **the artifact clears the packaging gate.** The
`globalThis.process` failure recorded on `K13` is this, and it is neither the
gate's defect nor a freshly resolved dependency, as that row supposes.

### The costs, measured

Bundle. esbuild, `platform: browser`, minified, then gzipped. Before is
`14425225^`, after is `14425225`.

| Package | Before (gzip) | After (gzip) | Growth |
| --- | --- | --- | --- |
| `interface` | 11.9 KB | 592.1 KB | 49.7x |
| `merkle-tree` | 12.6 KB | 596.5 KB | 47.4x |
| `keypair` | 31.4 KB | 614.0 KB | 19.6x |
| `transaction` | 44.5 KB | 627.0 KB | 14.1x |
| `client` | 60.1 KB | 644.1 KB | 10.7x |

An application importing several pays the 584.8 KB once, not per package. The
raw artifact is 1,503,358 bytes; base64 makes it 2,004,480 characters of
JavaScript. 99.8% of the wasm is code, not data, so the weight is `ark-ff` and
`light-poseidon` themselves rather than a constant table that could be trimmed.
`wasm-opt` is not installed here and was not run; it would shave a fraction, not
an order of magnitude. For scale, Light's own artifact is larger:
`light_wasm_hasher_bg.wasm` is 1,990,996 bytes.

Speed, which runs the other way. Node 22, 2000 iterations after 200 warmup:

| | WebAssembly | Hand-written | |
| --- | --- | --- | --- |
| 2 inputs | 77.3 us | 185.6 us | 2.4x faster |
| 12 inputs | 650.8 us | 2809.1 us | 4.3x faster |

Build. Producing the artifact needs the Rust toolchain plus the
`wasm32-unknown-unknown` target, then `node sdk-libs/ts/hasher/scripts/embed.mjs`,
which builds the crate and writes `src/artifact.ts`. Neither is needed to build
or test the TypeScript, because `artifact.ts` is committed. That is the trade:
2.1 MB of generated source in the tree, against a Rust toolchain in the
TypeScript build path. It costs nothing measurable at the gates: `tsc`
over the whole workspace is 5.2 s, ESLint 6.2 s.

Versioning and publication. `@zolana/hasher` versions and publishes as an
ordinary package, because the artifact is inside its source rather than beside
it. There is no second registry, no postinstall download, and no way for the
`.wasm` to drift from the JavaScript that loads it. What is not yet in place is
a gate proving `artifact.ts` was generated from the committed Rust: today a
stale artifact would be caught only if the Rust hasher changed behaviour, which
the parity fixture would then catch. A build-and-compare step in CI would close
that, and it is the one piece of this arrangement still owed.

### Would I recommend it, having done it

For the defect it targets, yes, and the ruling is right about the mechanism.
Five implementations meant five chances to be wrong, and the one that was wrong
was the one nobody had tested. That class is gone: 199 lines deleted, one
artifact, and the arity ceiling now expressed where it cannot be restated
incorrectly.

The price is higher than the ruling's estimate, and the estimate deserves
correcting. 585 KB gzipped is not "larger bundles"; for `interface` and
`merkle-tree` it is a 50x increase, and it lands on every browser consumer
whether or not they hash. The top-level `await` is the part I would flag hardest,
because it is a compatibility constraint on consumers rather than a size number
they can amortise.

So I would recommend it with one change: **the packages should not all reach for
this module.** Which brings up the question the ruling set aside, and the
observation is worth recording, because measuring it changes the answer. Light's
production SDK barely hashes, and that is not only because its prover server and
indexer supply the hashing. It is also because `merkle-tree`, in our arrangement,
is a *client-side tree*: `@zolana/merkle-tree` builds and maintains trees in the
browser, and that is where the arity-1 and arity-2 hashing volume is. Poseidon
in `interface` is two functions, `pkFieldCompressed` and
`ownerPkFieldCompressed`, both arity 2 over a 33-byte key. Those two are the
worst trade in the table: 49.7x for two calls that the hand-written 20 lines
performed correctly and that no test ever caught being wrong.

The shape I would argue for is the one Light ships: the compiled module for the
packages that hash in volume and for every test helper, and the small hand-written
path retained where a package makes a couple of arity-2 calls, with both held to
the same generated fixture. That keeps the defect class closed where it can
actually recur, without putting 585 KB into a package whose whole job is
encoding. I did not build that split, because the ruling asked for one artifact
and the honest way to price the alternative was to build the thing that was
ruled and measure it. The measurement is above; the decision is the owner's.

## Poseidon packaging, second pass

The owner reversed on the loading arrangement after reading the measurement
above, and recorded it at [authority-rulings.md](../authority-rulings.md),
"Whether the WebAssembly Poseidon may use a module-scope await", with the work
sequenced in
[poseidon-wasm-and-packaging.md](../poseidon-wasm-and-packaging.md). Keep the
artifact, drop the module-scope `await` for an explicit initializer, add a
CommonJS build. Done in `21c9fe0b` and `7cb3e468`. The size table in PW-4 of the
plan is updated from the same measurement recorded below.

### The premise the plan rests on does not reproduce

The plan, the ruling, and my own report above all state that a browser refuses
to compile a WebAssembly buffer above 4 KB synchronously on the main thread, and
that this is what forced the module-scope `await`. **That limit did not
reproduce.** In Chrome 144, `new WebAssembly.Module` over the full 1,503,358-byte
artifact on the main thread returns in 1 to 2 ms, instantiates against an empty
import object, and hashes `poseidon([1, 2])` to `115cc0f5…17189a`, the same
digest the fixture carries. No `await` anywhere in the page.

The 4 KB ceiling was a V8 heuristic, and it is not in the way here. So a lazy
synchronous load on first hash would have removed the module-scope `await` with
no initializer, no API change, and no setup file in the suites.

I implemented the ruling anyway, for two reasons rather than out of deference.
One browser is not the web: Firefox and Safari were not testable here, and a
runtime that does enforce the limit would fail hard at first hash rather than at
a call the consumer can see and place. And the CommonJS build is the substantive
half of the ruling, which stands on the packaging argument alone and does not
need the sync-compile claim. But the plan's decisive constraint is not the
constraint. What actually justifies the initializer is that it is the arrangement
that behaves the same in every runtime, which is a weaker and more honest reason
than the one recorded.

### What the initializer costs, which the plan does not mention

`poseidon()` throwing when uninitialized means every existing caller has to
initialize, and 1,629 tests hash. They are served by one setup file,
`sdk-libs/ts/config/poseidon.setup.mjs`, registered in the six vitest configs.
The suites therefore do not exercise the uninitialized path;
`hasher/test/initialization.test.ts` resets the singleton and covers it directly,
including the double call, the concurrent call, and that a reload gives the same
digest.

The consumer-facing cost is the real one and it is a breaking change:
`initializePoseidon` is now exported from `interface`, `keypair`, `merkle-tree`,
`transaction`, `client`, and `wallet`, and an application that skips it gets a
`HasherWasmError` at the first hash. That is the named failure the ruling chose
over a silent wrong digest, and it is right, but it is an API break rather than
an internal change.

### The CommonJS build

`tsc` emits `dist/es`; esbuild transpiles that tree into `dist/cjs`, and a
`package.json` in each says which format it is. A second `tsc` invocation was
the obvious route and does not work cleanly: the compiler takes a file's module
format from the manifest beside the *sources*, which declares
`"type": "module"`, so a CommonJS emit needs either a second manifest next to
the sources or `verbatimModuleSyntax` turned off for that pass. Transpiling the
output that was already checked cannot disagree with what was checked.
`test-kit` reads `import.meta.url` and is never published, so it stays ESM only.

Declarations are emitted once and copied into both trees. The text is identical;
what differs is the manifest, which is what tells TypeScript to read the copy in
`dist/cjs` as CommonJS. The exports map therefore nests `types` inside each of
`import` and `require` rather than hoisting one `types` key, because a CommonJS
consumer resolving the ESM declarations is told about a default export that does
not exist. `pack:check` proves this rather than asserting it: it typechecks a
`.cts` consumer against the packed tarballs.

### Do both formats load and agree

Yes.

| | Loads | `poseidon([1, 2])` |
| --- | --- | --- |
| ESM, Node 20 and 22 | yes | `115cc0f5…17189a` |
| CommonJS, Node 20 and 22 | yes | `115cc0f5…17189a` |
| ESM, Chrome 144 | yes | `115cc0f5…17189a` |

`hasher/test/module-formats.test.ts` holds the two builds to each other across
all 100 fixture vectors and the four short-input cases, having loaded the
CommonJS build through `createRequire` and the ESM build through `import` in one
process. `pack:check` repeats the comparison against the published tarballs
under Node 20 and Node 22, so a packaging change that silently served one format
from the other's files would fail there.

### Sizes, re-measured

Each package bundled alone with esbuild and minified, then gzipped. "Before" is
the same measurement on `4de089cc`, the base of this branch, so it supersedes
the earlier table rather than restating it; those numbers were taken on an older
base and are 0.3 to 1.5 KB off.

| Package | Before | ESM after | CommonJS after | Growth, ESM |
| --- | --- | --- | --- | --- |
| `interface` | 11.6 KB | 578.4 KB | 581.4 KB | 49.7x |
| `merkle-tree` | 12.3 KB | 581.9 KB | 597.5 KB | 47.3x |
| `keypair` | 30.6 KB | 603.6 KB | 630.6 KB | 19.7x |
| `transaction` | 45.5 KB | 618.7 KB | 650.6 KB | 13.6x |
| `client` | 59.0 KB | 636.2 KB | 688.6 KB | 10.8x |

The CommonJS build does not change the arithmetic. It costs 3 KB to 52 KB
gzipped over the ESM build of the same package, which is the transpiler's
interop preamble per module rather than a second copy of the artifact, and a
consumer resolves one format or the other, never both. The artifact is 584.1 KB
gzipped and is paid once per application.

What does double is `dist` on disk, since both trees carry the inlined artifact
and a full set of declarations. That is a publishing cost.

### Gates

`build`, `typecheck`, `lint:packages`, and `test:unit` pass; 1,629 tests, up
from 1,619 at the base.

`check:packaging` passes through `test:inventory`, `test:exports`,
`test:dependencies`, and `api:check`, then fails at `test:browser` on
`globalThis.process`. That is the `client/src/prover/client.ts:435`
`localProverUrl` leak, now owned by another agent on `port/ci-green`; it is
theirs and this branch does not touch it. Everything downstream of it was run
with that one expression stubbed out locally and passes: the tarball checks for
all ten production packages, the CommonJS and ESM consumers under Node 20 and
22, the `.mts` and `.cts` type consumers, and the packed browser bundle. Per
package, `browser-check.mjs` passes for `hasher`, `interface`, `keypair`,
`merkle-tree`, `transaction`, and `wallet`, and fails only for `client`.

The browser check was not weakened; it is still the bundle-level scan that
caught the leak in the first place, and the control is that removing the leak is
what makes it pass.

## H05 `program-libs/hasher/src/hash_chain.rs`

Verdict: `PARITY`. Commit `9866663e`.

The row names two owners for `create_hash_chain_from_slice` and only
`transaction` was held to the generated vectors. `client/src/internal.ts`
`hashChain`, which folds the proof public inputs, was checked against itself.
`sdk-libs/ts/client/test/vectors/program-libs-hash-chain.test.ts` now replays
the same seven vectors, including empty, single, and the reversed pair.
Reversing the fold order in `client/src/internal.ts` fails six of them.

`create_two_inputs_hash_chain` stays unported, and the row's stated reason for
porting it does not survive checking. The row lists seven Rust callers on the
proof path. Reading those seven call sites, every one calls
`create_hash_chain_from_slice`, which is ported. `create_two_inputs_hash_chain`
has no caller in Rust outside the hasher's own tests and the generator that
wrote the fixture, so a TypeScript port would be unreachable code kept in step
with unreachable code.

Its four vectors were sitting in the fixture with no reader, so they are now
consumed as a record rather than as a comparison, the way `merkle-tree` records
`Sha256BE`. The assertions hold two things. The one-pair case is pinned because
it genuinely coincides with a two-element `hashChain`: the seed is
`H(first[0], second[0])`, which at one pair is indistinguishable. From two pairs
on, the function folds three inputs at a time, and no composition of `hashChain`
reproduces its output, whether concatenated, interleaved, or hashed as two
chains and combined. That is the substitution the similarity of the two names
invites, and it is now the thing a test refuses.

## H08 `program-libs/hasher/src/hash_to_field_size.rs`

Verdict: `NOT_APPLICABLE`, and the audit is right that the reasoning was weaker
than the disposition. It is stronger now, though it is still an enumeration
rather than a test, and that limit is worth stating plainly.

The file exports one trait and five functions. Enumerating every reference in
the repository outside the file and its own tests:

| Symbol | References |
| --- | --- |
| `hash_to_bn254_field_size_be` | `program-libs/batched-merkle-tree/src/merkle_tree.rs:229`, `merkle_tree_metadata.rs:105` |
| the trait and the other four functions | none |

The previous argument was "no SDK caller", which is the shape the audit called
weak, because absence is hard to establish. This one does not rest on absence.
The two references that exist are both in `zolana-batched-merkle-tree`, and no
crate under `sdk-libs/` depends on that crate: its dependents are `forester`,
`bench/tree`, and three other `program-libs` crates. So the function is not
merely uncalled from the SDK, it is unreachable from it, and a port would add a
TypeScript surface with no Rust surface facing it.

What this row still lacks is an artifact that fails if that changes. The
cheapest one is the shape H05 now uses: generate the vectors into
`program-libs-parity-v1.json` and consume them as a record, so a future porter
inherits the oracle and the disposition cannot rot unnoticed. That is not done
here.

## M01 `sdk-libs/merkle-tree/src/indexed.rs`

Verdict: `PARITY`. No new commit; the evidence was already in the tree and this
row's claim against it is out of date.

The row re-opens on `tools/wasm-oracle/report/w07-merkle.json`, which recorded
Rust returning `ok` at the sentinel where TypeScript returns
`INDEXED_MERKLE_TREE_INVALID_VALUE`, and the owner ruled Rust the defective side
and required its correction to land first. That correction has landed.
`sdk-libs/merkle-tree/src/indexed.rs:142-150` is `check_below_highest_value`,
and both `append` (line 154) and `get_non_inclusion_proof` (line 177) call it as
their first statement, returning `ValueOutsideIndexedRange`. The guard runs
before any tree state is read, so it does not depend on the height or the
element count the report probed. The instruction not to relax the TypeScript
guard was right and is satisfied: TypeScript is unchanged, Rust is tightened,
and the two refuse the same value.

The evidence is a generated oracle rather than a reading.
`xtask/src/bin/merkle-semantics.rs` writes
`sdk-libs/ts/vectors/merkle-semantics-v1.json` by driving the Rust tree and
recording each step's outcome and state.
`merkle-tree/test/vectors/merkle-semantics.test.ts` replays it against
`IndexedMerkleTree`, comparing the root, the element count, the sentinel, and
the error code of each rejection through a table that fails on an unmapped Rust
variant rather than skipping it.

Two things were checked rather than assumed. Regenerating the fixture from
current Rust produces a byte-identical file, so it describes the Rust in the
tree today. And relaxing the TypeScript guard from `>=` to `>`, which is exactly
the change the row warns against, fails both indexed scenarios.

The row's two concerns are its two scenarios:
`sentinel-closes-the-indexed-range` covers the sentinel being neither insertable
nor provable, and `rejected-indexed-appends-leave-the-tree-provable` covers a
failed insert leaving the tree at the same root and still able to prove
non-inclusion.

## M02 `sdk-libs/merkle-tree/src/lib.rs`

Verdict: `PARITY`. `BLOCKED` was recorded because the row had never held a
verdict and the relayed evidence had not been rerun. It has been rerun.

The same oracle covers this row. `treeSnapshot` compares seven readings after
every step: root, next index, leaf count, root-history length, sequence number,
`historyRootIndex`, and `historyRootIndexV2`, with a rejected accessor compared
by error code rather than skipped.

`get_next_index` and the offset. `history-offset-does-not-shift-next-index`
builds a height-3 tree with `rootHistoryStartOffset: 2` and
`rootHistoryArrayLength: 3`, then appends, updates, and inserts. The next index
counts leaves and ignores the offset, while `historyRootIndex` errs with
`RootHistoryStartOffsetAboveIndex { offset: 2, next_index: 0 }` until the offset
is passed.

`get_history_root_index_v2`. It is not always zero, and the fixture shows why
the question arises: it advances with the root-update count rather than the leaf
count, so it reads `0, 0, 1, ...` where `historyRootIndex` reads
`err, err, 0, 1`. The two disagree by construction, which is the reason for
having both. Adding one to the TypeScript accessor fails two scenarios.

## K11 to K14 `sdk-libs/keypair` traits and surface

No verdict change. Each is short of `PARITY` for a reason that is someone else's
to decide or someone else's to change. One of the blockers is now identified,
which is the only new thing here.

`K11`. What remains is that `transaction/src/wallet/sync.ts`,
`transaction/src/serialization/codecs.ts`, and `wallet/src/sync.ts` bind to the
concrete `ShieldedKeypair` rather than `ViewingKeyLike`, so a backend that
typechecks still cannot be passed. Those files belong to the transaction and
wallet rows, with parallel owners.

`K12`. Rust's `nullifier_key()` returns secret material and TypeScript's
interface offers only `nullifierPublicKey()`. TypeScript is the safer surface;
which side moves is a protocol-owner call.

`K13`. The row supposes the packed-package failure is "a defect in the
packed-artifact gate or a freshly resolved dependency". It is neither, and it is
one expression. `sdk-libs/ts/client/src/prover/client.ts:400` `localProverUrl`
reads `(globalThis as { process?: ... }).process?.env?.["ZOLANA_PROVER_URL"]`,
split across two lines in a form the source-level regex in `browser-check.mjs`
does not match. esbuild's minifier collapses it to `globalThis.process`, which
the bundle-level regex in both `browser-check.mjs` and `pack-check.mjs` does
match. Stubbing that one expression out locally makes both gates pass for the
whole workspace, which is how the attribution was established rather than
argued. Every package fails together because the consumer bundle pulls in
`@zolana/client`, which is why it looks cross-cutting.

The fix is not to disguise the expression further. It is to stop reading the
environment inside the SDK: `ProverClient.local()` should take its URL from the
caller and the test harness should pass `process.env.ZOLANA_PROVER_URL`. That is
a public change to `@zolana/client` and belongs to the client row.

`K14`. Blocked on `K13` for the tarball and consumer allowlists, and on the
stale metadata in `inventory-keypair.md` that `K01` already describes.
