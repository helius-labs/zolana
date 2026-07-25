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
chains and combined. That is the substitution the similarity of the two names invites, and
it is now the thing a test refuses.
