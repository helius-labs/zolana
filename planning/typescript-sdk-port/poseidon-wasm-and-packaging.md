# Poseidon through WebAssembly, without top-level await

**Keep the compiled Rust Poseidon. Replace the module-scope `await` with an explicit one-time async initializer, and add a CommonJS build alongside the ESM one. This reverses a position taken three hours earlier, and the reversal is the point of this document.**

Owner-ruled 2026-07-25. Implementation is scoped, sequenced, and has acceptance criteria at the end. A worker should be able to execute this without asking anything.

## How the decision arrived here, because the sequence matters

Read this section before the task list. Two of the three positions taken tonight were wrong, and knowing why keeps a worker from re-deriving the wrong one.

**First position: consolidate five TypeScript Poseidon copies into one TypeScript copy.** The port had grown five hand-written implementations, in `keypair`, `merkle-tree`, `transaction`, `client`, and the client prover. The duplication was not tidiness. It was the mechanism by which a fix fails to land, and it had already fired: `client/src/internal.ts:26` carried partial-round counts for widths 14 through 17 when the Poseidon syscall accepts at most twelve arguments, so a thirteen-input call returned a digest no verifier can reproduce. A wrong answer shaped like a right one. It was the copy with no parity suite, which is why it was the copy that was wrong.

**Second position: compile the Rust Poseidon to WebAssembly instead.** The owner chose this over the TypeScript consolidation, on the reasoning that one compiled artifact removes the class of defect rather than testing for it, and that Light Protocol had already taken that route. The work was done and measured rather than estimated, which is what produced the third position.

**What measuring found.** It works: 111 fixture assertions in Node, and in Chrome 144 the `MerkleTree` root, `ownerPkFieldCompressed`, and `@zolana/keypair/hash` digests are byte-identical to Node at 64 ms to `DOMContentLoaded`. Hashing runs 2.4x faster at arity 2 and 4.3x at arity 12, and 199 lines of duplicated implementation are gone with the arity ceiling now living in the ABI where it cannot be restated wrongly.

The price was higher than the estimate the ruling rested on. Minified and gzipped: `interface` 11.9 KB to 592.1 KB, `merkle-tree` 12.6 to 596.5, `keypair` 31.4 to 614.0, `transaction` 44.5 to 627.0, `client` 60.1 to 644.1. An application importing several pays the 585 KB once rather than per package. 99.8% of the artifact is code rather than a constant table, so trimming cannot change the order of magnitude, and Light's own artifact is larger than ours.

**The constraint that actually decided it, and the mistake in judging it.** Browsers refuse to compile a WebAssembly buffer above 4 KB synchronously on the main thread. Ours is 1.5 MB. Keeping `poseidon()` synchronous therefore forced an `await` at module scope in `@zolana/keypair`, inherited by `transaction`, `client`, and `wallet`. A consumer bundling any of those to a CommonJS target cannot represent that graph.

The coordinator first called this decisive, then reversed and called it weak, on the ground that the ten packages are already `"type": "module"` with no `require` condition, so CommonJS consumers were not being served anyway. That second reading was wrong, and checking Light is what showed it.

**What Light Protocol settles.** Two questions, both answered by reading its packaging rather than by reasoning about ours.

Does CommonJS still matter? Light ships four build variants: `dist/cjs/node`, `dist/cjs/browser`, `dist/es/browser`, and the ESM node path, with `main` pointing at `dist/cjs/node/index.cjs` and explicit `require` conditions throughout `js/stateless.js/package.json`, `js/compressed-token/package.json`, and `js/token-interface/package.json`. A shipped SDK with real users in this exact ecosystem maintains four targets rather than drop CommonJS. Our packages are ESM-only because nobody decided otherwise, not because the ecosystem moved on.

Can WebAssembly and CommonJS coexist? Yes, and Light shows the technique. It keeps the hasher out of module scope. Functions take it as an argument: `lightWasm: LightWasm` at `js/stateless.js/src/test-helpers/test-rpc/test-rpc.ts:93` and `:146`, and at `js/stateless.js/src/rpc.ts:495` and `:524`. The consumer constructs it once, asynchronously, and passes it down. No module-scope await, so the CommonJS build is expressible.

**Why we adapt rather than copy Light here.** Light can pass a parameter because its production code barely hashes; the hasher appears in test helpers plus a single hash chain in `rpc.ts`. Ours hashes across five packages on production paths, so threading an argument through each call site would touch far more code and change many public signatures. A module-level singleton with an explicit initializer gets the same property, no module-scope await, while leaving call sites as they are.

## The decision

1. Keep the compiled Rust Poseidon. Do not revert to a hand-written implementation, and do not split the two approaches across packages: a second implementation reopens the defect class this work exists to close.
2. Remove the top-level `await`. Replace it with an explicit asynchronous initializer, called once by the consumer, after which `poseidon()` stays synchronous.
3. Add a CommonJS build next to the ESM build, for Node and for browser targets, matching what Light ships.
4. Accept the 585 KB. It is paid once per application and this SDK already ships proof machinery.

Calling `poseidon()` before initialization must throw a named, specific error. A clear failure is the acceptable cost of this design; returning a wrong digest or silently awaiting is not.

## Work packets

Sequenced. Each lands as its own commit with the four gates green.

### PW-1. Replace the module-scope await with an initializer

Current state is on branch `port/hashers-b`, five commits, with `@zolana/keypair` holding the await and `transaction`, `client`, and `wallet` inheriting it.

Deliver a singleton module owning the compiled artifact, exposing an async initializer that is safe to call more than once and concurrently, a synchronous `poseidon()` that throws a named error when uninitialized, and a way for tests to reset it. Remove the module-scope `await` from `keypair`, `transaction`, `client`, and `wallet`. Export the initializer from each package's public surface so a consumer reaching only `@zolana/client` can still initialize.

Node has no such restriction on synchronous compilation, so the initializer may resolve immediately there. Do not let that difference produce two code paths with different behaviour; one path, awaited in both runtimes.

### PW-2. Add the CommonJS build

Model it on `js/stateless.js/package.json` rather than inventing a layout. Produce `dist/cjs` and `dist/es`, with `main`, `module`, `types`, and an `exports` map carrying `require` and `import` conditions for each subpath a package already exports. Keep the existing `browser` condition working.

The compiled artifact is currently inlined as base64, because these packages produce plain `tsc` output and neither way of loading a sibling `.wasm` file is open: `fetch` will not read a `file:` URL in Node, and `node:fs` is what the browser gate exists to exclude.

**Corrected 2026-07-26.** This paragraph used to end "Light takes the same fork", and that reading was too narrow. Unpacking `@lightprotocol/hasher.rs@0.2.1` shows Light shipping the raw `dist/light_wasm_hasher_bg.wasm` (1.99 MB) and a SIMD variant (1.28 MB) beside two browser builds: a fat one that inlines base64 into 4.4 MB of JavaScript and is the default, and a slim one at 20 KB that loads the artifact as a file. So Light does inline, but as one variant among several inside a separately versioned package whose build compiles the Rust.

Two consequences the original reading missed. Light's packaging makes a stale artifact impossible rather than detectable, because the package cannot be built without compiling the Rust it wraps, whereas `@zolana/hasher` carries a committed `src/artifact.ts` that no build step regenerates. And the 585 KB accepted in point 4 below is avoidable for consumers who can load a file, which is what Light's slim build is for.

Each exported subpath needs the treatment, not just the package root. `@zolana/keypair` alone exports `./merge` and others.

### PW-3. Prove both formats load

A test that requires the CommonJS build from CommonJS and imports the ESM build from ESM, and asserts both produce identical digests for the same input after initialization. Extend `check:packaging` so a missing or broken CommonJS entry point fails the gate. Keep the browser check that caught `globalThis.process`; do not weaken it to a source-level scan.

### PW-4. Record the cost

Re-measure the gzipped size per package for both formats and update this document. If the CommonJS build changes the arithmetic materially, say so plainly rather than leaving the earlier table standing.

**Measured 2026-07-26**, on `port/hashers-b` at the integration tip, each package bundled alone with esbuild and minified. The "before" column is the same measurement taken on the base commit with the artifact absent, so it supersedes the estimate in the history section above rather than restating it.

| Package | Before, gzipped | ESM after | CommonJS after | Growth, ESM |
| --- | --- | --- | --- | --- |
| `interface` | 11.6 KB | 578.4 KB | 581.4 KB | 49.7x |
| `merkle-tree` | 12.3 KB | 581.9 KB | 597.5 KB | 47.3x |
| `keypair` | 30.6 KB | 603.6 KB | 630.6 KB | 19.7x |
| `transaction` | 45.5 KB | 618.7 KB | 650.6 KB | 13.6x |
| `client` | 59.0 KB | 636.2 KB | 688.6 KB | 10.8x |

The CommonJS build does not change the arithmetic. It costs between 3 KB and 52 KB gzipped over the ESM build of the same package, which is the transpiler's interop preamble per module and not a second copy of the artifact; the artifact itself is 584.1 KB gzipped and is paid once either way. Only one format reaches a given consumer.

The `dist` directory on disk roughly doubles, since both trees carry the inlined artifact and a full set of declarations. That is a publishing cost, not a consumer one.

## What not to do

Do not weaken a gate to pass. Do not reintroduce a hand-written Poseidon anywhere, including as a fallback for environments where the artifact fails to load: a fallback that produces digests by a second code path is the defect class returning by the back door. Do not make `poseidon()` async, since that pushes an await into each hashing call site across the five packages. Do not edit `programs/**`, `program-libs/**`, `prover/**`, or `docs/spec.md`; the Rust Poseidon is compiled through a thin wrapper crate that depends on it, and that wrapper is the only new Rust.

## Acceptance

- No module-scope `await` remains in any shipped package.
- `poseidon()` throws a named error when called before initialization, and a test asserts that.
- Each package resolves under `require` and under `import`, and a test proves both give the same digests.
- `npm run build`, `npm run typecheck`, `npm run lint:packages`, `npm run test:unit`, and `npm run check:packaging` pass.
- The browser check still fails when a Node-only global reaches a bundle. Verify by control edit: reintroduce one, watch the gate fail, revert it.
- The recorded size table matches what the build now produces.

## Open, and not blocking

Whether `@zolana/interface` should depend on the artifact. It pays the largest relative cost, 49.7x, for two arity-2 calls, and standalone use of it for instruction building without any cryptography is plausible. Resolving this by giving `interface` its own hand-written copy is the one answer ruled out. Removing its need to hash, or accepting the cost, are both open. Do not resolve this inside the packets above.
