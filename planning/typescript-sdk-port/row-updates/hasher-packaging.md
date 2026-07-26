# `@zolana/hasher`: the build compiles the Rust, and ships it as a file too

Closes the two consequences PW-2's 2026-07-26 correction drew out of Light's
published tarball. `@zolana/hasher` now compiles `program-libs/hasher` as part
of its build rather than reading a committed blob, and ships the compiled
artifact as a file beside the inlined one. Both landed; nothing was attempted
and abandoned.

The owner ruled against the queued CI step that would have rebuilt the artifact
and failed on a byte difference. That ruling is implemented rather than
supplemented: no gate was added. The residual holes the build cannot close are
named at the end, and none of them is the one a gate would have caught.

## What the build does now

`src/artifact.ts` was a 1.9 MB base64 module that only `npm run embed` ever
wrote, and nothing ran that. A change to the Rust Poseidon left the TypeScript
packages hashing to digests no verifier reproduces, which is precisely the
defect class the WebAssembly work exists to close, reintroduced by the
packaging.

The compile is now part of the build. `sdk-libs/ts/config/build.mjs` runs a
package's `scripts/build-hooks.mjs` when it has one: `beforeBuild` before `tsc`,
`afterBuild` on the finished `dist`. The hook lives in the build script rather
than in the package's `build` script on purpose, because the repository build
invokes `build.mjs` directly for every package, so a hook wired to the script
would have been skipped by exactly the build CI runs.

`@zolana/hasher`'s hook compiles `sdk-libs/hasher-wasm`, writes the inlined
module, and emits `dist/poseidon.wasm`. It does not compile every time.
`artifact.lock.json` records a hash over every input the compile reads together
with the `sha256` of what came out:

```json
{
  "sourceHash": "b077c8f0…",
  "artifactBytes": 1503358,
  "artifactSha256": "bb7fa1c0…"
}
```

The hashed inputs are `rust-toolchain.toml`, `.cargo/config.toml`, the root
`Cargo.toml`, `program-libs/hasher/{Cargo.toml,src/**.rs}`, and
`sdk-libs/hasher-wasm/{Cargo.toml,Cargo.lock,src/**.rs}`. The lockfile rather
than the workspace manifest is what pins the dependency versions, because the
wrapper crate is its own workspace. `.cargo/config.toml` is in the set because a
repository-wide `rustflags` would live there and would move the compiled bytes
without moving anything else.

The build compiles when either hash has moved, so the committed
`src/artifact.ts` is a cache under that key rather than a source. A hand-edited
or half-merged artifact fails the `artifactSha256` check and is recompiled over.

The lock and the artifact are written on different conditions, which matters
more than it looks: the lock is rewritten whenever the source hash moves, and
`src/artifact.ts` only when the bytes actually differ. An input change the
compiler ignores therefore costs one line of a small JSON file instead of a new
1.9 MB blob in git history.

### What it costs a developer

| Case | Cost |
| --- | --- |
| Rust unchanged, which is nearly every build | 12 ms, no toolchain |
| Rust changed, dependencies already built | 8.0 s |
| Rust changed, cold `target` | 16.0 s |
| Rust changed, no cargo on `PATH` | the build refuses, with instructions |

The 12 ms is hashing eleven files, verifying the cached artifact against the
lock, and writing `dist/poseidon.wasm`. `npm run build` for the whole workspace
takes 6.4 s, so the cache path is under a fifth of a percent of it, and a
contributor who never touches Rust never needs a `wasm32-unknown-unknown`
toolchain. That is the trade the design turns on: charging sixteen seconds and a
Rust install to every JavaScript build would have bought no additional
correctness, because the hash already tells us the previous artifact is the one
this Rust produces.

The refusal is deliberate rather than a fallback to the stale blob:

```
the Rust hasher changed since src/artifact.ts was generated, and cargo is not
on PATH. Install the toolchain rust-toolchain.toml names, add the
wasm32-unknown-unknown target, then commit the regenerated src/artifact.ts and
artifact.lock.json alongside the Rust: until they are committed, every build of
@zolana/hasher has to compile the crate itself.
```

## The slim variant

Shipped. Modelled on `@lightprotocol/hasher.rs@0.2.1`, which exports `.` at a
4.4 MB base64 build, `./slim` at 20 KB loading the artifact as a file, and the
raw `.wasm` under its own subpath. Ours is the same shape:

| Export | Reaches |
| --- | --- |
| `.` | the inlined build, still the default, unchanged for existing consumers |
| `./slim` | the same hasher, loading an artifact the caller resolved |
| `./poseidon.wasm` | the artifact itself, 1.43 MB |

What it saves, each entry point bundled alone with esbuild and minified:

| | Raw | Gzipped |
| --- | --- | --- |
| Inlined, `@zolana/hasher` | 1959.2 KB | 576.8 KB |
| Slim JavaScript | 1.9 KB | 0.9 KB |
| `poseidon.wasm` | 1468.1 KB | 493.3 KB |
| Slim total | 1470.0 KB | 494.2 KB |

489 KB less over the wire, 83 KB of it after compression, and the part that does
not show in either column: the slim consumer never puts 1.9 MB of base64 through
the JavaScript parser, and can stream the artifact into
`WebAssembly.instantiateStreaming` instead of decoding a string into a buffer
first.

The artifact is a parameter rather than something the module goes looking for,
and that is the PW-2 constraint rather than an omission. Locating a sibling file
needs a host: `fetch` refuses a `file:` URL in Node, `node:fs` is what the
browser gate excludes, and `import.meta.url` is not expressible in the CommonJS
half of a plain-`tsc` build. Light resolves `new URL(…, import.meta.url)` and
pays for it with a rollup shim whose CommonJS output contains
`require('u' + 'rl')`, spelled that way to hide it from bundlers, and our
browser gate would reject that string on sight. Only the consumer knows
which host facility it has, so `initializePoseidon` takes what they resolved:
a `BufferSource`, a `WebAssembly.Module`, a `Response`, or a URL to fetch.

```ts
import { initializePoseidon, poseidon } from "@zolana/hasher/slim";

// Node
await initializePoseidon(
  await readFile(createRequire(import.meta.url).resolve("@zolana/hasher/poseidon.wasm")),
);
// Browser
await initializePoseidon(fetch("/assets/poseidon.wasm"));
```

Both entry points share one instance through `src/core.ts`, so a graph holding
both compiles the module once and cannot end up with two hashers. That was the
first thing the tests had to be arranged around: `pack-check.mjs` runs the slim
consumer in its own process, because initializing the inlined build first would
have made the digest comparison assert nothing.

`./poseidon.wasm` is an asset rather than an entry point in
`config/packages.mjs`, and the export and pack checks were widened to understand
one. Listing it as an entry point would have had the browser check try to bundle
a WebAssembly file as JavaScript.

## The evidence

Measured, not asserted.

**The compile is reproducible.** A fresh `cargo build --release --target
wasm32-unknown-unknown` produced 1,503,358 bytes hashing to `bb7fa1c0…`, byte
for byte the artifact that was already committed. Without that, "recompile when
the sources move" would churn the blob on every machine.

**The forcing function fires.** With `hash_bytes_be` changed to `hash_bytes_le`
in `program-libs/hasher/src/poseidon.rs` and nothing else touched, `node
config/build.mjs hasher` recompiled unprompted and produced a different
artifact, 1,502,784 bytes hashing to `2a6df938…`, and the parity suites failed
107 of 118 assertions on the spot. Reverting the Rust and rebuilding restored
`bb7fa1c0…`
exactly, and `artifact.lock.json` came back byte-identical to its previous
content. Nobody ran an embed step in either direction.

**A missing toolchain refuses rather than falls back.** Running the build with
cargo off `PATH` while a recompile was owed raised the error above and exited
non-zero.

**Digest parity across all three paths.** `cargo run -p xtask --bin
poseidon-parity -- --check` verifies. The hasher's vector suites pass 118 of
118, and `test/slim.test.ts` re-runs every one of them through the file rather
than the base64, from a `Response` labelled `application/wasm` and again from
one labelled `application/octet-stream` so the buffered fallback is exercised
rather than described. `test/slim.test.ts` also asserts the shipped file's
length equals `POSEIDON_ARTIFACT_BYTES`, which ties the file to the base64, and
that the slim entry point bundles under 4 KB, which is the saving asserted
rather than claimed.

**Gates.** `npm run build`, `typecheck`, `lint`, `lint:packages`,
`format:check`, `test:unit` (1,814 passing and 1 skipped, six of them new in
`test/slim.test.ts`), `test:vectors`, and `check:packaging` end to end including `test:browser`
and `pack:check`. The browser gate stayed green with `./slim` added to the
bundled entry points, which is the check that the slim loader reaches no
Node-only global.

## What is not closed

**Three inputs the hash cannot see.** A `RUSTFLAGS` in the environment, a
`rustup override` in the working directory beating `rust-toolchain.toml`, and a
tampered registry cache all change the compiled bytes without changing the
source hash. None is reachable by a CI rebuild-and-compare either, since that
gate would run under the same three unknowns. The mitigation is the same one the
repository already relies on for `fixtures:check`: rustup resolves
`rust-toolchain.toml` from the crate directory, so the pinned compiler is the
default in every clone.

**The committed cache can lag its Rust.** A contributor may commit a change to
`program-libs/hasher` without the regenerated `src/artifact.ts`. Nothing shipped
is wrong when that happens, because the next build recompiles and produces the
correct artifact, which is the property the owner's ruling asked for. But the
blob in the tree is then a cache miss rather than a cache, and every later build pays
sixteen seconds until somebody commits it. This is the one place a gate would
have added something, and what it would add is tidiness rather than correctness.
It is deliberately not gated.

The visible consequence is that `typescript / static`, `suites`, and `packaging`
have no Rust toolchain, so a pull request that changes the Rust hasher without
regenerating the artifact turns those three jobs red on the refusal quoted
above. That is a true failure with an actionable message rather than a false
one, and installing Rust in those jobs would convert it into a green build over
a stale cache. Worth an owner decision, not taken here.

**`@zolana/hasher/slim` is not wired into the packages above it.**
`@zolana/interface`, `keypair`, `transaction`, `client`, `merkle-tree`, and
`wallet` all import `@zolana/hasher`, so they carry the inlined artifact and a
consumer reaching them cannot take the slim path. Giving them a slim variant
each means a second export tree per package and a decision about which one their
`browser` condition points at, which is a larger change than this batch and
interacts with the open question in PW-4 about whether `interface` should depend
on the artifact at all.

## A worktree collision

Recorded because the pattern keeps recurring, not because anything was lost.

`6b9c50fa`, "wip(hasher): build hooks and artifact lock, salvaged from a dropped
agent", is on `port/hasher-pkg` and was not made by the agent that wrote the
work in it. At 02:33:07, while `check:packaging` was running here, another
process committed this worktree's uncommitted files under that message; the
`git commit` intended for them a minute later found the tree already clean. The
commit contains exactly the three files this batch had changed and nothing else,
so the content is intact and the history is merely mislabelled. It was left
alone rather than reworded, since rewriting a commit another process created is
worse than an inaccurate message.

The topology rule holds, one tree and one branch and one agent, but a janitor
that commits orphaned work cannot tell a dropped agent's tree from a working
one, and this is the second failure mode in that family tonight.
