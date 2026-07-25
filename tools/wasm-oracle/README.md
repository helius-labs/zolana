# WASM differential oracle

The design is `planning/typescript-sdk-port/wasm-differential-oracle.md`. This
directory holds the first two packets it describes: W-07 for the Merkle
operations and W-03 for hashing and field encoding.

Canonical Rust compiles to WebAssembly and runs in the same process as the
TypeScript under test, so a property test can compare the two on generated
input rather than on a recorded vector.

## Layout

- `crate/` is the `wasm-bindgen` wrapper. It is its own Cargo workspace, so
  `cargo build` at the repository root does not see it and the published crates
  keep their current dependency set.
- `suite/` holds the `fast-check` suites, the comparison harness, and the
  report writer.
- `pkg/` and `report/` are build output and are not tracked.

## Running it

```bash
export PATH="$HOME/.cargo/bin:$PATH"
rustup target add wasm32-unknown-unknown
cd tools/wasm-oracle/crate && wasm-pack build --target nodejs --out-dir ../pkg --release
cd ../../.. && npx vitest run --config tools/wasm-oracle/suite/vitest.config.ts
node tools/wasm-oracle/suite/summarize.mjs
```

Build with `--release`. A `--dev` build overflows the WebAssembly stack inside
the unoptimized field arithmetic, and the failure surfaces as
`RuntimeError: memory access out of bounds` from `__wbindgen_free` rather than
as a stack error.

Nothing here runs from `npm run check`. The suite needs a Rust toolchain and a
WebAssembly build, and it reports divergences rather than gating on them, so it
stays on its own `vitest` config.

## What the wrapper may not do

The wrapper decodes hex and decimal strings and calls Rust. It does not pad
short input, truncate long input, flip byte order, or fill defaults. Anything it
normalizes is behavior the comparison can no longer see. `hash_field` takes
`&[u8; 32]`, so a 16-byte input has no Rust meaning and the wrapper reports a
rejection; padding to 32 bytes here would rebuild the TypeScript behavior under
test inside the reference and the comparison would agree for the wrong reason.

Widening a Rust signature to accept generated input is a judgment about what
Rust would have done. `crate/src/hashing.rs` and `crate/src/merkle.rs` record
each one at the function that makes it.

## Boundary encoding

Byte strings cross as lowercase hex with no prefix, integers as decimal strings,
and rejections as `{ code, details }`, matching the committed fixtures so a
counterexample transcribes into one without conversion. Integers stay strings
because a JSON number and a JavaScript `number` both lose precision above 2^53,
and the values under test reach `i64::MAX` and field elements near 2^254.
