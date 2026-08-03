# Zolana PoC: browser proving, with on-screen benchmarks

A browser app that generates Zolana transfer proofs locally and reports its own
timings.

```
poc/core     shared: shapes, benchmark model, wasm prover transport, flow driver
poc/web      Vite + React. Local proving via gnark compiled to js/wasm. Works.
poc/native   Expo scaffold. Renders the benchmark model; proves nothing yet.
```

`poc/native` is a specification with a screen attached, not a working app. React
Native has no WebAssembly, so the SDK's Poseidon does not run there and neither
does proving -- both need a native module that has not been built. The screen says
so rather than failing opaquely. `poc/native/MOPRO.md` covers what that module has
to provide and why mopro's stock gnark API does not fit Zolana's key format.

## The finding that shaped this

**mopro cannot prove Zolana's circuits in a browser, and this is not a
configuration problem.** Its gnark adapter is declared
`#[cfg(not(target_arch = "wasm32"))]` (`cli/src/template/gnark/lib.rs:1`) because
`rust-gnark` binds Go gnark through cgo; mopro's web build runs
`wasm-pack --features wasm`, which enables only its circom, halo2, and noir
adapters. Zolana's circuits are gnark.

So the browser uses gnark's **own** `GOOS=js GOARCH=wasm` target. That was
verified before any UI was written:

| Check | Result |
| --- | --- |
| gnark v0.15.0 Groth16 compiles to `js/wasm` | yes |
| Setup + Prove + Verify actually run under a JS wasm host | yes — `acceleration=none`, 331-constraint MiMC circuit proved in 82 ms |
| Zolana's own proving packages compile to `js/wasm` | yes — `prover/transfer_eddsa_only`, `prover/common`, `prover/merge`, `prover/provingkeys` |
| Transfer proving-key sizes | 7.6–37.3 MB per shape, ~223 MB for all ten |

Key sizes are the reason this is viable at all: they are small enough to fetch
and hold in a browser. The forester's `batch_address-append_40_250.key` is 3.5 GB
and is deliberately not provable in the browser.

mopro is still the right tool on iOS/Android, where the cgo path works — that is
what `poc/native` uses. See `poc/native/MOPRO.md`, including the gap between
mopro's stock gnark API and Zolana's key/witness formats.

## How local proving is wired

`ProverClient` accepts an injectable `fetch`, and `cmd/prover-wasm`'s `prove`
mirrors `server.processProofSync` — same JSON in, same JSON out. So the whole
integration is a `fetch` that recognizes the prover URL and answers it from wasm.
No SDK changes. Everything else (indexer, Solana RPC) falls through.

The module runs in a Web Worker because Go's js/wasm runtime occupies the thread
it is instantiated on and `groth16.Prove` blocks for seconds.

## Running the web app

Two benchmarks with different requirements.

**Proving-key benchmark — no validator needed.** Fetches and deserializes each
shape's key in the wasm instance and reports the cold-start cost of local
proving.

```sh
just build-prover-wasm    # compile the wasm module + copy wasm_exec.js
just poc-keys             # link proving keys into poc/web/public/keys
just poc-web              # vite dev server
```

Then click **Benchmark proving keys**.

**Full shield → transfer → unshield — needs the stack.**

```sh
just poc-up               # validator + Photon + prover + pool tree
# export the VITE_* vars it prints, then:
just poc-web
```

Click **Run shield → transfer → unshield**. It sweeps note counts 1–5; each maps
to the shape its transfer leg lands on. Results stream into the table with
per-step timings, and **Export CSV** dumps them.

`poc-keys` needs the keys present locally (`just build-prover-server` fetches
them per `provingkeys/proving-keys.lock`).

## Running the mobile app

```sh
cd poc/native && npm install && npm run ios     # or: npm run android
```

Without the native module the app launches and reports remote-proving benchmarks
only. It cannot do local work, and the screen says so, because **Hermes has no
WebAssembly** — the SDK's Poseidon (`@lightprotocol/hasher.rs`) is a wasm module,
so on device it blocks every hashing operation, not just proving. The native
module therefore has to supply Poseidon *and* proving. `poc/native/MOPRO.md` has
the build steps and the required UniFFI surface.

## Verifying the wasm prover without a browser

A Go fatal error kills the wasm instance, so the page cannot report it, and the
SDK reduces any prover failure to `status: 500` with the body dropped. With the
localnet up, this captures a real `/prove` request and replays it through the
module in Node, printing the module's actual error or the proof:

```sh
ZOLANA_TREE=<tree> node poc/web/scripts/verify-wasm-prover.mjs
```

It is what caught the deadlock below.

### gnark's logger deadlocks js/wasm

`groth16.Prove` logs progress to stderr. Under js/wasm a write is an *async* JS
operation, and `prove` is called synchronously from a JS callback, so the event
loop cannot run the write's completion callback while Go is on the stack. The Go
runtime then sees every goroutine blocked and aborts:

```
fatal error: all goroutines are asleep - deadlock!
  goroutine 9 [chan receive]: syscall.fsCall(...) syscall.Write(...)
```

The constraint solver finishes first (`nbConstraints=54031 took=88ms`), so the
crash lands mid-proof and looks like a proving failure rather than an I/O one.
`gnarklogger.Disable()` in `cmd/prover-wasm` removes the only async syscall on the
proving path. Anything else added there that writes to stdout/stderr will
reintroduce this.

## Status

Verified locally:

- the wasm prover builds (17 MB) and its API works under a JS wasm host — filename-derived
  circuit types, branchable errors, instance survives bad input
- `poc/core` and `poc/web` typecheck and build (4.95 MB bundle; the bulk is the
  Poseidon hasher's inlined wasm)
- the justfile recipes parse

Measured against a localnet, replaying a real transfer request through the wasm
module:

| | |
| --- | --- |
| Proving key load, 15.6 MiB (2x3) | 3.9 s |
| `groth16.Prove`, 2x3, 54031 constraints | **3.5 s** |
| Key deserialization rate | ~260 ms/MiB, linear from 7.8 to 15.6 MiB |

Single-threaded throughout: Go's js/wasm has no thread support, so the core count
the browser reports is irrelevant. Cold start dominates and cannot be cached away
-- the key bytes persist in the Cache API, but the deserialized proving key lives
in wasm linear memory and dies with the instance.

Not yet exercised:

- the full shield -> transfer -> unshield sweep driven from the page (the proving
  step itself is verified above)
- per-shape proving times beyond 2x3
- the native module: `poc/native/MOPRO.md` specifies it; it is not built
