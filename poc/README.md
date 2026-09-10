# Zolana PoC: browser proving, with on-screen benchmarks

A browser app that generates and verifies Zolana transfer proofs locally with
Mopro's threaded Rust arithmetic kernel and Zolana's gnark witness builder.
This branch starts from PR #187 (`17a420f4a92bfd894b34661f2b5842f6b2137289`).

The Mopro prover source is in
[`sergeytimoshin/mopro`, branch `feat/gnark-web`](https://github.com/sergeytimoshin/mopro/tree/feat/gnark-web).
Follow that branch's
[gnark web setup](https://github.com/sergeytimoshin/mopro/blob/feat/gnark-web/docs/docs/setup/web-wasm-setup.md#gnark-groth16-bn254)
to produce `MoproWasmBindings`. Until the web build helper is released, install
the CLI from that checkout and explicitly patch the generated app's `mopro-ffi`
dependency to the same local checkout, as shown in the setup instructions.
The CLI leaves generated apps on the standard crates.io dependency.
This demo adapts the Go bridge to
Zolana's gnark 0.15 keys and reuses the built Rust kernel.

```
poc/core     shared: shapes, benchmark model, wasm prover transport, flow driver
poc/web      Vite + React. Local proving via Mopro + gnark compiled to js/wasm.
poc/native   Expo scaffold. Renders the benchmark model; proves nothing yet.
```

`poc/native` is a specification with a screen attached, not a working app. React
Native has no WebAssembly, so the SDK's Poseidon does not run there and neither
does proving -- both need a native module that has not been built. The screen says
so rather than failing opaquely. `poc/native/MOPRO.md` covers what that module has
to provide and why mopro's stock gnark API does not fit Zolana's key format.

## What changed from PR #187

The original PR used Go's single-threaded WASM prover because Mopro's cgo gnark
adapter could not run in a browser. The new Mopro web prover supplies a Rust
WASM kernel for FFTs and multi-scalar multiplication, using a Rayon worker pool.
Zolana's Go module still decodes its combined keys, builds the witness, assembles
the proof and verifies it. Its existing JSON protocol and pinned keys are retained.

The baseline PR established:

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

The Go module runs in a Web Worker and calls the Mopro kernel in that worker.
Mopro's arithmetic pool uses additional workers and requires cross-origin
isolation (COOP/COEP headers). The Vite server supplies these headers.
Only one circuit shape stays deserialized at a time to bound memory use;
downloaded key bytes remain cached and are checked against the pinned digest.
Every generated proof is locally verified before the SDK receives it.
The injected fetch honors request cancellation and deadlines. Cancelling queued
work leaves active proving alone; cancelling active work terminates the runtime
and rejects its outstanding requests. A later request starts a fresh worker and
reloads its key. Worker failures use the same cleanup and restart path.

## Running the web app

**Local proof playground — no validator needed.** It replays a local test
transfer request with 2 inputs, 3 outputs and 54,031 constraints. Prepare a Mopro
web build (the directory containing `gnark/accelerator/`), this checkout's pinned
proving keys, and a captured local test request. Generated binaries, keys, request
fixtures and `.env.local` are ignored by git.

```sh
npm ci
npm run build:ts
just build-prover-wasm
node poc/web/scripts/stage-mopro.mjs \
  /path/to/MoproWasmBindings \
  /path/to/proving-keys \
  /path/to/local-test-transfer-2x3.json
npm run poc:dev
```

Open **http://127.0.0.1:5178/** and click **Generate & verify proof**, or
**Benchmark 5 proofs** for a median. The sample stays local; this does not submit
a transaction. Key preparation is measured separately from proving.

**Proving threads** defaults to **Automatic**: use the CPU thread count reported
by `navigator.hardwareConcurrency`, capped at 18, or 4 when unavailable. This is
a starting configuration, not an autotuning benchmark. Browsers can report fewer
threads than the machine has. Select **Custom thread count** to experiment, or
**Original Go prover** to compare the original single-threaded implementation.
Changing modes or counts clears the prover and its deserialized key.

The staging script accepts an unpacked Mopro npm package as well as a bindings
directory. It validates supplied keys against this checkout's lockfile before
copying them; the 2x3 key is required, other transfer and merge keys are optional.
The sample must be a valid local test request for these keys. The existing
`verify-wasm-prover.mjs` script can capture such a request from a localnet.

Additional tools are under **Localnet transfers, key benchmarks & connection settings**.

**Proving-key benchmark — no validator needed.** Fetches and deserializes each
shape's key in the wasm instance and reports the cold-start cost of local
proving.

```sh
just build-prover-wasm    # compile the wasm module + copy wasm_exec.js
just poc-keys             # link proving keys into poc/web/public/keys
npm run poc:dev            # requires the Mopro kernel staged above
```

Then click **Benchmark proving keys**.

**Full shield → transfer → unshield — needs the stack.**

```sh
just poc-up               # validator + Photon + prover, protocol accounts preloaded
just poc-web              # reads the same ports the stack bound
```

Click **Run shield → transfer → unshield**. It sweeps note counts 1–5; each maps
to the shape its transfer leg lands on. Each transfer spends enough to require
all of that run's equal notes and keeps half a note for the withdrawal. The table
labels the actual transfer shape observed in the prover request, including padding.
Results stream into the table with
per-step timings, and **Export CSV** dumps them.

`poc-keys` needs the keys present locally (`just build-prover-server` fetches
them per `provingkeys/proving-keys.lock`).

## Deployment baseline

This branch is configured and tested locally. PR #187's Fly image does not yet
stage the new Mopro kernel or local sample; those artifacts must be added to its
build before deploying this version. No hosted service was changed.

```sh
just poc-deploy           # fly deploy, app and region in poc/web/fly.toml
```

The image builds the wasm prover and the page, and nginx proxies `/keys/` to
the CloudFront folder the lockfile pins, so the keys stay same-origin without
shipping them in the image, and `/devnet/indexer` and `/devnet/prover` to the
devnet services, which speak plaintext HTTP an HTTPS page cannot call. The hosted
page opens on the devnet preset. The three service URLs are editable and persist
in the browser, so a tester points the flow at any stack they can reach. A
non-loopback indexer or prover must be HTTPS, the SDK refuses plaintext otherwise.

The flow pays from a funding wallet the page generates and keeps in browser
storage. On a localnet it airdrops to itself. On devnet, send SOL to the address
the page shows. Devnet currently runs the program from before the nullifier tree
change, so the flow stops at the missing state tree until devnet is redeployed.

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
node poc/web/scripts/verify-wasm-prover.mjs
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

## Validation and measurements

With the Vite server running:

```sh
npm run poc:typecheck
npm run poc:build
# Optional CHROME_BIN selects a Chromium browser, e.g. Brave.
npm run test:browser --workspace @zolana/poc-web
cd prover/server
MOPRO_BROWSER_PROOFS=../../target/mopro-browser-ui/proofs.json \
  go test ./cmd/prover-wasm -count=1
```

The browser test exercises automatic and custom thread counts, the original Go
prover, five-proof benchmarking, invalid-witness rejection and recovery, and the
mobile layout. It saves screenshots and proofs under `target/mopro-browser-ui/`.
The Go test independently verifies those browser proofs using native gnark.

Local Brave measurements on the same 2x3 sample (September 10, 2026):

| Configuration | Proving time | Key preparation |
| --- | ---: | ---: |
| Mopro, 18 custom threads | 232.1 ms median of 5 | 3.96 s |
| Mopro, automatic (browser reported 6) | 408.4 ms median of 5 | 4.05 s |
| Mopro, 2 custom threads | 994.0 ms, one proof | 4.02 s |
| Original Go prover | 3,437.9 ms, one proof | 3.95 s |

Browser verification took approximately 5–7 ms. These are local sample
measurements, not a comparison with native proving speed. Key bytes persist in
the Cache API, but the prepared key is rebuilt when the worker or shape changes.

### Comparing browsers

Run each browser sequentially so their worker pools do not compete for CPU:

```sh
node poc/web/scripts/benchmark-browsers.mjs brave 18,6,1
node poc/web/scripts/benchmark-browsers.mjs firefox 18,6,1
# Optional diagnostic timings around the shipped Rust kernel's JS methods:
node poc/web/scripts/benchmark-browsers.mjs brave 18,12 profile
node poc/web/scripts/benchmark-browsers.mjs firefox 18,12 profile
```

These use separate headless profiles and save raw samples in
`target/mopro-browser-comparison/`. Each configuration discards three warm-up
proofs, measures 15 proofs and verifies every proof. `CHROME_BIN` and
`FIREFOX_BIN` override the default macOS browser paths. Selenium can download
matching drivers on first use. Key preparation and verification are excluded
from the reported proving time.

On the same Mac and 2x3 sample, Brave/Chromium 152 and Firefox 155 measured:

| Workers | Brave median | Firefox median |
| ---: | ---: | ---: |
| 1 | 1,860.5 ms | 2,034.1 ms |
| 6 | 403.2 ms | 464.0 ms |
| 18 | 230.4 ms | 401.3 ms |

The diagnostic run at 18 workers measured 142.7 ms inside the Rust kernel in
Brave and 284.2 ms in Firefox. The remaining Go/witness/bridge/assembly work was
approximately 87.4 and 109.8 ms respectively. This sample retained the Go solver.
Separate phase medians need not add up to the total median.

Reducing Firefox to 12 workers improved the diagnostic run's total median from
396.2 to 325.3 ms; Brave was faster at 18 (229.7 ms) than 12 (272.1 ms). This
points to poorer scaling of the threaded arithmetic path in Firefox for this
workload. It does not isolate the underlying compiler, synchronization or
scheduler behavior. The Automatic setting still uses the reported CPU count;
it does not perform this calibration.

Not yet exercised:

- the full shield -> transfer -> unshield sweep driven from the page (the proving
  step itself is verified above)
- per-shape proving times beyond 2x3
- the native module: `poc/native/MOPRO.md` specifies it; it is not built

## Regression checks

```sh
just poc-check
```

`npm run poc:test` runs the core regressions without building Go Wasm and is also
part of TypeScript CI.

The core tests cover worker recovery, request cancellation, actual request-shape
reporting, and selection of every requested note count with the SDK selector.
