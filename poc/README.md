# Zolana PoC: browser proving, with on-screen benchmarks

A browser app that generates and verifies Zolana transfer proofs locally with
Mopro's threaded Rust arithmetic kernel and Zolana's gnark witness builder.
This branch starts from PR #187 (`17a420f4a92bfd894b34661f2b5842f6b2137289`).

The Mopro prover source is in
[`sergeytimoshin/mopro`, branch `feat/gnark-web-arkworks`](https://github.com/sergeytimoshin/mopro/tree/feat/gnark-web-arkworks).
Follow that branch's
[gnark web setup](https://github.com/sergeytimoshin/mopro/blob/feat/gnark-web-arkworks/docs/docs/setup/web-wasm-setup.md#gnark-groth16-bn254)
to produce `MoproWasmBindings`. Until the web build helper is released, install
the CLI from that checkout and explicitly patch the generated app's `mopro-ffi`
dependency to the same local checkout, as shown in the setup instructions.
The CLI leaves generated apps on the standard crates.io dependency.
This demo needs the experimental kernel. Before building the Mopro web bindings,
add this to the generated app's root `Cargo.toml`:

```toml
[package.metadata.mopro.gnark]
experimental-accelerator = true
```

Default Mopro builds omit the gnark accelerator.
This demo adapts the Go bridge to
Zolana's gnark 0.15 keys and reuses the built Rust kernel. Witness solving stays
in Go; the accelerator uses published Arkworks 0.5 crates for FFTs and MSMs.

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

Open **http://127.0.0.1:5178/** and click **Generate proof**. Choose
**Benchmark** for five verified proofs and their median proving time. The page
only runs the prover: it does not create a wallet or connect to a blockchain.
Preparation happens on the first run; later proofs reuse the decoded key.

**Options** contains automatic/custom thread selection, the Go baseline, and a
JSON input editor. Automatic uses the CPU count reported by the browser, capped
at 18. **View proof** shows the proof, verification and preparation timings, and
the engine used. Proof JSON can also be downloaded. **Cancel** stops an active
run; the next run starts a fresh prover.

The staging script accepts an unpacked Mopro npm package as well as a bindings
directory. It validates supplied keys against this checkout's lockfile before
copying them; the 2x3 key is required. The sample must be a valid local test
request for those keys. `verify-wasm-prover.mjs` can capture such a request from
a localnet independently of this UI.

## AWS deployment

Open the [hosted Arkworks demo](https://d11pqvzf0b88yp.cloudfront.net/).

The browser proof playground is hosted on private S3 behind CloudFront. The
[deployment instructions](web/deploy/aws/README.md) build a versioned release
with the Arkworks accelerator, matching Go runtime, pinned proving keys and a
local test request. CloudFront supplies HTTPS and COOP/COEP headers for workers.
The sample generates and verifies proofs locally without submitting transactions.

The hosted UI only uses same-origin runtime assets, keys and the sample. It
makes no RPC, indexer or remote-prover requests. Existing devnet proxy routes
are retained by the hosting stack for compatibility with earlier releases.

The older Fly Dockerfile is retained but does not stage the Arkworks kernel or
sample. Use the AWS release scripts for this version.

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
mobile layout, cancellation, dialog focus, and absence of external API requests.
It saves screenshots and proofs under `target/mopro-browser-ui/`.
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

### One-second target on a device

[Open the deployed device benchmark](https://d11pqvzf0b88yp.cloudfront.net/releases/device-bench-20260911-1/benchmark.html).

[Desktop reference measurements and phase breakdown](web/benchmark-results/2026-09-11.md).

Open `/benchmark.html` on the served build. For a versioned AWS deployment use
`/releases/RELEASE_ID/benchmark.html`. This separate page runs the actual 2×3
transfer circuit through the same worker and prover as the main demo.

Enter the device model and worker count. Each run creates a fresh worker, prepares
the key, performs three warmups, then measures 30 proofs. Every proof is verified.
It shows first-proof latency, p50, nearest-rank p95, maximum latency, and separate
startup/key preparation/verification timings. Backgrounding the tab or cancelling
invalidates the run. Reports download locally; no results are uploaded.

For the target device, run three sessions and require proof p95 below 1,000 ms in
each. Keep first-proof latency alongside the warm measurements. Compare worker
counts on the physical device; a desktop with fewer workers is not a phone
measurement. The report retains all samples, including outliers, the public
sample's proofs, device/browser identity, fixture digest, key digest and release
metadata. It does not include the witness body.

Automated desktop reference runs (Chrome and a matching ChromeDriver required):

```sh
# Run a production preview first; it supplies the required isolation headers.
npm run poc:build
npm run preview --workspace @zolana/poc-web -- --port 3220
# In another terminal. Set CHROME_BIN and CHROMEDRIVER_BIN as needed.
node poc/web/scripts/benchmark-device.mjs 2,4,8,16 3
# Diagnostic kernel / remaining-work split; run separately from timing tests.
node poc/web/scripts/benchmark-device.mjs 8,16 1 profile
# Cancellation, foreground and mobile-layout checks.
node poc/web/scripts/benchmark-device.mjs 4 1 checks
```

Set `DEMO_URL` to the benchmark page and `DEMO_REPORT_DIR` to change the output
directory. `BENCH_DEVICE_LABEL` labels desktop reports. The runner writes a
`*-proofs.json` beside each report for independent native verification:

```sh
cd prover/server
MOPRO_BROWSER_PROOFS=/absolute/path/proof-8-1-proofs.json \
  go test ./cmd/prover-wasm -run '^TestZolanaMoproTransfer$' -count=1
```

Stage the matching sample and key before verification, as described above.
Profile runs assert the circuit has 54,031 constraints and acceleration is active.
`BENCH_KERNEL_BASE` can select a separately built instrumented kernel directory;
keep those diagnostic results separate from the shipped-build latency results.
For Go phase timings, build `cmd/prover-wasm` with `-tags bench_profile`, serve it
under a separate filename, and set `BENCH_WASM_URL` to that file. Ordinary builds
inline the empty timer functions away. The optional fields contain durations,
including witness construction, solving, commitment work, bridge/arithmetic and
assembly; they contain no witness values. Timers are nested, not additive.

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
`target/mopro-browser-comparison/`. The UI comparison discards three warm-up
proofs and measures 15 proofs; diagnostic profile runs measure 30. Every proof is verified. `CHROME_BIN` and
`FIREFOX_BIN` override the default macOS browser paths. Selenium can download
matching drivers on first use. Key preparation and verification are excluded
from the reported proving time.

On the same Mac and 2x3 sample, Brave/Chromium 152 and Firefox 155 measured:

| Workers | Brave median | Firefox median |
| ---: | ---: | ---: |
| 1 | 1,860.5 ms | 2,034.1 ms |
| 6 | 403.2 ms | 464.0 ms |
| 18 | 230.4 ms | 401.3 ms |

The historical diagnostic run at 18 workers measured 142.7 ms inside the Rust kernel in
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
