# Browser runtime vectors (G9-4)

Closes the gap `browser-check.mjs` cannot see: cryptographic values produced
inside a real browser engine, compared to the same Rust-generated vectors the
Node suites already pin.

## Bottom line

**Yes: the SDK produces identical values in headless Chromium and in Node on
the vectors this job runs.** Poseidon (WASM), SHA-256, HKDF-backed viewing
tags, AES-CTR encrypt/decrypt, Ed25519 sign/verify, and P256 sign/verify
matched. No Node-versus-browser divergence turned up.

The job detects a wrong value: flipping the last nibble of
`poseidon-zeros-1.expectedBytes` made the check exit 1 with

```
poseidon/poseidon-zeros-1: expected …e110, got …e11c
```

and restoring the vector made it green again.

## What was missing

`sdk-libs/ts/config/browser-check.mjs` bundles with esbuild and greps for
`node:` / Node globals. That proves the graph is browser-shaped. It does not
execute the bundle. Two failure classes therefore shipped green:

1. A crypto path that resolves differently under Web Crypto / a different
   `crypto` global than Node (wrong bytes, no crash).
2. Poseidon WebAssembly instantiation, which an import scan does not observe
   and which sits on the commitment and nullifier path.

G9-4 in `production-readiness-issues.md` named the first class; the WASM gap is
the sharper one for this SDK.

## What landed

| Piece | Role |
| --- | --- |
| `sdk-libs/ts/config/browser-runtime-harness.mjs` | Browser-side assertions against the committed vectors |
| `sdk-libs/ts/config/browser-runtime-check.mjs` | esbuild browser bundle → loopback HTTP → Playwright Chromium |
| `npm run test:browser-runtime` / `check:browser-runtime` | Local and `npm run check` entry points |
| `typescript.yml` job `browser-runtime` | Merge-gate job, Chromium only, browser cache keyed on the lockfile |

Light Protocol's `stateless.js` browser suite is the same shape: serve a bundled
page, `page.evaluate` the SDK, assert. Zolana keeps that shape inside the
existing config-script convention rather than adding a Playwright test project.

### Vectors (same files as the Node suites)

| Primitive | Vector file | What is asserted |
| --- | --- | --- |
| Poseidon (inlined WASM) | `poseidon-parity-v1.json` | 100 vectors + 4 short inputs |
| SHA-256 | `keypair-parity-v1.json` `hashes` | `sha256Bytes`, `sha256Be` |
| HKDF | `keypair-parity-v1.json` `viewingKeys` | ECDH, view tags, transaction viewing key |
| AES-CTR | `keypair-parity-v1.json` `encryption` | Encrypt and decrypt across the recorded lengths |
| Ed25519 | `key-certification-v1.json` `k3Ed25519Signatures` | Public key, sign, verify |
| P256 | `key-certification-v1.json` `k2P256Signatures` | Sign and verify over the digest sweep |

Crypto in the TypeScript packages is `@noble/*` plus `globalThis.crypto` for
randomness and the inlined Poseidon artifact via `WebAssembly.instantiate` /
`atob`. The harness initializes Poseidon explicitly, the same call a browser
consumer must make.

## Control edit

| Step | Result |
| --- | --- |
| Perturb `poseidon-zeros-1` expected last nibble `c` → `0` | exit 1, one mismatch naming expected vs got |
| Revert the vector | exit 0, full suite green |

A browser test that cannot go red is worse than no browser test; this one can.

## Cost and flakiness

Measured locally with Chromium already cached: **~2.1 s** for the check itself
(bundle + serve + launch + the vector set above). CI adds `npm ci`, the
Rust/wasm setup shared with other TypeScript jobs, and a Playwright Chromium
install cached on `package-lock.json`.

Choices that keep the job cheap and stable:

- One engine (Chromium), not Firefox/WebKit.
- Cache `~/.cache/ms-playwright` keyed on the lockfile.
- Cryptographic vectors only; not the wallet/e2e suite.
- No path filter. The rest of `typescript.yml` already runs unconditionally,
  and a path-filtered job that reports `skipped` would fail today's merge gate
  (`needs.*.result` must be `success`). Filtering would only pay off if the
  workflow gained a broader path-based skip pattern; alone it would either
  weaken the gate or add merge-gate special cases for one job.

## Path not taken

Vitest's browser mode (`@vitest/browser-playwright` appears in the lockfile as
an optional peer) would re-run the whole unit graph in a browser. That is the
wrong width for G9-4: more flake surface, more CI minutes, and no stronger
differential signal than replaying the Rust vectors the Node suites already
own.
