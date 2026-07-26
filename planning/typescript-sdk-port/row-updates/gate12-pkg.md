# Gates 1 and 2 — package surface and cross-package boundaries

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-ts-gate12-pkg` |
| Branch | `port/gate12-pkg` |
| Scope | Full-SDK gates 1 and 2 from `review-checklist.md` |
| Measured against | [gates.md](gates.md) adjudication (`OPEN` / `PARTIAL`) |

## Gate 1 — package gates

### Workspace count

Root `package.json` `workspaces` lists **eleven** packages:

`hasher`, `interface`, `keypair`, `transaction`, `indexer-api`, `api`,
`client`, `wallet`, `merkle-tree`, `smart-account-client`, `test-kit`.

The former gate text said "nine." The two uncounted packages were
**`@zolana/hasher`** and **`@zolana/test-kit`**. The primary-queue dependency
order still names the original nine Rust-facing packages; hasher is covered by
the `H01`–`H14` rows, and test-kit is private annex-only for publish. The gate
wording now states the eleven-workspace list and that distinction.

`format` / `format:check` path globs now include `hasher` so a new file there
cannot skip prettier.

### G9-4 (browser runtime) — closed, already on tree

[gates.md](gates.md) recorded G9-4 open because `browser-check.mjs` is a static
scan. On this branch the close already landed (`deec8273` / `d84a1647` /
`ede0dd59`, [browser.md](browser.md)):

- `npm run test:browser-runtime` bundles the harness for `platform: browser`,
  serves it over loopback, and runs Poseidon / SHA-256 / HKDF / AES-CTR /
  Ed25519 / P256 vectors in headless Chromium.
- Re-run this session: green
  (`poseidonVectors:100`, `poseidonShortInputs:4`, `sha256:2`, `hkdfTags:4`,
  `aesCtrLengths:12`, `ed25519Messages:4`, `p256Digests:16`).

Package-gate checkbox for G9-4 is checked. No new browser code was required.

### G6-2 (aliasing census) — closed this run

[production-readiness-issues.md](../production-readiness-issues.md) G6-2 required
an aliasing test per public secret-adjacent accessor, not only the isolated
lifecycle cases in `secret-lifecycle-certification.test.ts`.

Landed:

- `keypair/test/vectors/aliasing-census.test.ts` — named census of accessors;
  each returned buffer is mutated and the next read must be unchanged; constructor
  inputs are zeroed after construction.
- `CompressedShieldedAddress.ownerHash` was a public field aliasing internal
  storage; it is now a copying getter over `#ownerHash`.

Package-gate checkbox for G6-2 is checked.

### F041 (publish metadata and import-aware deps) — closed this run

Verified against current manifests (register was stale in part):

| Claim | Verdict |
| --- | --- |
| Most packages lack repository / license / publish metadata | **True** except `@zolana/transaction`, which already had license + repository. |
| Two packages declare unused runtime `@noble/curves` | **True** for `@zolana/interface` and `@zolana/transaction` (no `src` import). Also found unused `@noble/ed25519` on `@zolana/keypair` and unused `@zolana/indexer-api` / `@zolana/merkle-tree` on `@zolana/test-kit`. |
| Dependency test compares manifests without inspecting source imports | **True** at `workspace-check.mjs` `checkDependencies`. |
| Client undeclared `@noble/*` | **True** and worse: `@zolana/client` imported `@noble/curves` and `@noble/hashes` without declaring them (hoisted from siblings). |

Fixes (Light-shaped metadata: `license`, `repository`, `homepage`, `bugs`,
`publishConfig.access` on publishable packages; private `test-kit` omits
`publishConfig`):

- Added publish metadata to all eleven package manifests.
- Aligned `dependencies` / `packages.mjs` with `src` imports (remove unused,
  declare client's `@noble/curves` + `@noble/hashes`).
- `checkDependencies` now requires source imports to match the declared graph
  and asserts the publish metadata fields.

`npm run test:dependencies` green after the change.

### Gate 1 checkable off?

**No.** G9-4, G6-2, the stale count, and F041 are closed, and the package-row
adverse-empty recount from [gates.md](gates.md) still holds. The remaining
package-completion bullets (fixture freshness per package, rejection/tamper as a
per-package claim, browser entry points, pack checks, export disposition, etc.)
are still unchecked and were not re-walked with named per-package evidence in
this run. Checking the top-level line would repeat the unsupported-check
failure mode. Leave gate 1 unchecked until that walk lands.

---

## Gate 2 — cross-package types, errors, capabilities

### `KEYPAIR_HASH` empty-slice / Poseidon sites — already closed

[crypto-certification-b.md](crypto-certification-b.md) residual 1 asked for
`KEYPAIR_POSEIDON` where Rust returns `Poseidon` on expressible inputs. On this
tree:

| Site | Code today |
| --- | --- |
| `mergeCiphertextHash` empty ciphertext | `KEYPAIR_POSEIDON` (`merge/index.ts`) |
| `ShieldedPublicKey.hash` P256 path | `KEYPAIR_POSEIDON` (`public-key.ts`) |
| `ShieldedPublicKey.ownerPublicKeyField` P256 path | `KEYPAIR_POSEIDON` (`public-key.ts`) |

`security.test.ts` and `error-redaction-certification.test.ts` assert
`rustVariant === "Poseidon"` / code `KEYPAIR_POSEIDON` for the empty ciphertext.
`KEYPAIR_HASH` remains only for TypeScript-only shapes (e.g. wrong-length
`hashField` inputs) with `rustVariant: null`, which matches the standing rule.

No code change this run; residual closed by prior commits, verified here.

### Promise / vestigial async — closed for the named audit; capability rule follows Q17

- `userRecordAddress` is synchronous in `wallet/src/registry.ts` and
  `test-kit/src/user-registry.ts` (PDA derivation, matching Rust).
- Scan of `export async function` bodies under `sdk-libs/ts/*/src` found no other
  public PDA/sync helper that is async without I/O; remaining `async` wrappers
  either `await` RPC/signing or return another I/O promise.
- `ViewingKeyLike` is already synchronous ([Q17](../authority-rulings.md#q17-an-out-of-process-viewing-key-backend-k11)).
- `ShieldedKeypairLike` **keeps** `T | Promise<T>` by that same ruling (remote
  signer). [gates.md](gates.md) residual 10 that asked to drop Promise from both
  capability interfaces is superseded for the signing half; dropping it would
  contradict the owner. `trait-surface.test.ts` pins the split.

### `address-append` — owner ruling fully carried out

[authority-rulings.md](../authority-rulings.md) "The forester instruction builder
on the TypeScript public surface": withdraw the builder; do not port the witness.

Confirmed on this tree:

- No `batchUpdateNullifierTreeInstruction` under `sdk-libs/ts`.
- Comment block at `interface/src/instructions/index.ts` records the deliberate
  absence; codec + `InstructionTag` remain.
- `client/test/prover/circuit-types.test.ts` fails if any shipped source names
  `address-append`; fixture `typescriptPaths["address-append"] = false`.
- Gate 2 checklist text now carves this out as an unsupported capability rather
  than an unexplained hole.

### P3 G2 compression — not this worker

Owned by `port/g2`. TypeScript `compressProof` rejecting live prover G2 points
remains. **Gate 2 cannot fully close until that lands.** Checklist gate 2 stays
unchecked and names the carve-out.

### Gate 2 checkable off?

**No.** Three of four named residuals are closed or accepted-with-ledger
(`KEYPAIR_HASH`, Promise/Q17, `address-append`). G2 compression still blocks a
HOLDS claim.

---

## Commands run this session

```bash
npm run build
npm run test:dependencies
npm run test:browser-runtime
# from sdk-libs/ts/keypair:
npx vitest run --config ../config/vitest.vectors.config.js aliasing-census
npx vitest run --config ../config/vitest.package.config.js test/security.test.ts
cargo fmt --all
npm run check:static   # expect only the seven known G2 static errors in
                       # client/test/vectors/g2-compression-live.test.ts
npm run test:unit
```

## Commits

Incremental commits on `port/gate12-pkg` with `--no-gpg-sign` (see git log).
