# Example-surface reconciliation

Branch: `port/example-surface`  
Worktree: `/Users/tilohelius/Workspace/zolana-wt-example`  
Merged: `ts-example-deposit-transfer-withdraw`  
Date: 2026-07-26

## Reconciled surface

The public TypeScript client surface is now the example branch's instruction-level
shape, with this branch's Rust-parity behaviour kept underneath it.

| Surface | Before (this branch) | After (reconciled) |
| --- | --- | --- |
| `@zolana/client` root | `ZolanaClient`, free `createAndSendTransaction` | `ZolanaClient`, free `compileTransaction`, free `createAndSendTransaction` |
| `ZolanaClient` send | no method form | `createAndSendTransaction({ instructions, feePayer: TransactionSigner, signers? })` |
| `@zolana/interface` | no signer helpers | `TransactionSigner`, `signerIndex`, `withSignature` |
| Sync authority name | `SyncWalletAuthority` | `WalletSyncAuthority` (Rust still spells `SyncWalletAuthority`) |
| `decryptTransactions` | `{ authority, transactions, registry } → AssetBalance[]` | unchanged (Rust-aligned; see disagreements) |
| `Wallet.decrypt` | absent | present; construct-sync via `syncWalletWithMaterial` |
| Examples | `sdk-tests/client` only | paired `sdk-tests/rust-client` + `sdk-tests/typescript-client` |
| `test-kit` primitives | no `base58.ts`; no thin `native.ts` helpers | thin `native.ts` (`sendAndConfirm`, `confirm`, airdrop/rent); no `base58.ts` |

`compressG2` limb order was left alone. HEAD, the example tip, and the merge
result are byte-for-byte identical on the gnark `c1`-first layout.

## Conflicts and resolutions

| File | Resolution |
| --- | --- |
| `package.json` | Union: keep HEAD's hasher/format paths, e2e photon/p5/gate3, `fixtures:check` node script, `check:scope`, and `check:browser-runtime`; add example's `lint:example`, `typecheck:example`, `test:e2e:example`. |
| `client/src/index.ts` | Export `compileTransaction`, `ZolanaClient`, and keep free `createAndSendTransaction` for `Rpc` parity fixtures. |
| `client/src/error.ts` | Keep HEAD's existing `CLIENT_INCOMPLETE_SIGNATURES` / `CLIENT_CONFIRMATION_TIMEOUT` placement; drop duplicate DETAIL_SHAPES entry the merge introduced. |
| `client/src/prover/proof.ts` | Whitespace only; `compressG2` untouched. |
| `test-kit/src/node/index.ts` | Keep HEAD's Photon TMPDIR comment (already present above the call); drop the example's duplicate. |
| `test-kit/src/user-registry.ts` | Keep HEAD's `placeNativeSignature` fallback for hand-built TestRpc messages; example's bare `createSolanaSigner` wrapper alone breaks those doubles. |
| `transaction/src/wallet/sync.ts` | Keep HEAD's `SyncPass` / `AssetRegistry` body; rename authority type to `WalletSyncAuthority`. |
| `transaction/src/wallet/state.ts` | Keep example's `Wallet.decrypt`, but wire it through `syncWalletWithMaterial` so it does not fight HEAD/`decrypt_transactions` shape. |

Auto-merged without conflict: client method form, `signers.ts`, wallet imports of
`compileTransaction` from `@zolana/client`, rust-client rename, TypeScript
example + READMEs, hasher artifact refresh driven by the `Cargo.toml` member
rename.

## F106

**Partially closed.**

Closed by this work:

- `sdk-libs/ts/test-kit/src/base58.ts` remains absent (example move).
- `sdk-libs/ts/test-kit/src/native.ts` is the thin local-stack helper set, not a
  second crypto primitive library.
- `sdk-libs/ts/smart-account-client/src/sha256.ts` is **deleted**; PDA hashing
  uses `@noble/hashes/sha2.js`.
- Smart-account address encode/decode uses `bs58` instead of a hand-rolled
  alphabet loop.

Still duplicated (hand-rolled `BASE58` alphabets remain in):

- `interface/src/internal.ts`
- `client/src/internal.ts`
- `wallet/src/internal.ts`
- `transaction/src/internal.ts`
- `indexer-api/src/scalars.ts`
- `test-kit/src/user-registry.ts` (local helpers for the TestRpc signer fallback)
- e2e/test doubles

`fnd-tail.md` records F106 as `PARTIAL`.

## Example shape vs Rust

Verified rather than trusted:

1. **Claim holds for the send path.** Rust
   `Rpc::create_and_send_transaction` compiles with `Message::new` and sends.
   TypeScript now exposes `compileTransaction` (the `Message::new` job) and
   `ZolanaClient.createAndSendTransaction` (signer-based send). That is the
   instruction-level surface the commit message described.
2. **`decryptTransactions` shape.** Example tip mutated a caller wallet and
   returned `SyncReport`. Rust's free `decrypt_transactions` builds a fresh
   wallet from the authority, syncs, and returns balances. We kept the
   Rust/HEAD free-function shape and adapted `Wallet.decrypt` to the
   construct-sync path Rust's TODO already sketches.
3. **Naming.** Rust `SyncWalletAuthority` → TypeScript `WalletSyncAuthority`
   (documented rename; disposition suites pin it).
4. **Free `createAndSendTransaction`.** Rust puts create-and-send on the `Rpc`
   trait. The example only exported the method on `ZolanaClient`. We kept the
   free function (rpc + sign callback) as additional parity surface used by
   oracle tests.

## Export gates

### `api:check` before update

12 undeclared differences (intended):

- interface: `+signerIndex`, `+TransactionSigner`, `+withSignature`
- transaction / wallet: `+WalletSyncAuthority`, `-SyncWalletAuthority`
- client: `+compileTransaction`
- wallet: `+createSolanaSigner` (and subpath mirrors)
- test-kit `./node`: `+confirm`, `+minimumBalanceForRentExemption`,
  `+requestAirdrop`, `+sendAndConfirm`

### After `npm run api:update`

`api reports match for 11 packages`.

### Disposition suites

| Suite | Result |
| --- | --- |
| `client/test/vectors/crate-root-exports.test.ts` | 3 passed |
| `transaction/test/vectors/module-surface.test.ts` | 24 passed |
| `wallet/test/vectors/export-vector.test.ts` | 11 passed |
| `interface/test/exports.test.ts` | 1 passed |

`planning/typescript-sdk-port/public-exports.md` updated to describe the
reconciled surface.

## Command results

```text
npm install                                          ok
npm run build                                        ok (after cargo on PATH)
npm run test:unit                                    2301 passed | 9 skipped
npm run check:static                                 ok
npm run check:packaging                              ok
npm run fixtures:check                               ok (58 fixtures, 182 inventory rows)
npm run api:check (before update)                    12 differences
npm run api:update                                   wrote 11 reports
npm run api:check (after)                            api reports match for 11 packages
```

## Commits on `port/example-surface`

1. `40ba2215` — Merge `ts-example-deposit-transfer-withdraw` (conflicts resolved)
2. `f6bc2a4c` — Drop hand-rolled smart-account SHA-256 and base58
3. `35c159c5` — Record reconciled surface in api-reports + public-exports
4. `1f57ce4c` — Eslint fixes on the TypeScript example
5. `2df7bb6a` — Allow smart-account `@noble/hashes` and `bs58` in packages.mjs

## Out of scope (honoured)

- No edits under `programs/`, `program-libs/`, or `prover/server/circuits/`
- No edits to `compressG2` limb order
- Stayed out of `xtask/src/bin/`, `fixtures/manifest.json`, and
  `fixtures-check.mjs` (parallel rejection-fixture worker)
