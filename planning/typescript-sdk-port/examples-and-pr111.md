# Examples and PR #111

## Public example baseline

Inspected
[`rust-client/examples`](https://github.com/helius-labs/zolana-examples/tree/4d8c2d16487a653d163d80b8c7f6e3702ebfdadc/rust-client/examples),
its `Cargo.toml`, `README.md`, and `src/lib.rs` at commit
`4d8c2d16487a653d163d80b8c7f6e3702ebfdadc`. The manifest pins Zolana
`2eba04498ab852e2c3135bf25e20f11e9d28bb2c` (`2eba044`). Treat the examples as
workflow acceptance, not current API or byte-layout authority. Current package
ownership and behavior come from frozen `origin/main`
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`).

The pinned examples predate the current `zolana-wallet` split. Their action
operations map to `@zolana/wallet`, service composition to `@zolana/client`,
deterministic private-transaction construction to `@zolana/transaction`, and
raw program instructions to `@zolana/interface`. Do not copy their older
module paths into TypeScript.

### Acceptance workflow matrix

| Example | Current TypeScript imports and contract | E2E assertion |
| --- | --- | --- |
| `create_private_wallet.rs` | `ShieldedKeypair` from `@zolana/keypair`; `Wallet` from `@zolana/transaction`; registry, registration transaction, checked fetch, and resolution from `@zolana/wallet`; `SolanaRpc`, `ZolanaIndexer`, and `ZolanaClient` from `@zolana/client`; `ProverClient` from `@zolana/client/prover`. Use [canonical declarations](action-and-instruction-api.md#canonical-declarations) and [submission, confirmation, sync, balances, and history](action-and-instruction-api.md#submission-confirmation-sync-balances-and-history). | First run creates the canonical user record; second run builds no registration transaction; fetched owner, signing, nullifier, and viewing public material equal the local authority. |
| `deposit.rs` | `createDeposit`, `buildDepositTransaction`, `syncWallet`, and balance reads from `@zolana/wallet`; `SOL_MINT` and `Wallet` from `@zolana/transaction`; RPC/indexer from `@zolana/client`. Follow [SOL and SPL deposit](action-and-instruction-api.md#sol-and-spl-deposit). | SOL and SPL private balances increase by exact amounts once; public source/custody deltas match; repeated sync is idempotent; commitment/event/Photon bytes match Rust V. |
| `deposit_instruction.rs` | `ShieldedAddress` and `randomBlinding` from `@zolana/keypair`; `ownerUtxoHash` from `@zolana/transaction`; shared settlement types from `@zolana/interface`; `depositInstruction` from `@zolana/interface/instructions`; RPC only from `@zolana/client`. Follow [deposit instruction](action-and-instruction-api.md#deposit-instruction). | Public SPL source decreases and vault increases exactly; Photon finds the bootstrap view tag; recipient decryption yields the deposited amount; instruction bytes/accounts match Rust V. |
| `sync_balance.rs` | `syncWallet`, `getPrivateTokenBalances`, `getPrivateTransactions`, and authority from `@zolana/wallet`; `Wallet` from `@zolana/transaction`; `ZolanaIndexer` from `@zolana/client`; indexer request/response schema from `@zolana/indexer-api`. Follow [submission, confirmation, sync, balances, and history](action-and-instruction-api.md#submission-confirmation-sync-balances-and-history). | Synced balance equals funded amount; raw tag query contains the indexed output; a second sync adds no UTXO or history row. |
| `transfer.rs` | `createTransfer`, `buildPrivateTransaction`/`signPrivateTransaction`, authority, sync, and recipient resolution from `@zolana/wallet`; `Wallet` and asset constants from `@zolana/transaction`; proof/RPC/confirmation from `@zolana/client`. Follow [registered transfer and public fallback](action-and-instruction-api.md#registered-transfer-and-public-fallback) and [SOL/SPL withdrawal, external custody, and authority signing](action-and-instruction-api.md#solspl-withdrawal-external-custody-and-authority-signing). | Registered recipient routes privately and receives the exact amount. An independent unregistered case returns `publicWithdrawal`, increases the public SOL/SPL destination exactly, and creates no recipient private UTXO. |
| `transfer_instruction.rs` | `ConfidentialTransfer`, spend inputs, authority encryption values, and decryption from `@zolana/transaction`; `assemble`, `ProverClient`, and `compressProof` from `@zolana/client/prover`; `transactInstruction` from `@zolana/interface/instructions`. Follow [registered confidential transfer instruction](action-and-instruction-api.md#registered-confidential-transfer-instruction) and [prover boundary invariant](action-and-instruction-api.md#prover-boundary-invariant). | Program proof verifies, each nullifier is inserted, outputs append, recipient decrypts the exact amount, sender change is exact, and prover/instruction vectors match Rust V. |
| `withdraw.rs` | `createWithdrawal`, `buildPrivateTransaction`/`signPrivateTransaction`, `WalletAuthority`, external `TransactionSigner`, sync, balances, and history from `@zolana/wallet`; settlement/proving client from `@zolana/client`. Follow [SOL/SPL withdrawal, external custody, and authority signing](action-and-instruction-api.md#solspl-withdrawal-external-custody-and-authority-signing). | Run SOL and SPL cases: recipient lamports or ATA increases exactly, private balance decreases exactly, and repeated confirmation/sync does not duplicate history. |
| `withdraw_instruction.rs` | `ConfidentialTransfer` and proof inputs from `@zolana/transaction`; Merkle/prover pipeline from `@zolana/client/prover`; `TransactWithdrawal` from `@zolana/interface`; `transactInstruction` from `@zolana/interface/instructions`. Follow [SOL withdrawal instruction](action-and-instruction-api.md#sol-withdrawal-instruction) and [SPL withdrawal instruction](action-and-instruction-api.md#spl-withdrawal-instruction). | Run independent SOL and SPL cases. Assert exact interface/vault and recipient deltas, proof/instruction vector parity, and typed failure for wrong CPI authority, token account, token program, or SOL settlement account. |

### Current wallet acceptance beyond the eight examples

Do not invent additional upstream Rust examples. Add split, merge creation,
merge submission, and idempotent ATA creation as current frozen-Rust
integration scenarios in the wallet E2E suite. Their imports, stage ownership,
success assertions, and negative assertions are fixed by
[additional wallet acceptance contracts](action-and-instruction-api.md#additional-wallet-acceptance-contracts).
They supplement rather than renumber the eight example mappings above.

### Shared example support

`rust-client/src/lib.rs` is test scaffolding, but it reveals acceptance
dependencies:

- environment/signer loading;
- canonical default tree and explicit RPC/indexer/prover URLs;
- program-account scan and `SplAssetRegistry` decode;
- mint/interface/token-account setup;
- funded recipient and user registration;
- indexer polling before sync;
- SOL/SPL deposit setup.

Port the production capabilities, not the ad hoc hardcoded devnet URLs or test
mint helpers. Put local funding/mint/service setup in `@zolana/test-kit`.

### TypeScript example acceptance shape

Do not port examples during core implementation. In the final E2E packet,
create action-level and instruction-level TypeScript examples with the same
observable steps. Each example must:

- accept URLs/tree/signer through explicit configuration;
- avoid printing secrets or full ciphertext plaintext;
- exit non-zero on a failed assertion;
- emit one machine-readable final result for CI;
- run against an isolated local stack through `ZOLANA_PORT_OFFSET`;
- use no test-only production imports.

## PR #111 metadata

- URL: [`helius-labs/zolana#111`](https://github.com/helius-labs/zolana/pull/111)
- Title: `chore: ts sdk port`
- Author: `swenhelius`
- State: open, non-draft, review required
- Base/head: `main` ← `ts-port`
- Head: `8d1a6e032fc656496a6833da3367ac90e9139fa1`
- Commits: `95cc8aa` (`feat(sdk): add TypeScript client e2e`) and `8d1a6e0`
  (`chore: ignore nested node_modules`)
- Body: `wait for rem. PRs to be merged`
- Discussion: no issue comments, inline review comments, submitted reviews,
  labels, or review decision beyond `REVIEW_REQUIRED`.
- Diff: 30 files, 6,897 additions, 1 deletion.
- Checks inspected on 2026-07-23: all reported Rust, Go, TypeScript, and
  integration checks passed; one unevaluated matrix-expression check skipped.

Green checks establish that the branch compiled and its own tests passed. They
do not establish Rust parity, browser compatibility, package publishability,
or on-chain workflow acceptance.

PR #111 predates frozen `43fde8e4` package ownership. Its single
`sdk-libs/ts/client` workspace is not the target package. Reclassify every
usable fragment into the current package graph below; do not retain a
compatibility barrel in `@zolana/client`.

## PR #111 file-by-file incorporation

| PR file(s) | Decision | Incorporation requirement |
| --- | --- | --- |
| `.github/workflows/rust.yml` | reuse concept | Keep separate unit and prover integration jobs; add build/package, Rust conformance, browser, localnet/Photon, examples, coverage, and API-report gates. Use the repository's current proving-key release/cache tag. |
| `.gitignore` | reuse narrowly | Ignore root/workspace install/build output with anchored patterns; do not introduce a blanket rule that can hide fixtures or nested package metadata. |
| `justfile` | reuse concept | Keep check/unit/integration recipes, but run package build and artifact smoke tests and use common service lifecycle/port-offset helpers. |
| `package.json`, `package-lock.json` | replace | Preserve npm workspaces only if npm remains the selected manager. Move package dependencies to their owning workspaces, pin engine/package-manager versions, add audit/license/API/build/browser scripts, and regenerate the lockfile. |
| `prover/server/prover/common/marshal.go`, `prover/server/server/server.go` | do not require | The `X-Zolana-Proof-Format: transact` response avoids BN254 work in JS but changes a shared service solely for one client. Prefer the existing gnark response and a correct audited TS parser/compressor. Propose a versioned server format separately only if every client benefits and Go/Rust compatibility tests cover it. |
| `sdk-libs/ts/client/package.json` | replace structure | Reuse ESM intent and declaration output. Split packages, fix built entry paths, add `sideEffects`, engine, repository, exports/subpaths, publish config, files, and consumer tests. The PR's `rootDir: "."` would emit `dist/src/index.js` while `main` points to `dist/index.js`; its CI does not run `npm pack`/consumer import. |
| `sdk-libs/ts/client/tsconfig.json` | reuse flags | Keep strict, no-unchecked-index, exact-optional, declarations/maps, ES2022. Split build/test configs; remove unconditional Node types from browser packages; run browser type and bundle checks. |
| `src/bytes.ts` | reuse after vectors | Useful checked integer/byte helpers. Replace `Buffer` hex conversions, brand fixed lengths, reject odd/invalid hex instead of normalizing silently where protocol input is expected, and test all ranges. |
| `src/constants.ts` | move/replace | Values are useful evidence, but canonical program IDs/tags belong in `@zolana/interface`; key-domain constants belong in keypair internals. Generate or vector-check them rather than duplicating. |
| `src/hash.ts` | reuse only after audit | Structure is small. Confirm `poseidon-lite` parameters/input rules against `zolana-hasher`; reject field inputs outside BN254 rather than relying on library reduction; add Rust V. |
| `src/keypair.ts` | split and rework | Reuse method decomposition and domain strings. Remove `node:crypto`/`Buffer`; add typed errors and secret lifecycle; prove P256 signing options, HKDF semantics, deterministic transaction key derivation, curve validation, AES counter semantics, and every output with Rust V. |
| `src/data.ts` | reuse after codec fixtures | Immutable copying and canonical checks are useful. Verify record set/order and exact wincode bytes against the frozen baseline/spec; add decode and malformed-input support. |
| `src/utxo.ts` | reuse after vectors | Class/factory boundaries are useful. Replace generic `Error`, validate amount ranges and field canonicality, add full data/zone behavior, and match Rust hashes. |
| `src/shape.ts` | reuse | Shape list and first-fit rule mirror the local client, subject to the four-source synchronization gate in `CLAUDE.md`. |
| `src/rpc.ts` | expand | Keep async interface intent. Add the full Rust Rpc surface, request context, typed accounts/signatures, generated indexer schemas, confirmation, program accounts, rent, blockhash, and precise unsupported errors. |
| `src/pda.ts`, `src/instructions.ts` | move to interface | Reuse only after comparison with canonical interface builders. Hand-copied IDs, tags, account order, and serialization are drift risks. |
| `src/actions.ts` | split into `@zolana/wallet` | Deposit preparation is a seed only. Implement the exact wallet-owned declarations and [action flows](action-and-instruction-api.md#action-flows): registration, deposit, transfer routing/fallback, withdrawal, external custody, authority signing, confirmation handoff, sync, balances, and history. |
| `src/prover.ts` | split into `@zolana/client/prover` | JSON interfaces and client methods are useful reference. `negateG1` is explicitly a no-op, so existing gnark proof conversion is incomplete. Implement the exact [prover boundary](action-and-instruction-api.md#prover-boundary-invariant), real BN254 validation/negation/compression, retry/timeout/abort behavior, and Rust proof/result fixtures. |
| `src/transaction.ts` | split across `@zolana/transaction`, `@zolana/client/prover`, and `@zolana/interface` | It sketches builder/witness/instruction flow but supports only 2x3, conflates layers, and uses Node-only APIs. Deterministic transfer/slots belong to transaction, witness/prover transport to client, and final accounts/bytes to interface. Implement the independent [instruction flows](action-and-instruction-api.md#instruction-flows) by frozen Rust module and vector. |
| `src/walletAuthority.ts` | move to `@zolana/wallet` over transaction authority types | Local authority structure is useful. Match the canonical authority declarations in [the public export manifest](public-exports.md#zolanawallet), including transfer/split encryption, approval, P256 signing, sync material, external authority contract tests, typed failures, and no secret exposure. |
| `src/index.ts` | replace | Explicit package/subpath export reports replace wildcard exports. |
| `test/keypair.test.ts`, `test/utxo.test.ts`, `test/instructions.test.ts` | retain as smoke ideas | Determinism/round-trip/length assertions are insufficient. Replace expected values with Rust-produced bytes and assert typed negative errors. |
| `test/prover.test.ts` | retain request-shape ideas | Keep mocked HTTP/error coverage. Add real proof math vectors; a length-only proof assertion cannot detect coordinate errors. |
| `test/transaction.test.ts` | retain scenario ideas | Add Rust fixtures and program execution. `length > N` assertions do not establish instruction compatibility. |
| `test/e2e.test.ts` | replace with layered integration | It proves against synthetic single-leaf trees but does not submit to SPP, query Photon, sync a wallet, or run example workflows. Keep a prover-only tier and add localnet lifecycle/E2E tiers. |

## Specific PR gaps and conflicts

### Protocol and correctness

- No Rust-generated fixtures or cross-language oracle exist.
- Proof A negation is a no-op in the normal gnark parser.
- Default-zone dummy ciphertexts conflict with
  [`docs/spec.md`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/docs/spec.md#empty-utxo):
  dummy outputs get no
  ciphertext.
- The private transaction builder restricts shapes to 2x3 even though the
  exported shape list contains ten shapes.
- The branch does not cover merge, merge-zone, zone transfer,
  zone-authority, split, plaintext, proofless decode, wallet history, or full
  wallet sync.
- Typed Rust error parity is absent; plain `Error` messages are the only
  contract.
- Several fixed byte types are aliases without runtime branding, so callers can
  pass wrong lengths until a later helper happens to check.

### Public workflow

- No `SolanaRpc`, `ZolanaIndexer`, generated API client, `ZolanaClient`,
  registry resolution/registration, ATA action, transfer/withdraw action,
  transaction confirmation, indexer polling, wallet sync, or private balance
  API.
- No E2E submits a proof-backed instruction to the shielded-pool program.
- No acceptance case maps to the eight current Rust examples.

### Runtime and package

- `node:crypto`, `Buffer`, `process.env`, and Node global types make the core
  entry Node-specific despite a DOM lib declaration.
- The package output paths are inconsistent with the compiler root.
- Tests are included in the declaration build.
- No `npm pack` consumer smoke test, browser bundle test, export report,
  coverage gate, dependency/license policy, or release metadata exists.

## Incorporation sequence

1. Save PR #111 source files as review references or cherry-pick only after the
   package skeleton exists; do not make its server response format a
   prerequisite.
2. Extract byte/hash/key/prover ideas into their target package modules.
3. Create Rust V before accepting each extracted operation.
4. Replace length-only/internal-consistency tests with vector and negative
   tests.
5. Implement missing transaction/wallet/RPC/action surfaces from the frozen
   Rust baseline.
6. Run the example workflow E2E suite.
7. Delete superseded monolithic files; do not keep compatibility shims for
   unshipped PR-only APIs.
