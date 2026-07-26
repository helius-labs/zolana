# P5. Prove-to-chain, full shape matrix, G2 characterisation

Suite P5 closes the gaps P4 left in
[proof-and-key-parity.md](../proof-and-key-parity.md) stages PKP-06 (full matrix
execution), PKP-07 (program acceptance), and PKP-08 (G2 compression
characterisation for reconciliation with fnd-d5). It builds on
[pkp-p4.md](pkp-p4.md): synthetic-tree prove→Rust-oracle verify is already green
for the fast gate; P5 asks whether a TypeScript-built transaction is accepted by
the shielded-pool program on a real validator, whether the full shape matrix
holds, and which live G2 points take the Rust compress fallback.

## Bottom line

**Does a TypeScript-built shielded transaction get accepted by the shielded-pool
program on a real validator?**

- **Pure TypeScript wire path: no.** After a real deposit, Photon sync, and
  prover proof against indexer Merkle context, production `compressProof` rejects
  the live G2 B point with `CLIENT_PROOF_POINT` (same class as the 16/16 sample
  in PKP-08). Submission does not reach the program. The default suite
  (`npm run test:e2e:p5`) asserts that wall and stops; it does not stub the
  program.
- **Hybrid wire path (TypeScript assemble + prove, Rust
  `alt_bn128_*_compress_be` only for compression): yes** for confidential
  Ed25519 deposit → private transfer → withdraw on the same-revision local
  stack (`npm run test:e2e:p5:hybrid`). The program confirms both private
  transactions; Photon indexes them; sender change and recipient note decrypt
  and sync; a stranger wallet finds nothing; public withdraw balances settle.
  This certifies program acceptance of a TypeScript-assembled, prover-built
  proof. It does **not** certify TypeScript G2 compression.

Program acceptance was exercised for confidential Ed25519 only. Zone,
zone-authority, P256, and merge prove-to-chain remain unproven against the
program.

## What P4 could not reach (owned here)

| Gap | P5 result |
| --- | --- |
| Program acceptance (PKP-07 / F080) | Hybrid confidential Ed25519 green; pure TS blocked by G2 compress |
| Full shape matrix (`ZOLANA_TEST_P4_FULL=1`) | **53/53 passed** in 536s against prover `http://127.0.0.1:3501` (`ZOLANA_PORT_OFFSET=500`); no shape broke |
| Live G2 fallback characterisation | 16/16 confidential Ed25519 1×1 samples: TS compress fail, Rust compress ok; noble `assertValidity` → `bad point: equation left != right`; `fromAffine` succeeds (`onCurveFp2: true`). Report: `g2-compression-live.json` |

`planning/typescript-sdk-port/row-updates/fnd-d5.md` was absent when this pass
ran. Compression behaviour was not changed.

## PKP-07: prove-to-chain

### Infrastructure (test-kit, not a parallel stack)

- `startLocalStack` / `createE2eHarness` with `ZOLANA_PORT_OFFSET=500`.
- Photon ephemeral SQLite: removed `--db-url` so `RingsMigrator` runs (otherwise
  `no such table: blocks`).
- Native multi-signer txs: `createTestNativeSigner` / `signTestTransaction` place
  signatures in reserved account-key slots.

### Flow

1. Protocol config + pool tree (authority + tree + payer signers).
2. Register sender and recipient.
3. Deposit SOL; Photon sync until sender decrypts the deposit UTXO.
4. `createTransfer` in TypeScript against wallet + indexer context.
5. Pure path: `signPrivateTransaction` → expect `CLIENT_PROOF_POINT`.
6. Hybrid path: monkeypatch `client.proveTransact` to fall back to
   `rustCompressProof` from the P4 oracle when TS compress fails; then transfer,
   withdraw, and assert state.

### Hybrid assertions (beyond “tx succeeded”)

- Transfer and withdraw confirm via `confirmPrivateTransaction`.
- Sender spent input + change amount; recipient decrypts transfer amount on the
  same tree; stranger sync finds zero UTXOs.
- Indexer returns the transfer by recipient view tag with nullifiers and output
  slots; Merkle proof for the recipient leaf resolves on the live tree.
- Withdraw recipient public balance increases by the withdraw amount; recipient
  private SOL balance returns to zero.

### What remains unproven for PKP-07 exit

The overlay exit asks for each supported family through the program. This pass
delivers confidential Ed25519 only. Zone / zone-authority / P256 / merge paths
through the program were not stood up. Pure TypeScript submission remains blocked
until G2 compression matches Solana’s `alt_bn128_g2_compress_be` acceptance
(fnd-d5 / P3).

## PKP-06: full shape matrix

Command (from `sdk-libs/ts/client`, offset 500):

```bash
npm run test:p4:full
# ZOLANA_TEST_P4=1 ZOLANA_TEST_P4_FULL=1 …
```

Result: 53 passed, 0 failed, duration ~536s. Prover-free oracle self-check cases
plus the full confidential set (both rails × `SPP_SUPPORTED_SHAPES`), full zone
set (both rails × shapes), remaining zone-authority shapes, and `merge_zone`
8×1. No shape failed on first execution. Compressed verification still uses the
P4 Rust compress fallback when TypeScript refuses a point; uncompressed verify
does not need that path.

## PKP-08: G2 characterisation (no behaviour change)

Command: `npm run test:p5:g2` under `@zolana/client` (or `ZOLANA_TEST_P5=1` on
`g2-compression-live.test.ts`).

| Metric | Value (n=16, confidential eddsa 1×1) |
| --- | --- |
| `tsCompressOk` | 0 |
| `rustFallbackNeeded` | 16 |
| `bothFail` | 0 |
| noble `assertValidity` throw | 16 (`equation left != right`) |
| `onCurveFp2` via `fromAffine` | 16 |

Interpretation for fnd-d5 reconciliation: live prover B points are accepted by
Solana’s compress syscall and by noble’s affine constructor as on the Fp2 curve,
but noble’s stricter `assertValidity` (the production `compressProof` path)
rejects them. That is the same divergence P3 recorded for off-curve / validity
policy; in this 16-sample confidential Ed25519 1×1 set it was the common case,
not a rare edge. Do not change production compression in this branch; disposition
belongs with fnd-d5 / P3.

## Commands ledger

| Claim | Command | Result |
| --- | --- | --- |
| Pure TS wall | `npm run test:e2e:p5` | 1 passed (~25s) |
| Hybrid prove-to-chain | `npm run test:e2e:p5:hybrid` | 1 passed (~110s) |
| Full P4 matrix | `cd sdk-libs/ts/client && npm run test:p4:full` | 53 passed (~536s) |
| G2 sample | `cd sdk-libs/ts/client && npm run test:p5:g2` | report written; rates above |

Port isolation: `ZOLANA_PORT_OFFSET=500` → RPC 9399, Photon 9284, prover 3501.
Requires prior `just build-programs`, `build-prover-server`, `ensure-photon`,
`npm run build` at repo root.

## Residual risk

1. **Release wire path:** wallets that only call production TypeScript
   `compressProof` cannot submit live proofs until G2 policy matches the
   program. Hybrid e2e must not be cited as TypeScript G2 certification.
2. **Family coverage through the program:** confidential Ed25519 only.
3. **Matrix vs program:** full-matrix green is still oracle verify, not program
   execution per shape.
4. Workspace `check:static` remains red on unrelated pre-existing client/wallet/
   test-kit errors owned by another worker; P5 files were not used to “fix”
   those.

## Verdict

P5 answers the release-blocker question honestly: the shielded-pool program
accepts a TypeScript-assembled confidential Ed25519 transaction when compression
uses Solana’s BN254 path; the pure TypeScript compressor still cannot produce
that wire form for live prover points. The full cryptographic shape matrix ran
once and passed. G2 fallback is characterised for fnd-d5 without changing
compression behaviour.
