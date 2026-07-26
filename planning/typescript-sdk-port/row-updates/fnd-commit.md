# FND commit — verdicts and fixes

Worktree: `zolana-ts-fnd-commit` · branch `port/fnd-commit` · base `1557cf10`.

Four Medium findings that can make the SDK commit a different value than Rust
or produce an artifact the chain rejects. Treated at the severity of that
effect.

## Verdicts

| ID | Verdict | Evidence |
|----|---------|----------|
| **F131** (+F141 dup) | CONFIRMED | Rust `PreparedTransfer::finalize` (`transfer.rs:458-464`) only calls `with_public_sol` / `with_public_spl` when the amount is `Some`. TS `finalizeTransfer` (`transact.ts` pre-fix) flat-passed `userSolAccount` / SPL accounts into `createExternalData` even when `publicSolAmount` / `publicSplAmount` were omitted. `prepare` already omits a zero public amount (`publicSol === 0n ? {} : …`) while still storing the withdrawal recipient on the prepared struct — same as Rust — so a zero-amount withdrawal hashed a real recipient in TS and the unset default in Rust. Oracle builder cases exercise `withPublicSol` / `withPublicSpl`; the production path did not. |
| **F101** | STALE | `resolveZoneProgramId` at `sdk-libs/ts/transaction/src/utxo.ts:38-47` already mirrors Rust `resolve_zone_program_id` (`utxo.rs:49-60`): no zone data → drop the program id; zone data without a program → error; both present → retain. Deserialization paths call it; `zone-resolution.test.ts` pins the drop. Direct `Utxo` construction retaining `zoneProgramId` without zone data matches Rust’s public-field struct (neither constructor normalizes). **No conflict with T28:** T28 normalizes the zone *data hash* and deliberately leaves the zone *address* alone (`authority-rulings.md` Q10). F101’s recommended constructor normalization would change address retention and diverge from Rust; stopped rather than reverse T28. |
| **A002** | CONFIRMED | Pre-fix `isProvedMerge` (`client.ts:804-818`) only checked `outputHash` / `data.outputUtxoHash`. `isProvedMergeZone` required `isProvedMerge` **plus** a string `zoneProgramId`, so every zone object satisfied the plain guard. `finishMergeSubmissionUnsigned` therefore accepted a zone proved object. Guards were not mutually exclusive. |
| **F120** | CONFIRMED | `standard-accounts.ts` local `decodeBase58` (pre-fix) used `alphabet.indexOf` without rejecting `-1`, started from `[0]` so empty input became `[0]`, and never checked length 32. `instructions.ts` already validated alphabet + length. |

## Fixes landed (one commit each)

| Commit | Finding |
|--------|---------|
| `0a520018` | F131 — `createExternalData` forces unset settlement accounts when the matching public amount is absent; `finalizeTransfer` routes through `withPublicSol` / `withPublicSpl`; Rust oracle `settlementBinding` + TS parity tests; Rust unit test on zero-amount finalize |
| `9c0c7611` | A002 — shared `hasProvedMergeShape`; plain requires `zoneProgramId` absent; zone requires string `zoneProgramId`; cross-rail rejection tests |
| `9f734ecf` | F120 — export `decodeBase58Address`; `standard-accounts` reuses it; refusal tests for empty / invalid alphabet / short input |

## Deliberately not fixed

- **F101** — already implemented on the resolve paths that Rust uses. Applying the finding’s constructor-side drop would reverse T28’s zone-address clause and diverge from Rust `Utxo` field retention. No code change.

## Owner rulings needed

None. F101’s recommended constructor change would need an owner ruling that explicitly revisits T28 / Rust `Utxo` construction; not taken here.

## Checks run

- `ZOLANA_WRITE_TS_ORACLES=1 cargo test -p zolana-transaction --test ts_oracle` — pass (regenerated `settlementBinding`)
- `cargo test -p zolana-transaction zero_amount_withdrawal_leaves_settlement` — pass
- `npm run build` then vitest: `rust-oracle.test.ts`, `transfer.test.ts`, `merge.test.ts`, `test-kit.test.ts` — pass
- `cargo fmt --all` before commits
