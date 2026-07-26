# Reject / tamper fixtures for indexer-api and smart-account-client

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-reject` |
| Branch | `port/reject-fixtures` |
| Measured at | 2026-07-26 |
| Scope | Full SDK gate line: fixture provenance + rejection/tamper coverage for `@zolana/indexer-api` and `@zolana/smart-account-client` |

## Verdict

**Gate line closes.** Provenance was already closed. The rejection/tamper gap
named in [gate-ledger.md](gate-ledger.md) is closed by two Rust-generated gated
vectors, the same pattern as `poseidon-parity` and `proof-response-parity`.

No Rust-versus-TypeScript accept/reject disagreement was found.

## What was missing

Both packages shipped success-shape P00 fixtures
(`fixtures/indexer-api/schema-v1.json`,
`fixtures/smart-account-client/standard-create-v1.json`) and rejected malformed
input only in hand-written TypeScript unit tests. Those tests prove TypeScript
refuses something; they do not prove it refuses what Rust refuses.

## Artifacts

| Package | Generator | Vector | Tests |
| --- | --- | --- | --- |
| `@zolana/indexer-api` | `xtask/src/bin/indexer-schema-rejects.rs` | `sdk-libs/ts/vectors/indexer-schema-rejects-v1.json` | `indexer-api/test/vectors/schema-rejects.test.ts` |
| `@zolana/smart-account-client` | `xtask/src/bin/smart-account-rejects.rs` | `sdk-libs/ts/vectors/smart-account-rejects-v1.json` | `smart-account-client/test/vectors/rejects.test.ts` |

Both generators are listed in `sdk-libs/ts/config/fixtures-check.mjs` and support
`--check`. Bodies live under `vectors/` (not `fixtures/`) so they do not need a
P00 envelope; putting a non-P00 certification vector under `fixtures/` fails
`ts-fixtures` with a missing-`id` / provenance error.

## Cases added

### `@zolana/indexer-api` — from `sdk-libs/indexer-api` `Deserialize`

Derived by calling production serde on wire JSON, not by copying TypeScript
checks.

| Group | Count | Sources |
| --- | --- | --- |
| Scalars | 5 | `Base64String`, `Hash`, `Limit` refusals |
| Rejects | 25 | request/response families: bad cursor/limit/address/signature, wrong types, unknown fields (`deny_unknown_fields`), integer bounds, decimal string on bounded `leaf_index`, inclusion-only field on non-inclusion proofs |
| Tampers | 4 | mutate a previously accepted merkle/encrypted/rings/non-inclusion body |
| Accepts | 8 | control bodies the tampers start from, plus unbounded decimal-string integers Rust already accepts |

Rust sources: `sdk-libs/indexer-api/src/lib.rs`,
`sdk-libs/indexer-api/src/integer.rs`.

### `@zolana/smart-account-client` — from `checked_u8` / builders

Derived by calling `create_smart_account_ix` / `execute_sync_ix` under
`catch_unwind`. Rust refuses overflows by panic; TypeScript maps the same
inputs to `SmartAccountClientError`.

| Group | Count | Sources |
| --- | --- | --- |
| Accepts | 8 | empty/duplicate/zero-threshold create shapes; 255 signers/inners; 255 repeated accounts-per-ix; 256 compiled accounts; duplicate execute signers |
| Rejects | 5 | 256 signers; 256 inners; 256 accounts-per-ix (repeated key); 257 compiled accounts; **255 distinct accounts** (compiled overflow via vault+program) |
| Tampers | 1 | XOR first create data byte; regenerating from the same inputs restores canonical bytes |

Rust source: `sdk-libs/smart-account-client/src/lib.rs` (`checked_u8`,
`compile_instructions_to_payload`).

Integer-range refusals that exist only as TypeScript adaptations of Rust's
typed parameters (`settingsSeed` as `u128`, `timeLock` as `u32`, …) are not
rejection fixtures: Rust cannot be asked those values at runtime. They remain
in hand-written `boundaries.test.ts`.

## Findings

**No accept/reject divergence.** Every generated case that Rust accepts is
accepted by TypeScript; every case Rust refuses is refused by TypeScript.

Noted while deriving cases (not a disagreement):

- The TypeScript “255 accounts per instruction” boundary uses a **repeated**
  account key. Feeding 255 **distinct** keys makes Rust refuse with
  `compiled account count exceeds u8` (vault + program + 255 = 257). TypeScript
  also refuses that input (`SMART_ACCOUNT_TOO_MANY_ACCOUNTS` when the compiled
  list grows past 256). Both sides refuse; the fixture records the distinct-key
  overflow separately from the repeated-key length overflow.

## Commands

After `npm install` and `npm run build` in this worktree:

| Command | Result |
| --- | --- |
| `npm run build && npm run test:unit` | **pass** — 2359 passed, 9 skipped (was 2301 before these 58 vector cases) |
| `npm run check:static` | **pass** |
| `npm run fixtures:check` | **pass** — includes `indexer-schema-rejects` and `smart-account-rejects` `--check`, then `fixture provenance ok` |
| `npm run check:packaging` | **pass** |

## Commits on this branch for this cluster

1. `1ab58c2e` — `feat(xtask): generate indexer and smart-account reject oracles`
2. `6eddfa8e` — `feat(ts): gate indexer and smart-account reject vectors`
3. `0a43d2d1` — `test(ts): replay Rust reject fixtures in indexer and smart-account`
4. (docs) checklist gate line + this report
