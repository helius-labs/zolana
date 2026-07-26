# Gate 6 — live Photon contract suite

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-ts-gate6-photon` |
| Branch | `port/gate6-photon` |
| Gate | Indexer requests and responses match the same-revision live Photon contract |
| Measured at | 2026-07-26 |

## Verdict

**Live Photon contract matches what the TypeScript client expects: yes.**

Every production indexer method was exercised against `just build-photon`'s
same-revision binary (`target/debug/photon`) through `@zolana/api` and
`ZolanaIndexer`. The client's method descriptors decode the live payloads, and
raw wire inspection confirms the field names and integer encodings the decoders
depend on.

No Photon-side disagreement was found that would require an owner judgment call.
Safe-range integers arrive as JSON numbers (Photon's plain serde / Light
`UnsignedInteger` serialize path). The TypeScript decoder's string union for
unbounded fields remains a reader tolerance for values past `2^53`, exercised by
unit tests; live Photon does not emit those strings for ordinary slots and
block times.

## What closed the gate

| Item | Evidence |
| --- | --- |
| Suite | `sdk-libs/ts/e2e/photon/photon-contract.live.test.ts` |
| Runner | `npm run test:e2e:photon` (`ZOLANA_PORT_OFFSET=800`) |
| CI | Appended to `check:e2e` in the existing `typescript / e2e` job (already builds Photon, programs, prover) |
| Light precedent | `js/stateless.js/tests/e2e/rpc-interop.test.ts` — live Photon, production client, field-level asserts after real chain activity |

Methods covered (every request `@zolana/api` ships):

1. `get_encrypted_utxos_by_tags`
2. `get_shielded_transactions_by_tags`
3. `get_merkle_proofs`
4. `get_non_inclusion_proofs`
5. `get_nullifier_queue_elements`

Contract surfaces asserted (not merely HTTP 200):

- Empty-result shapes (`matches` / `transactions` / `elements` arrays, `context.block_time`)
- JSON-RPC error shapes (empty tags, limit `> PAGE_LIMIT`, unknown tree, missing leaf)
- Pagination (`limit: 1`, `next_cursor` round-trip, omitted limit accepted)
- Populated deposits: wire field names (`block_time`, `tx_signature`, `output_slot`, …), integer wire types as JSON numbers, decoder → `bigint`, `ZolanaIndexer` conversion
- Body size stays under the 10 MiB client cap (F121)
- Request encoding via `encodeRequest` accepted by live Photon

Seeding: protocol config + pool tree + registration + three SOL deposits, then
wallet sync through Photon — the same path Light uses (compress / transfer then
query), without stubs.

## Control edits (suite can go red)

| Edit | Result |
| --- | --- |
| Expect `context` keys `["blockTime"]` instead of `["block_time"]` | 6/11 failed — live wire is snake_case `block_time` |
| Expect `typeof block_time === "string"` instead of `"number"` | 7/11 failed — live Photon emits a JSON number for safe-range values |

Both edits were reverted. A suite that cannot detect those breaks would not
close this gate.

## Cost

| Metric | Value |
| --- | --- |
| Wall time (warm binaries, offset 800) | ~28 s for 11 tests (one stack start) |
| CI incremental cost | One additional stack start after actions + instructions in the existing e2e job |
| Prerequisites | `just build-programs`, `just build-photon`, `just build-prover-server`, Squads dump (already required by `typescript / e2e`) |

Port offset **800** is reserved for this suite (300 actions, 400 instructions,
500 P5 / user-registry; 600 was occupied by a concurrent worktree during
development).

## Checks

| Command | Result |
| --- | --- |
| `ZOLANA_PORT_OFFSET=800 npm run test:e2e:photon` | 11 passed |
| `npm run test:unit` | 2226 passed (no regression) |
| `npm run check:static` | Same 7 pre-existing errors in `g2-compression-live.test.ts` (other worker); no new static failures from this gate |

## Open questions

None that blocked the suite. Integer string-vs-number for values past `2^53` is
already settled by C04 / X01 (per-field union, Light-aligned); live Photon at
ordinary magnitudes emits numbers, which the suite asserts.
