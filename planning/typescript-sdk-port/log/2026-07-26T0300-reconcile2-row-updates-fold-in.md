# 2026-07-26 01:00 UTC | reconciliation: two row-update files folded, the merge-prefix cluster closed, the integer domain declined | queue-wide

- Baseline: HEAD `653db1a6`, the `ts-sdk-port` tip, reviewed and merged into `port/reconcile2`
- Worker: reconciler, third holder of the role
- Explanation: folds `row-updates/t28-zone-binding.md` and `row-updates/open-questions.md`, and the work that landed on `ts-sdk-port` while this pass ran, which changed two of its conclusions before they were written. The filename keeps the directory's local-clock ordering so this entry sorts last; the heading time is UTC.
- Evidence: the claims below were checked against code at the reviewed HEAD rather than taken from a worker's report. Commands run here: `fixtures:check`, `review-checklist-check.mjs`, `pkp-entry-gate.mjs --skip-ci`, and the five affected test files under `vitest`, 38 cases, plus the interface oracle suite, 40 cases

## The recount

Counted from the tables, not adjusted from the previous figures. The tables, the baseline block, and `pkp-entry-gate.mjs` agree.

| | Before | After |
| --- | --- | --- |
| `PARITY` | 95 | 99 |
| `PARTIAL` | 22 | 22 |
| `DIVERGENT` | 17 | 13 |
| `STALE` | 1 | 1 |
| `NOT_APPLICABLE` | 10 | 10 |
| adverse | 40 | 36 |
| `done` and `PARITY` | 95 | 98 |

Four rows closed and one left `done` without losing its verdict, which is why `PARITY` rises by four and the progress figure by three. The `pinned_divergence` status is now unused.

## What moved, and on what

The merge-prefix cluster closed on an artifact that compares acceptance rather than asserting a difference. `MERGE_ENCRYPTED_UTXO_TYPE_PREFIX` appears nowhere in `interface/src/codecs/index.ts`, and `interface/test/vectors/rust-oracle.test.ts:1005` takes Rust's own non-canonical bytes, asserts they differ from the canonical payload at exactly the prefix offset, decodes them, and re-encodes to identical bytes, on both the merge and the merge-zone codec. The program's rejection is untouched and the same test still pins it. Read at HEAD and run here.

## What was declined

The size claim, for `S01`. `52302969` put the rule in `@zolana/interface` and called it from the client, wallet, and test-kit compilers; `0e26c397` had already put a second copy in `@zolana/client`. Neither touched `smart-account-client`, which is the package this row reviews and which already refuses a payload Rust compiles. The row does not move, and the constant now exists three times in TypeScript.

The integer domain, for `C04` and `X01`. The ruled per-field union did land and is the owner's form, but the ruling branch states it did not touch `docs/spec.md`, and `docs/spec.md:1897` still restricts an RPC integer to the safe-integer range and still cites the decoder line that is now the string grammar. A row whose decoder accepts a domain the specification forbids is not at parity, so the amendment that released this finding one pass ago is credited only for its `Context` half, which did land and which TypeScript follows.

The reported red, as a premise. `api/test/transport.test.ts` "reads a u64 above the safe-integer bound without losing precision" passes at this HEAD with the other 17 in the file. The `api` package reaches `@zolana/indexer-api` through `dist`, so an unbuilt worktree fails it while the source is correct. That removes the stated blocker without changing the verdict, which rests on the specification conflict.

## Recorded without moving a verdict

`T28` keeps `PARTIAL`: the zone-binding analysis changed no behaviour, so it converts an open question into a named recommendation with the three clauses separated by who can decide them.

`A01` keeps `PARITY` and leaves `done`, the only row in the table in that combination. `quoteUnsafeIntegers` is new behaviour in its owner file and is the surviving half of the uniform integer domain the per-field ruling replaced, so the review it needs is which layer owns the rule.

`C22` keeps `PARTIAL` with a sharper finding: `public-exports.md:341` records `MERGE_INPUTS` under `@zolana/interface`, which exports no such name, while `@zolana/transaction`, which does export it, has no entry for it, and `MERGE_INPUT_COUNT` has no entry in either section. The two size exports its own package added are unledgered and unused inside it.

- Verdict: `PARITY` for `I08`, `I09`, `I20`, and `I21`, closed out of `pinned_divergence`
- Verdict: `PARITY` for `A01`, unchanged, with the row reopened to `needs_re_review`
- Verdict: `DIVERGENT` for `C04`, `X01`, and `S01`, each unchanged and each with a claim declined
- Verdict: `PARTIAL` for `C22` and `T28`, unchanged
- Gap and smallest fix: `C04` and `X01` owe the specification entry queued in `remaining-work.md`, which states the per-field integer domain the decoder implements; `S01` owes a decision on whether its compiler measures or refuses, then the shared `TRANSACTION_SIZE_LIMIT` rather than a fourth copy of 1232; `C22` owes three ledger lines and the removal of the duplicated size helper from `@zolana/client`
- Row transitions: four rows to `done`, one row out of it
- Progress: `98/145`
- Exact next file: `I07`, first at `needs_re_review` in queue order
- Full SDK parity claim: unsupported
