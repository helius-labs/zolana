# Full SDK parity gates - adjudication

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-ts-gates` |
| Branch | `port/gates` |
| Measured revision | `34361e5e1e364b6ac67bcdf763fff4943191e87b` |
| Measured at | 2026-07-26 |
| Scope | The seven top-level gates at `review-checklist.md` lines 709-715 |
| Method | Read-only adjudication against this tree and committed planning evidence. No SDK code changes. `npm install` and `npm run build` succeeded before command citations. |

Verdict vocabulary:

- **HOLDS** - regenerable evidence on this revision supports the gate as written.
- **PARTIAL** - a named subset holds; a named remainder does not.
- **OPEN** - the gate does not hold. Where a mechanism exists but has no recorded execution on this revision, that is stated as "implemented but never run."

No gate below is marked HOLDS. No checkbox in `review-checklist.md` was checked.

This adjudication is consistent with
[`certification-evidence.md`](../certification-evidence.md) on cryptographic
scope (P3 does not certify; P5 / program execution is a hole; P4 full matrix
was not the certification pass). Disagreements with that packet are listed at
the end; they are revision drift and one repaired import path, not a reason to
raise any of these seven gates.

---

## Gate 1 - Each of the nine packages passes its package gates

**Verdict: OPEN**

### Count is stale

The gate text still says "nine packages." On this revision the npm workspace
lists **eleven** packages in root `package.json`:

`hasher`, `interface`, `keypair`, `transaction`, `indexer-api`, `api`,
`client`, `wallet`, `merkle-tree`, `smart-account-client`, `test-kit`.

The primary-queue dependency order in `review-checklist.md` still names the
original nine Rust-facing packages (interface through wallet, including
merkle-tree / indexer-api / smart-account-client / API). `@zolana/hasher` and
`@zolana/test-kit` are additional TypeScript workspaces with no seat in that
"nine." Any claim that "the nine packages" pass must first say which set is
meant.

### Package completion gates themselves do not pass

The package-completion block (`review-checklist.md` lines 684-702) is the
definition of "passes its package gates." On this revision those items remain
unchecked, and at least two are openly unmet by the production-readiness
register:

| Package-gate item | Evidence it is not closed |
| --- | --- |
| Browser-capable packages execute vector suites in a headless browser | [G9-4](../production-readiness-issues.md#g9-4-browser-support-is-checked-statically-not-in-a-browser-medium): `browser-check.mjs` is a static forbidden-import / bundle scan, not Chromium execution of keypair or transaction vectors. |
| Each public secret-adjacent accessor has an aliasing test | [G6-2](../production-readiness-issues.md#g6-2-defensive-copy-discipline-is-not-uniformly-verified-medium): `copyBytes` is used on some paths; there is no suite that mutates each returned buffer from the public accessor set and asserts internal state. Isolated copy tests exist (for example `secret-lifecycle-certification.test.ts`), not the gate's full accessor census. |

Row-level status is not a substitute. Recounted from the primary tables on this
revision: 135 `done`/`PARITY`, 7 `done`/`NOT_APPLICABLE`, 3
`needs_re_review`/`NOT_APPLICABLE`, 0 adverse. That clears the "no
`PARTIAL`/`MISSING`/..." package-gate line for the queue, and it does not clear
G9-4, G6-2, or the other unchecked package-gate lines (fixture freshness per
package, rejection/tamper coverage, browser entry points, pack checks as a
per-package claim).

### Smallest close

1. Restate the gate for the eleven workspaces (or explicitly exclude `test-kit`
   as annex-only and name the ten publishable packages).
2. Close G9-4 (headless Chromium run of keypair and transaction vectors) and
   G6-2 (aliasing census), then walk the remaining package-gate bullets with
   named evidence per package - not a roll-up from the 145-row table.

---

## Gate 2 - Cross-package public types, errors, dependencies, and capability boundaries match current Rust

**Verdict: PARTIAL**

### What holds

- Dependency and export structure is gated:
  `npm run test:dependencies`, `npm run test:exports`, `npm run api:check`, and
  `npm run check:packaging` are real scripts on this tree (verified present;
  packaging was green in the checklist's known-commands block at earlier HEADs;
  not re-run as a release claim here beyond `npm run build`).
- Primary rows that own cross-package surfaces are at `PARITY` or justified
  `NOT_APPLICABLE` with no adverse verdict in the table (recount above).
- Capability and error certification suites exist:
  `keypair/test/vectors/capability-boundary-certification.test.ts`,
  `trait-surface.test.ts`, `error-redaction-certification.test.ts`
  ([`crypto-certification-b.md`](crypto-certification-b.md), K9/K10).

### What does not hold

Named residuals recorded as accepted or pinned, not cleared:

| Residual | Why it blocks "match current Rust" |
| --- | --- |
| `KEYPAIR_HASH` at empty-slice merge ciphertext hash | TypeScript reports `KEYPAIR_HASH` (`rustVariant` null); Rust returns `Poseidon` ([`certification-evidence.md`](../certification-evidence.md) residual 8; K10). |
| Capability types still admit `Promise` | `ViewingKeyLike` / `ShieldedKeypairLike` declare `T \| Promise<T>` after the ruling against out-of-process backends; the suite catches promise-returning implementations, not the wide type (residual 10; K9). |
| `address-append` has no TypeScript path | Eighth prover circuit; owner-ruled omission, still a cross-language capability hole (residual 5). |
| P3 G2 compress divergence | TypeScript refuses some off-curve G2 points Rust's host compress accepts; P3 **does not certify** (residual 1; [`pkp-p3.md`](pkp-p3.md)). |

These are not "two files look similar." They are recorded divergences. The gate
asks for a match; a match with pinned exceptions is PARTIAL, not HOLDS.

### Smallest close

Resolve or formally accept-with-ledger each residual above at the same altitude
as the gate (errors, capabilities, dependencies). Minimum code closes for a
strict match: align the merge-hash error variant; drop `Promise` from capability
return types; keep `address-append` as an explicit documented non-goal if the
owner still refuses a port - but then the gate text must carve that non-goal out
rather than claim a full match.

---

## Gate 3 - Deposit, private transfer, withdraw, split, merge, registration, sync, and submission flows have current-Rust coverage without behavior-hiding stubs

**Verdict: OPEN**

### Construction coverage exists; proving and chain submission do not, without stubs

`sdk-libs/ts/e2e/actions/actions.test.ts` routes deposit, transfer, withdrawal,
split, merge creation, registration transaction build, and `syncWallet` through
production APIs against fixtures / `TestRpc` / fixture indexers. That is
current-Rust *construction* coverage, not end-to-end flow coverage.

The only merge **submission** path in that suite builds a `ProverClient` whose
`fetch` is `vi.fn(() => Promise.resolve(proofResponse(...)))`
(`actions.test.ts` around the "creates and submits a merge through the
production pipeline" case). That is exactly a behavior-hiding stub for the
prover. `wallet/test/submit.test.ts` likewise uses `proverFetch = vi.fn(...)`.

### Live action suite does not cover the named spend flows

`sdk-libs/ts/e2e/actions/live.test.ts` starts a same-revision local stack
(validator, Photon, prover via `@zolana/test-kit`) and exercises registration,
merge opt-in, and idempotent ATA creation only. It does not deposit, privately
transfer, withdraw, split, or merge with a real proof.

### Instruction e2e is not a substitute

`sdk-libs/ts/e2e/instructions/acceptance.test.ts` matches fixture instruction
bytes and messages. `instructions/live.test.ts` rejects a wrong external
signature against an isolated stack. Neither is deposit -> prove -> submit ->
confirm -> sync for the named flows without stubs.

### On this revision, prove-to-chain is absent

`sdk-libs/ts/e2e/actions/prove-to-chain.live.test.ts` is **not** in this tree.
[`certification-evidence.md`](../certification-evidence.md) **HOLE-P5** and
[`pkp-p4.md`](pkp-p4.md) both record that P4 used synthetic trees and did not
execute the shielded-pool program. Production-readiness [G4-2](../production-readiness-issues.md)
still describes the live suites as not sending a proof through the pool.

### Smallest close

Land and green a prove-to-chain suite that runs deposit, private transfer,
withdraw (and the other named flows) against the same-revision local stack with
a real prover and real Photon, and remove or demote any path whose only
submission evidence is a mocked `ProverClient.fetch`. Owned in substance by
suite P5 / PKP-07 (`port/pkp-p5`); not present on `34361e5e`.

---

## Gate 4 - Instruction bytes execute against same-revision Solana programs

**Verdict: OPEN (owned by P5)**

### Evidence on this revision

- No `row-updates/pkp-p5.md` in this worktree.
- No `prove-to-chain.live.test.ts`.
- P4 certification ([`pkp-p4.md`](pkp-p4.md),
  [`certification-evidence.md`](../certification-evidence.md) residual 6 /
  HOLE-P5): live proofs verify through `groth16-solana` with embedded keys;
  trees are synthetic; no deposit / index / transact on a validator.

Instruction byte *assembly* against Rust fixtures (interface codecs, wallet
deposit vectors, instruction acceptance fixtures) is not program execution.

### Sibling branch (not evidence for this tree)

`port/pkp-p5` carries commits not in `34361e5e` (including
`e6665776` prove-to-chain and `a63a5b96` P5 report). That branch's report is
out of scope for checking this gate on `port/gates`. Disposition here stays
**OPEN / P5-owned** until that work is merged and re-measured on this branch.
Do not guess a post-merge verdict from the sibling tip: even that tip's own
report distinguishes hybrid compression from a pure TypeScript wire path.

### Smallest close

Merge P5's prove-to-chain evidence into this line of development, re-run the
named command from its report on a clean checkout of the merge revision, and
only then re-adjudicate. Closing action is owned by `port/pkp-p5`, not by
editing this checklist ahead of the merge.

---

## Gate 5 - Proof inputs work with the same-revision prover for each supported shape and rail

**Verdict: OPEN (implemented but never run for the full matrix on this revision)**

### Mechanism exists

`@zolana/client` defines:

- `npm run test:p4` - oracle self-check without a prover;
- `npm run test:p4:live` - fast live gate;
- `npm run test:p4:full` - `ZOLANA_TEST_P4=1` and `ZOLANA_TEST_P4_FULL=1`.

`sdk-libs/ts/client/test/vectors/cryptographic-verification.test.ts` expands
confidential cases to each entry of `SPP_SUPPORTED_SHAPES` on both `eddsa` and
`p256` when `FULL` is set, and under `FULL` also expands zone both rails,
zone-authority's four squares, and merge-zone.

### What has been executed

[`pkp-p4.md`](pkp-p4.md) / certification matrix P4: fast live gate only:

- confidential Ed25519 1x1 and 2x3;
- confidential P256 2x3;
- zone Ed25519 1x1;
- zone-authority 1x1;
- merge 8x1.

Explicit statement in that report and in
[`certification-evidence.md`](../certification-evidence.md) residual 7:
`ZOLANA_TEST_P4_FULL=1` was **not** executed in the P4 certification pass.

This adjudication did not run `test:p4:full` (long prover-key load). Absence of
a committed pass record on this revision is enough to refuse HOLDS for "each
supported shape and rail."

### Smallest close

Run and record `ZOLANA_PORT_OFFSET=<offset> npm run test:p4:full --workspace
@zolana/client` to green on a named revision (or accept a merged P5 report that
already did so, after that revision is an ancestor of the claim). Mechanism
without execution does not close the gate.

---

## Gate 6 - Indexer requests and responses match the same-revision live Photon contract

**Verdict: OPEN**

### What is strong (and insufficient)

- Photon imports `zolana-indexer-api` types and returns those structs
  (checklist row X01; Photon `Cargo.toml` workspace dependency). Schema
  agreement with Rust is by construction, and TypeScript tracks that crate.
- TypeScript coverage is fixture- and mock-fetch based:
  `client/test/indexer-parity.test.ts`, `indexer-client.test.ts`,
  `indexer-api` schema/vector/integer-domain tests, frozen
  `fixtures/client/rpc-indexer-v1.json`.

### What the gate requires

The gate names the **live Photon contract**, not the Rust crate Photon
imports. Historical review evidence still stands and was not superseded on this
tree:

- `planning/typescript-sdk-port/log/2026-07-25T1323-c04.md`: "no live Photon
  contract test exists."
- X01's earlier gap text (still visible in the row's history): exhaustive
  rejection and live-Photon evidence missing; later reconciliation closed the
  authority question without adding a live contract suite.

Live stacks (`startLocalStack`) boot Photon for registration / ATA tests and
readiness probes. They do not assert that TypeScript-encoded requests and
decoded responses match what the running same-revision Photon binary accepts and
emits for `getEncryptedUtxosByTags`, `getShieldedTransactionsByTags`,
`getMerkleProofs`, and `getNonInclusionProofs`.

### Smallest close

Add a live suite that, against `startLocalStack`'s Photon on a fixed port
offset, drives those four indexer calls (and any other production indexer call
TypeScript ships), and compares request bodies / response decoding to the live
process (not to a `vi.fn` envelope). That Photon compiles against the Rust
`zolana-indexer-api` crate does not satisfy this gate's wording by itself.

---

## Gate 7 - EdDSA and P256 rails cover the complete supported shape set

**Verdict: PARTIAL**

### What holds (deterministic coverage, executed)

- Canonical list: `SPP_SUPPORTED_SHAPES` in `interface/src/shape.ts` is ten
  shapes; `interface/test/vectors/rust-oracle.test.ts` and row I02 compare that
  ordered list and first-cover selection to Rust.
- Public-input assembly: suite P1 /
  `client/test/vectors/public-input-assembly.test.ts` against
  `vectors/public-input-assembly-v1.json` covers confidential shapes on both
  rails ([`pkp-p1.md`](pkp-p1.md); certification matrix **Certifies**).
- Prover request JSON: P2 covers TypeScript-reachable confidential shapes on
  both rails ([`pkp-p2.md`](pkp-p2.md)).
- Zone assembly oracles cover the ten shapes on both zone rails
  (`zone-oracle.test.ts` / client batch B notes on C13-C14).

So both ownership rails **declare and assemble** the complete confidential
supported shape set; that part has been run in ordinary unit/vector CI, not
merely sketched.

### What does not hold (live prove completeness)

"Cover" in the certification sense used beside gate 5 also means the shapes
prove. On this revision the live prover matrix for the ten confidential shapes
on both rails is the same unfinished execution as gate 5: implemented behind
`ZOLANA_TEST_P4_FULL=1`, with no recorded green run on this branch. Fast-gate
live prove exercises three confidential shape/rail pairs, not twenty.

Gate 7 is therefore PARTIAL rather than HOLDS: structural and oracle coverage
are real; live completeness is not.

### Smallest close

Same execution as gate 5's close (`test:p4:full` recorded green), after which
this gate can be re-adjudicated to HOLDS if the confidential EdDSA and P256
rows in that matrix are included. No additional product feature is required for
the confidential rails beyond running what is already written.

---

## Checklist edits

None. All seven gates remain unchecked in `review-checklist.md`. A checked box
without HOLDS evidence would invert the purpose of this list.

---

## Consistency with `certification-evidence.md`

| Topic | Packet claim | This adjudication |
| --- | --- | --- |
| P5 / program execution | HOLE-P5, does not certify | Agree for this tree (gate 4 OPEN, P5-owned). |
| P4 full matrix | Not run in certification pass | Agree (gates 5 and 7). |
| P3 | Does not certify (G2 compress) | Agree; feeds gate 2 PARTIAL. |
| P2 fixture import path | Broken (`fixtures/client/public-input-assembly-v1.json`) | **Disagree for this revision:** `prover-request-parity.test.ts` imports `vectors/public-input-assembly-v1.json`, and that file exists. Treat the packet's collection failure as measured on `882d5e1e` / `port/pkp-p8`, not as current on `34361e5e`. |
| Static gate red | Eight lint errors | **Possibly stale relative to this tree.** Checklist known-commands block claims `lint:packages` clean after `db7a6981`. Not re-litigated here; neither claim closes any of the seven gates. |
| Measured revision | `882d5e1e` on `port/pkp-p8` | Different worktree and commit than this adjudication. Do not reuse packet digests as proof that these gates hold on `port/gates`. |

The packet does not overclaim that the seven full-SDK gates hold. It correctly
refuses "complete proof and key-handling parity" and "P5 certified." The
main caution for a release reviewer is revision drift (P2 path, static lint)
and the temptation to treat package-row `PARITY` counts as gate 1.

---

## Largest single blocker to a full parity claim

**Same-revision prove -> submit -> shielded-pool program acceptance without
stubs or hybrid compression escape hatches (gates 3 and 4), owned by P5.**

Even after that lands, gates 1 (package gates including browser and aliasing),
5 (full live shape matrix execution on the claim revision), and 6 (live Photon
contract suite) remain independently open. The row table being empty of adverse
verdicts does not move these seven gates.
