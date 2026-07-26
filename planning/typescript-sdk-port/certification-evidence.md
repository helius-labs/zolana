# Cryptographic certification evidence (PKP-08)

Release-reviewer packet for the Rust-to-TypeScript SDK proof and key-handling
claim defined in [`proof-and-key-parity.md`](proof-and-key-parity.md).

A reviewer who has not followed the port can reproduce the claim from a clean
checkout of this revision by reading this file and running the command ledger
below. Do not treat a green row in
[`review-checklist.md`](review-checklist.md) as cryptographic certification;
that checklist is the parity queue. This packet is the certification claim.

## How to read this packet

| Section | Purpose |
| --- | --- |
| [Certification matrix](#1-certification-matrix) | What each of K1-K10 and P1-P5 certifies, where the evidence lives, and the honest status |
| [Command-and-result ledger](#2-command-and-result-ledger) | Ordered gates a reviewer must run, with pass criteria verified against this tree |
| [Residual risk and unsupported capability](#3-residual-risk-and-unsupported-capability) | Accepted divergences, deliberate gaps, and known defects collected from the planning sources |
| [Fixture and package hashes](#4-fixture-and-package-hashes) | Digests of the artifacts this revision certifies |
| [Independent review of previously adverse rows](#5-independent-review-of-previously-adverse-rows) | Spot-check of early-closed rows that the 2026-07-25 evidence audit found unsupported |

### Claim revision

| Field | Value |
| --- | --- |
| Worktree branch | `port/pkp-p8` |
| Measured git revision | `882d5e1e13140e02c7734b76b3fcbec42204ef27` |
| Measured at | 2026-07-26 |
| Planning sources | `row-updates/` (74 reports), `authority-rulings.md`, `review-checklist.md`, suite reports `key-certification.md`, `crypto-certification-b.md`, `pkp-p1.md` … `pkp-p4.md` |

### Late-arrival holes (do not guess)

Three worker branches were still landing work when this packet was written.
Their outcomes are **not** asserted here. Fill the holes when those branches
merge; do not invent results.

| Hole id | Branch | Expected subject | Status in this packet |
| --- | --- | --- | --- |
| HOLE-P5 | `port/pkp-p5` | Suite P5: TypeScript instruction execution against the same-revision shielded-pool program | **OPEN.** No `row-updates/pkp-p5.md`. Suite P5 does not certify. |
| HOLE-STATIC-A001 | `port/static-a001` | Static gate repair and merge tree selector (A001) | **OPEN.** Tip `3e2d17b2` is not an ancestor of the measured revision. Static gate is red here (see ledger). |
| HOLE-FND-COMMIT | `port/fnd-commit` | Commitment-affecting external findings | **OPEN.** Tip carries commits not in the measured revision (`db29fcb0`, `9f734ecf`, `9c0c7611`, `0a520018`). |

---

## 1. Certification matrix

Status vocabulary used below:

- **Certifies** - suite exit criterion met for the claim it defines; named caveats are evidence limits, not open divergences.
- **Certifies with exceptions** - claim holds for the covered surface; named uncovered cases or accepted divergences remain.
- **Does not certify** - suite found a real divergence, or the suite has not landed, so the claim must not be stated as certified.

### Key-handling suites

| Suite | Certifies | Test / vector | Status |
| --- | --- | --- | --- |
| **K1** Public-key encoding and parsing | 34-byte tagged keys; prefix sweeps; P256 point checks; Ed25519 padding; length refusals; zero sentinel | Tests: `sdk-libs/ts/keypair/test/vectors/key-certification-k1-*.test.ts`. Vector: `sdk-libs/ts/vectors/key-certification-v1.json` (Rust generator `sdk-libs/keypair/tests/key_certification_vectors.rs`). Reverse: `key-certification-typescript-v1.json` + `key_certification_reverse.rs` | **Certifies.** Report: [`row-updates/key-certification.md`](row-updates/key-certification.md). |
| **K2** P256 signing and verification | RFC 6979 determinism; high-S acceptance (G2-1); adversarial `r`/`s`; prehash length and digest boundaries | Same vector file; `key-certification-k2-p256.test.ts` | **Certifies.** The earlier `z >= n` nonce divergence was closed by Rust `reduce_prehash` ([`row-updates/p256-rfc6979-reduction.md`](row-updates/p256-rfc6979-reduction.md)); the suite now requires `matchesReducedDigestSignature: true`. |
| **K3** Ed25519 signing and verification | Byte-identical signatures; Solana `verify_strict` hinge cases (G2-2) | `key-certification-k3-*.test.ts` | **Certifies.** |
| **K4** Nullifier derivation and binding | Nullifier secret/public key; BN254 boundary refusals; owner-hash binding | `key-certification-k4-*.test.ts` (consumes `@zolana/hasher`) | **Certifies.** Poseidon itself is certified under the Poseidon parity suite, not K4. |
| **K5** Viewing and transaction-viewing keys | Independent `P_const`; ECDH; five tag families; epoch rotation; scalar reduction; transaction viewing keys | `key-certification-k5-*.test.ts` | **Certifies.** |
| **K6** Transfer encryption | ECDH both directions; joint key/nonce/counter via keystream; slot endianness; truncation; wrong-key garbage | `sdk-libs/ts/keypair/test/vectors/transfer-encryption-certification.test.ts` against `sdk-libs/ts/vectors/keypair-crypto-cert-v1.json` | **Certifies with exceptions.** AES key, nonce, and counter are certified jointly through the keystream, not as three named values. Report: [`row-updates/crypto-certification-b.md`](row-updates/crypto-certification-b.md). |
| **K7** Merge verifiable encryption | Poseidon key schedule; `packInfo` / trailing `ciphertextHash` / `pack33`; truncation moves only the committed hash | `merge-encryption-certification.test.ts` | **Certifies with exceptions.** Same joint-keystream evidence limit as K6. |
| **K8** Secret ownership and lifecycle | Export independence; constructor copies; `destroy()` refuses each listed capability afterward | `secret-lifecycle-certification.test.ts` | **Certifies with exceptions.** Rust has no explicit `destroy`; wipe of private buffers is unobservable and is not claimed. |
| **K9** Capability and HSM boundaries | Non-`ViewingKey` backend satisfies the interface; no construction/secret export on capability types; no capability returns a Promise at runtime | `capability-boundary-certification.test.ts` plus `trait-surface.test.ts` | **Certifies with exceptions.** Interfaces still declare `T \| Promise<T>` even though the owner ruled out-of-process backends unsupported; the suite catches promise-returning implementations, not the wide type. |
| **K10** Error and redaction parity | Rust variant ledger; non-error CTR garbage; redaction of secrets across logger surfaces | `error-redaction-certification.test.ts` | **Certifies with exceptions.** One defect is pinned rather than fixed: empty-slice merge ciphertext hash reports TypeScript-only `KEYPAIR_HASH` where Rust returns `Poseidon` (see residual list). |

### Proof suites

| Suite | Certifies | Test / vector | Status |
| --- | --- | --- | --- |
| **P1** Public-input assembly | Named intermediate chains and final `publicInputHash` for confidential (the ten supported shapes, both rails, mixed owners), zone, zone-authority, and merge (default and zone tails) | Test: `sdk-libs/ts/client/test/vectors/public-input-assembly.test.ts`. Vector: `sdk-libs/ts/vectors/public-input-assembly-v1.json`. Generator: `xtask` bin `public-input-assembly`. Related: zone/merge oracles | **Certifies** assembly parity only. Does not ask a prover or run the program verifier. Report: [`row-updates/pkp-p1.md`](row-updates/pkp-p1.md). |
| **P2** Prover request parity | Exact request JSON bodies, key encounter order, encoding, rejection of unknown/malformed leaves; protocol revision hash of Rust `json.rs` | Test: `sdk-libs/ts/client/test/vectors/prover-request-parity.test.ts`. Fixture: `sdk-libs/ts/fixtures/client/prover-request-parity-v1.json`. Generator: `xtask` bin `prover-request` | **Certifies with exceptions.** Seven TypeScript-reachable shapes match Rust. **`address-append` has no TypeScript path** (`typescriptPaths["address-append"] = false`). Report: [`row-updates/pkp-p2.md`](row-updates/pkp-p2.md). **Gate finding on this revision:** the P2 test imports `fixtures/client/public-input-assembly-v1.json`, but that file lives at `vectors/public-input-assembly-v1.json`; `npm run test:unit` fails to collect the P2 file until that path is corrected (owned by suite maintainers, not fixed in this packet). |
| **P3** Proof response parsing and compression | Gnark parse, A negation, G1/G2 compression, rail commitment presence, rejection matrix | Tests: `proof-response-parity.test.ts`, `proof-compression.test.ts`, `proof-canonical-oracle.test.ts`, `g2-eip197-limbs.test.ts`. Vectors: `proof-response-parity-v1.json`, `g2-eip197-live-v1.json`. Generator: `xtask` bin `proof-response-parity` | **Certifies with exceptions.** G2 compress matches the Solana syscall after the gnark `c1`-first limb fix ([`g2.md`](row-updates/g2.md)); off-curve G2 is a shared accept under the same range check, not a language divergence. Remaining exceptions: shared acceptance of unknown response fields; unavailable `y1 == 0` G2 parity branch. Report: [`row-updates/pkp-p3.md`](row-updates/pkp-p3.md), [`row-updates/g2.md`](row-updates/g2.md), [`row-updates/fnd-d5.md`](row-updates/fnd-d5.md). |
| **P4** Cryptographic verification | TypeScript witness to pinned local prover to parse/compress to Rust `groth16-solana` oracle with embedded release verifying keys; rejection mutations | Test: `sdk-libs/ts/client/test/vectors/cryptographic-verification.test.ts`. Scripts: `npm run test:p4` / `test:p4:live` / `test:p4:full` in `@zolana/client`. Oracle: `xtask` bin `groth16-verify` | **Certifies with exceptions** for the fast live gate (Ed25519 1x1 and 2x3, P256 2x3, zone 1x1, zone-authority 1x1, merge 8x1). Does **not** certify instruction execution against the shielded-pool program (that is P5 / HOLE-P5). Full shape matrix behind `ZOLANA_TEST_P4_FULL=1` was not run in the suite report. TypeScript G2 compression no longer needs the Rust oracle for live points ([`g2.md`](row-updates/g2.md)); the oracle fallback remains as a regression path. Report: [`row-updates/pkp-p4.md`](row-updates/pkp-p4.md). |
| **P5** End-to-end proof flows | TypeScript wallet intent through authority, witness assembly, pinned prover, parse/compress, instruction submit, local validator, shielded-pool state transition, indexer observation, and wallet sync, with no stubs | Required by [`proof-and-key-parity.md`](proof-and-key-parity.md#p5-end-to-end-proof-flows); e2e harness under `sdk-libs/ts/e2e/` | **Does not certify.** **HOLE-P5:** closing report and program-execution evidence are owed by `port/pkp-p5`. Existing e2e action/instruction suites are not a substitute for the P5 family matrix. |

### Matrix summary for citation

Do **not** cite "the fifteen suites are certified." On this revision:

- Suites that certify (possibly with named exceptions): K1-K10, P1, P2, P3, P4.
- Suites that **do not** certify: **P5** (not landed).

---

## 2. Command-and-result ledger

Run from the repository root. Install Node dependencies once (`npm install`).
Prefer `just` recipes for Rust and localnet so `ZOLANA_PORT_OFFSET` from a local
`.env` is applied (see root `CLAUDE.md`).

Commands below were checked against `package.json`, `sdk-libs/ts/client/package.json`,
`sdk-libs/ts/config/fixtures-check.mjs`, and the root `justfile` on the measured
revision. Pass criteria describe what success looks like; measured results on
this worktree are recorded where a gate was executed.

### 0. Prerequisites

| Step | Command | Pass looks like |
| --- | --- | --- |
| 0.1 Node install | `npm install` | Completes with exit 0 |
| 0.2 Port isolation | Copy `.env.example` → `.env` and set e.g. `ZOLANA_PORT_OFFSET=100` when another clone is live | Offset 100 → RPC 8999, Photon 8884, prover 3101. `just` exports `ZOLANA_PROVER_URL`. Running `cargo test` outside `just` does not load `.env` |

### 1. TypeScript build (required before each TypeScript gate)

| Step | Command | Pass looks like | Measured here |
| --- | --- | --- | --- |
| 1.1 Build | `npm run build` | Exit 0; packages emit `dist/` | Pass |

### 2. Unit and vector suites

| Step | Command | Pass looks like | Measured here |
| --- | --- | --- | --- |
| 2.1 Unit | `npm run test:unit` | Vitest exit 0; each collected file passes | **Not green on this revision.** Collection fails for `prover-request-parity.test.ts` (wrong fixture path: imports `fixtures/client/public-input-assembly-v1.json`, file is under `vectors/`). Other files reported 2021 passed when collection continued. Treat as a known-open suite defect, not as certification green. |
| 2.2 Vectors | `npm run test:vectors` | Exit 0 across workspaces that define the script | Not re-run in full here; required for release |
| 2.3 Property / cross / prover | `npm run test:property`, `npm run test:cross`, `npm run test:prover` | Exit 0 | Required for release; aggregate is `npm run check:suites` |
| 2.4 Key certification (focused) | `cargo test -p zolana-keypair --test key_certification_vectors` then `cargo test -p zolana-keypair --test key_certification_reverse`; in `sdk-libs/ts/keypair`, `npm run test:vectors` | Exit 0 | Documented in K1-K5 report |
| 2.5 Crypto certification K6-K10 | `cargo test -p zolana-keypair --test crypto_certification`; in keypair package, vitest certification files | Exit 0 | Documented in K6-K10 report |
| 2.6 P4 oracle-only (no prover) | `npm run test:p4 --workspace @zolana/client` | Oracle self-check and rail/shape mismatch cases pass | Script exists |
| 2.7 P4 live (needs prover) | `ZOLANA_PORT_OFFSET=<offset> npm run test:p4:live --workspace @zolana/client` with prover at the offset URL | Fast-gate shapes listed in P4 report verify | Needs local prover; not asserted as green in this packet |
| 2.8 P4 full matrix | `ZOLANA_PORT_OFFSET=<offset> npm run test:p4:full --workspace @zolana/client` | Full confidential/zone/merge-zone matrix | Slower job; not run in the P4 report |

### 3. Static gate

| Step | Command | Pass looks like | Measured here |
| --- | --- | --- | --- |
| 3.1 Static | `npm run check:static` | Each of `build`, `typecheck`, `lint`, `lint:packages`, `format:check` exits 0 | **RED.** `npm run lint:packages` reports **8 errors** (exit 1): unnecessary `String()` in `proof-response-parity.test.ts`; unsafe typed fixture imports in `prover-request-parity.test.ts` (4); `require-await` on `userRecordAddress` in wallet and test-kit; non-null assertion in `wallet/test/sync.test.ts`. **HOLE-STATIC-A001** owns the repair. Do not treat static green as part of this packet's claim. |

### 4. Fixtures drift gate (registered generators)

| Step | Command | Pass looks like |
| --- | --- | --- |
| 4.1 Fixtures | `npm run fixtures:check` (alias `npm run check:fixtures`) | Each `xtask` generator listed in `sdk-libs/ts/config/fixtures-check.mjs` runs with `--check` and exits 0 |

Generators registered on this revision (order is the gate order):

`merkle-semantics`, `poseidon-parity`, `program-libs-parity`, `proof-response-parity`, `prover-request`, `public-input-assembly`, `retry-schedule`, `solana-rpc-groups`, `solana-rpc-reads`, `solana-rpc-send`, `ts-fixtures`, `ts-interface-oracle`, `wallet-actions`, `wallet-sync-tags`.

A generator present under `xtask/src/bin/` but missing from that list is ungated; a reviewer should fail the claim if that happens after a merge.

### 5. Packaging gate

| Step | Command | Pass looks like | Measured here |
| --- | --- | --- | --- |
| 5.1 Packaging | `npm run check:packaging` | Inventory, exports, dependencies, API extractor, browser check, and `pack:check` exit 0 | `pack:check` alone passed after build |
| 5.2 Pack only | `npm run pack:check` | Packed tarballs contain only `package.json` + `dist/**`; Node and browser consumers resolve exports | Pass |

### 6. Rust workspace tests

| Step | Command | Pass looks like |
| --- | --- | --- |
| 6.1 SDK libs | `just test-sdk-libs` | Exit 0 |
| 6.2 Client integration (prover) | `just test-client-integration` | Exit 0; uses `ZOLANA_PROVER_URL` from offset |
| 6.3 Programs (optional breadth) | `just test-programs` after `just build-programs` | Exit 0 |
| 6.4 Aggregate check | `just check-all` | Exit 0 |

### 7. Localnet and prover flows

Isolate each local stack with `ZOLANA_PORT_OFFSET` so clones do not contend on
RPC 8899 / Photon 8784 / prover 3001.

| Step | Command | Pass looks like |
| --- | --- | --- |
| 7.1 Action e2e | `ZOLANA_PORT_OFFSET=300 npm run test:e2e:actions` | Exit 0 (suite asserts its own offset and starts services) |
| 7.2 Instruction e2e | `ZOLANA_PORT_OFFSET=400 npm run test:e2e:instructions` | Exit 0 |
| 7.3 Aggregate e2e | `npm run check:e2e` | Both of the above |
| 7.4 P5 prove, submit, and verify on a local validator | **HOLE-P5** - command and pass criteria to be filled by `port/pkp-p5` | Until filled, P5 remains uncertified |
| 7.5 Localnet recipes (Rust) | e.g. `just test-spp-validator` with offset set in `.env` | Exit 0; same-revision Photon via `just build-photon` |

### 8. Aggregate TypeScript check

| Step | Command | Pass looks like |
| --- | --- | --- |
| 8.1 Full check | `npm run check` | `check:static` ∧ `check:suites` ∧ `check:packaging` ∧ `check:fixtures` ∧ `check:e2e` |

On this measured revision, step 8.1 **cannot** pass because step 3.1 is red and
step 2.1 has a known collection failure. Record that as open CI debt under
HOLE-STATIC-A001 and the P2 path finding, not as a silent pass.

---

## 3. Residual risk and unsupported capability

Each item is something a release reviewer must still know after the matrix is
read. Sources are cited so the claim can be re-derived.

### Cryptographic residuals

1. **Off-curve G2 at compress — closed (was misrecorded as a divergence)**  
   - **What was wrong:** TypeScript read gnark Fq2 limbs `c0`-first while gnark writes `c1`-first, so noble's curve check ran on a different off-curve point. That was framed as a deliberate fail-fast versus Solana `Validate::No`; it was a parsing bug.  
   - **End state:** Compression keeps only the field-range check `alt_bn128_g2_compress_be` performs; curve validity is deferred to on-chain verify. Fixture id `off-curve-g2-compress-shared-accept`, disposition `match-syscall-range-check`. Live prover B points compress in pure TypeScript.  
   - **Affects:** None as residual risk; kept here so release readers do not revive the old framing.  
   - **Source:** [`row-updates/g2.md`](row-updates/g2.md), [`row-updates/fnd-d5.md`](row-updates/fnd-d5.md), [`row-updates/pkp-p3.md`](row-updates/pkp-p3.md).

2. **Unknown prover response fields accepted in both languages**  
   - **What:** Serde ignores unknown keys on `GnarkProofJson`; TypeScript reads named fields only. Both accept `unexpected_field`. Fixture id `unknown-response-field`, disposition `accept-forward-compat`.  
   - **Why accepted:** Forward compatibility for prover metadata; rejecting would be a coordinated API break with no soundness win.  
   - **Affects:** Both SDK parsers; prover evolution.  
   - **Source:** [`row-updates/fnd-d5.md`](row-updates/fnd-d5.md), [`row-updates/pkp-p3.md`](row-updates/pkp-p3.md).

3. **G2 `y1 == 0 && isLargest(y0)` parity branch skipped**  
   - **What:** No short prime-order witness on the algebraic locus; fixture row stays `unavailable`.  
   - **Why accepted:** Locus evidence shows on-curve points with `y.c1 == 0` fail the r-torsion check; skip is not a failed search.  
   - **Affects:** Completeness of P3 compression coverage.  
   - **Source:** [`row-updates/fnd-d5.md`](row-updates/fnd-d5.md), [`row-updates/pkp-p3.md`](row-updates/pkp-p3.md).

4. **P3 error taxonomy differs by language**  
   - **What:** Rust folds parse/point/rail failures into `ClientError::ProofParse`; TypeScript names `CLIENT_PROOF_PARSE`, `CLIENT_PROOF_POINT`, `CLIENT_PROOF_RAIL_MISMATCH`.  
   - **Why accepted:** Recorded mapping; suites compare categories inside each taxonomy.  
   - **Affects:** Callers matching error strings across languages.  
   - **Source:** [`row-updates/pkp-p3.md`](row-updates/pkp-p3.md).

5. **`address-append` has no TypeScript path**  
   - **What:** Eighth prover circuit type; no TypeScript serializer, witness, or proof path. Public builder withdrawn; decode codec retained.  
   - **Why accepted:** TypeScript ships no forester; owner ruled not to port the witness (2026-07-25).  
   - **Affects:** Forester/operators; P2 coverage (seven of eight shapes).  
   - **Source:** [`authority-rulings.md`](authority-rulings.md) (forester builder ruling), [`row-updates/pkp-p2.md`](row-updates/pkp-p2.md), [`scope-and-denominator.md`](scope-and-denominator.md).

6. **P4 does not execute the shielded-pool program**  
   - **What:** Live proofs verify through `groth16-solana` with embedded keys; trees are synthetic; no deposit/index/transact on a validator.  
   - **Why deferred:** Explicit P5 / PKP-07 work. **HOLE-P5.**  
   - **Affects:** Any release statement that a TypeScript flow proved, submitted, and verified against the shielded-pool program.  
   - **Source:** [`row-updates/pkp-p4.md`](row-updates/pkp-p4.md).

7. **P4 full shape matrix not run in the certification pass**  
   - **What:** Fast gate only; `ZOLANA_TEST_P4_FULL=1` not executed in the P4 report.  
   - **Why deferred:** Proving-key load time for the PR-adjacent gate.  
   - **Affects:** Breadth of live verify evidence.  
   - **Source:** [`row-updates/pkp-p4.md`](row-updates/pkp-p4.md).

8. **`KEYPAIR_HASH` wrong variant at merge ciphertext hash**  
   - **What:** Rust `merge_ciphertext_hash(&[])` → `KeypairError::Poseidon`; TypeScript wraps as `KEYPAIR_HASH` (`rustVariant` null).  
   - **Why left open:** Pinned in K10; same question exists at other `KEYPAIR_HASH` sites; decide together.  
   - **Affects:** TypeScript callers matching Rust error variants.  
   - **Source:** [`row-updates/crypto-certification-b.md`](row-updates/crypto-certification-b.md).

9. **Nullifier secret: Rust lends, TypeScript copies**  
   - **What:** Rust returns `&[u8; 31]`; TypeScript returns an owned copy.  
   - **Why accepted:** TypeScript is stricter; recorded, not reconciled.  
   - **Affects:** Cross-language aliasing assumptions.  
   - **Source:** [`row-updates/crypto-certification-b.md`](row-updates/crypto-certification-b.md).

10. **K9 type still admits `Promise` returns**  
    - **What:** `ViewingKeyLike` / `ShieldedKeypairLike` still declare `T \| Promise<T>` after the ruling against out-of-process backends.  
    - **Why left open:** Narrowing collided with parallel work on `shielded.ts`.  
    - **Affects:** TypeScript call sites that can still be written to `await`.  
    - **Source:** [`row-updates/crypto-certification-b.md`](row-updates/crypto-certification-b.md), [`authority-rulings.md`](authority-rulings.md) Q17.

### Program and protocol defects (outside the TypeScript parity denominator)

11. **PD-1 - padding dummy nullifier unconstrained**  
    - **What:** Circuit leaves a padding dummy's public nullifier unconstrained; the program inserts it. A chosen padding nullifier (for example `0`) can wedge the nullifier queue and freeze pool balances.  
    - **Why accepted for this port:** Owner ruled (2026-07-26) to record it, leave it unowned here (no branch, no PR on this effort), and not block the port.  
    - **Affects:** Program, circuit, verifying/proving keys, pool liveness - not the SDK row denominator.  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) Q11, [`scope-and-denominator.md`](scope-and-denominator.md), checklist protocol-defect table.

12. **PD-2 - `user_record` binding on `merge_transact`**  
    - **What:** `merge_transact` does not bind `user_record` to the owner whose notes are merged; a delegate holding nullifier material can substitute a record (blocks the owner from merging, without moving funds).  
    - **Why deferred:** Own program PR #160, branch `fix/merge-user-record-binding`, commit `a811b20e` (open, not on `main`).  
    - **Affects:** Program, merge callers, sync delegates.  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) Q11 and "Where the `user_record` binding defect lands".

### Deferred surfaces

13. **Versioned transactions and address lookup tables deferred**  
    - **What:** Stay on legacy messages; no `VersionedTransaction` / ALT migration scheduled.  
    - **Why deferred:** Measured: ALT costs a pure transfer ~5 bytes and saves ~57 bytes on an SPL withdrawal; not the size fix. Revisit when a second pool tree ships or wallet interop requires v0.  
    - **Affects:** Submit path; wallet adapters expecting v0.  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) Q7, [`versioned-transactions.md`](versioned-transactions.md).

14. **Ciphertext format change / unsendable shapes not scheduled**  
    - **What:** Some supported shapes exceed the 1232-byte packet limit today; a format change that would rescue most is ruled "not scheduled."  
    - **Why deferred:** Owner ruling Q8; size check and shape narrowing are the near-term tools.  
    - **Affects:** Callers of wide shapes (confirmation-timeout misdiagnosis).  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) Q8.

15. **A001 - merge multi-tree selector missing**  
    - **What:** Public `MergeParams` has no `tree` in either language; auto-sweep refuses multi-tree holdings after rollover. Owner ruled to add optional `tree` to both SDKs.  
    - **Why open:** Implementation assigned to **HOLE-STATIC-A001**.  
    - **Affects:** Rust and TypeScript merge callers after tree rollover.  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) A001, [`row-updates/fnd-blockers.md`](row-updates/fnd-blockers.md).

16. **Commitment-affecting external findings still landing**  
    - **What:** Medium/commitment findings from external review under validation on `port/fnd-commit` (and related blocker work).  
    - **Why open:** **HOLE-FND-COMMIT.** Do not cite this packet as having closed those findings.  
    - **Affects:** Release claim until that branch merges and is re-measured.  
    - **Source:** branch `port/fnd-commit`, [`README.md`](README.md) status notes on PR #159 findings.

### Authority-ruled accepted divergences (knowingly less-safe or split)

17. **Owner-hash parity split (G7-1)**  
    - **What:** Spec once described one `pk_field`; implementations use parity-free `owner_pk_field` for `owner_hash` and parity-inclusive `pk_field` for viewing keys.  
    - **Why accepted:** Deliberate, not drift; amend the spec to match.  
    - **Affects:** Readers implementing from old spec text.  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) G7-1.

18. **`SppProofInputs` - TypeScript made less safe to match Rust**  
    - **What:** TypeScript removed extra checks Rust lacks so callers Rust accepts reach the prover.  
    - **Why accepted:** One-language-only refusal is worse than neither.  
    - **Affects:** TypeScript transaction builders (failures shift later).  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) T23 ruling.

19. **High-S ECDSA acceptance (G2-1)**  
    - **What:** Circuit accepts high-S; both SDKs sign and verify high-S.  
    - **Why accepted:** SDK must not unilaterally remove a protocol property.  
    - **Affects:** P256 rail; malleability in `s`.  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) G2-1; K2 suite.

20. **Ed25519 helpers mirror Solana `verify_strict` (G2-2)**  
    - **What:** Both SDK helpers follow the runtime strict verifier, not permissive dalek `verify`.  
    - **Why ruled:** Caller asking the SDK for validity gets the runtime answer.  
    - **Affects:** Ed25519 verify callers (stricter than permissive verify).  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) G2-2; K3 suite.

21. **External-data length prefix - SDKs refuse, program truncates (T21)**  
    - **What:** Program truncates via `u16` cast; both SDKs refuse lengths `> 0xffff` loudly.  
    - **Why accepted:** Prefer loud disagreement over quiet wrong preimage at an unreachable cardinality.  
    - **Affects:** Documented SDK≠program boundary.  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) T21.

22. **Zone address `Some(zero)` left alone (T28)**  
    - **What:** Zero zone *data hash* is normalized; zero zone *address* keeps today's unbound-looking semantics (`pk_field(0)` nonzero).  
    - **Why accepted:** Unreachable via real `zone_config` PDA; changing commitment semantics buys nothing.  
    - **Affects:** Constructors that pass `Some([0;32])` as a zone address.  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) Q10.

23. **Poseidon short-input domain (WASM hasher)**  
    - **What:** TypeScript accepts right-aligned short limbs that host Rust refuses; digests match Rust padded form.  
    - **Why deliberate:** Callers such as `ciphertext_hash` 16-byte chunks rely on it.  
    - **Affects:** TypeScript Poseidon callers versus host Rust API strictness.  
    - **Source:** [`row-updates/wasm-poseidon-verification.md`](row-updates/wasm-poseidon-verification.md).

24. **Zone-authority shapes narrowed to four squares**  
    - **What:** Both SDKs refuse non-square zone-authority shapes; six missing keys are not generated.  
    - **Why accepted:** Spec lists four; keys on disk match.  
    - **Affects:** Zone-authority callers of non-square shapes (fail early).  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) Q16.

25. **`sync_wallet` wait split stays**  
    - **What:** Blocking Rust wait-for-indexer defaults differ from async; TypeScript matches the async default.  
    - **Why accepted:** Owner: deliberate; do not unify with Light's default of waiting for the indexer.  
    - **Affects:** Wallet sync callers expecting automatic catch-up.  
    - **Source:** [`authority-rulings.md`](authority-rulings.md) Q19.

### Operational / CI residuals on this revision

26. **Static gate red (eight lint errors)**  
    - **What:** `npm run lint:packages` exits 1 with eight errors listed in the ledger.  
    - **Why not fixed here:** Owned by **HOLE-STATIC-A001**; this packet records rather than repairs.  
    - **Affects:** `npm run check` / CI criterion 4.  
    - **Source:** Measured on `882d5e1e`; branch `port/static-a001`.

27. **P2 fixture import path broken in unit collection**  
    - **What:** `prover-request-parity.test.ts` imports a non-existent `fixtures/client/public-input-assembly-v1.json`.  
    - **Why reported, not fixed:** Production SDK change outside this documentation packet; correcting the import is a one-line suite fix for the P2 maintainers.  
    - **Affects:** `npm run test:unit` / ability to reproduce P2 from a clean checkout until fixed.  
    - **Source:** Measured on this revision; compare `public-input-assembly.test.ts` which imports `vectors/public-input-assembly-v1.json` correctly.

---

## 4. Fixture and package hashes

Digests are SHA-256 of file bytes on revision `882d5e1e13140e02c7734b76b3fcbec42204ef27`,
unless noted as npm integrity (sha512) from `npm pack`.

### Certification vectors

| Artifact | SHA-256 |
| --- | --- |
| `sdk-libs/ts/vectors/key-certification-v1.json` | `dbaa48cb7cf883bd99609b2eebc0fe63acdf70ad73c047cd6d3a4b2a22748fde` |
| `sdk-libs/ts/vectors/key-certification-typescript-v1.json` | `d6b73410fcee0271576436b8cd23672e299e43ffba98163ddf4cca74dd52f1c8` |
| `sdk-libs/ts/vectors/keypair-crypto-cert-v1.json` | `a8636824d8eed4be99b6f739b7387bdc3576b7952449cf4454be064a7f336e22` |
| `sdk-libs/ts/vectors/public-input-assembly-v1.json` | `3f6d83da7aa117f33fd51ec08047ba9f56d4c8c9938416bac9222f670c9e3328` |
| `sdk-libs/ts/vectors/proof-response-parity-v1.json` | `0b24ed6ae3b5f61920e48553c0a02805fe9977201794b7d93a9f3be70279d941` |
| `sdk-libs/ts/fixtures/client/prover-request-parity-v1.json` | `9bf7102c366ad185302be37f11bbe1af0b643816396697d788bb74253db6b4ab` |
| `sdk-libs/ts/fixtures/client/proof-validity-v1.json` | `f02f21eabe246ab6db9d4b9123835abb3fc939d4b731efa46983a4bf316f273b` |
| `sdk-libs/ts/vectors/merkle-semantics-v1.json` | `04ab7e71cabde4c212d14e40e67d4306719a8b1b11befb70c63a07e29041b80e` |
| `sdk-libs/ts/vectors/poseidon-parity-v1.json` | `bdeb22b8723335b14b4bdffe348a76b2af2f662799cba1907dd09f926c7dd644` |
| `sdk-libs/ts/fixtures/manifest.json` | `efe6b23cfd31024c8be61f751cb28b4b1a39f647b54eb6cc903cc770ab45a184` |
| `package-lock.json` | `96513dd4c3098c8b94ef03856604a354910d80aa78b71380b79625dced6745e2` |

The 58 paths listed in `sdk-libs/ts/fixtures/manifest.json` matched their
embedded `sha256` fields when checked on this revision (`bad = 0`).

### Packed `@zolana/*` packages (`npm pack` at this revision)

| Package tarball | SHA-256 | npm integrity (sha512) |
| --- | --- | --- |
| `zolana-hasher-0.1.0.tgz` | `edd16c7daed7d6840f6e1921290f33d95b0c2680735f1e33583025c7cba4c12c` | `sha512-pYsduXbzSTgMlqaFH8aYAAEizIEueDx0cIcwpXpmsgz/3YDplyVay8tpW89ZvfSuLe+JvUkYK+aqhGgkpeAyhg==` |
| `zolana-interface-0.1.0.tgz` | `16b54890cee5999e2a7168a09120744ad61cec23a9711b0e6280d54acdac3226` | `sha512-Di6mQ7bi7vmm8W5KKEazzaSf3SfnpWavhXBWn0KHil2zEFJcCj8ep8Vyf2b7x+DGtx5TM1sko2TJlfNJ8vLBUw==` |
| `zolana-keypair-0.1.0.tgz` | `de3fe6f01f1e571f84624765bf11a1057074627a4d7d882a25d55a745c34eaf0` | `sha512-PcKXi5hT+B3xvspATeXNbTvAgfayny5RakzRgYz4o9SrDN3BzXcUqwB+2p7Stckmq8D3aEiSu/SlVrwj7nNrDg==` |
| `zolana-transaction-0.1.0.tgz` | `294bd065496550ba3847c6577f5443651f19343f015575357db81ed2999ae29f` | `sha512-+wdZp1/LNC1H06uhJMSrB1axWqUtGyFrVwxkk/VFIKOzIpb203Vnnv9tLtgNyoq7Fbt4sIZwgaGV05O2mPxdhQ==` |
| `zolana-indexer-api-0.1.0.tgz` | `de1152307ae0bc0c8a47c3252b838c793459d4ba9dadef9f0b773e473f158c9b` | `sha512-Mb85EI0kOhxUMSAZQpJN5W/8sx8z8PPdQgnPLPqB3zJ6iZ4h/0GNzbUwgUSwujQqjpkieQ2YFVmhqTScYfK7fA==` |
| `zolana-api-0.1.0.tgz` | `d8c596a1814020ca69666eb11f46ff3d0a10d6ac090582b99d84ca03b0892c18` | `sha512-DOljaYrwS6msVgvCLqtKRKX1mX7FN1m0N+5OBJ89ox4pCz4CEQEA/dgNFtZMq7tQwgbuA/zmfC00lk2BqQVjng==` |
| `zolana-client-0.1.0.tgz` | `cff2304bdf0c702a8e1331b8ccd4edfde044b5a21a27be34e5bbcb801565a727` | `sha512-WgiH8kvaxlHZLhvTEwAvzQ26W7eie/vSaSq+yfZxLLNTeWT5rHEXKHuGLd3PoDXSaTHLAfysqeoZdsY+FKW2QQ==` |
| `zolana-wallet-0.1.0.tgz` | `4867560761a50babb3a856430042401f18a85da56122d2e94f3af3885992579e` | `sha512-FxZpAqdcZ31dGfIp2vDd7Ejz3zn7vK6jE+TtVQBnfKkGHsOfWvH+c5D/tVKR/7CTLWNf1brqQCk0T57KajJOzw==` |
| `zolana-merkle-tree-0.1.0.tgz` | `08ef3f8af32102e52814627e320663b61574542a45e26dec840aeb9fe091effc` | `sha512-glrvo3TqKAYSzNMgBJBb3vAmWmxEuprpyt1qJqkmvCly2vBWoETY1RA0mxchpcfIFMoWEPmqo3fgUp0nemorOA==` |
| `zolana-smart-account-client-0.1.0.tgz` | `f03abff8c9babe1a82d1ecdb4fdb2d2891747dd503e514b06833b903414e5153` | `sha512-ZyT/DkwzClOvDb7vj2vfYbUHpxYr65n4zbf+liiaFz/NHSRrC95i0dzqqRyirpj++0mT3XEn3rTB2ng/UcTwbQ==` |

Hasher artifact stamp (source pointer, not the wasm bytes):  
`sdk-libs/ts/hasher/src/artifact.ts` SHA-256 `dd916e4944165b36cecac1f17c4ad49848cd34243ba76169357c9ac3f94448d1`.

After HOLE-\* branches merge, re-run this section; do not reuse these digests for a
different revision.

---

## 5. Independent review of previously adverse rows

### Background

On 2026-07-25 an evidence audit examined 36 rows then marked `done` / `PARITY`
and found **1 supported**, **34 unsupported**, and **1 contradicted**
([`row-updates/parity-evidence-audit.md`](row-updates/parity-evidence-audit.md)).
Most were reopened; the bar was raised to require attributable evidence (named
reviewer or regenerable oracle), not "two files look similar."

This packet does **not** re-review the full set of 145 rows. It identifies rows that were
ever adverse and are now closed, then spot-checks a sample concentrated on
**early** closes (before the raised bar), because those are where unsupported
verdicts are most likely to have survived.

### Previously adverse, now closed

From the audit's 36 early `PARITY` claims, 35 were unsupported or contradicted.
They held earlier adverse verdicts including `PARTIAL`, `DIVERGENT`, `MISSING`,
`BLOCKED`, and (for W02 later) `STALE`. Those rows are `done` / `PARITY` again in the
current checklist. Highest-risk survivors of the early close are the Class-1
wallet rows that were **not** put through the post-audit reopen cycle: W01,
W03, W05, W07.

### Spot-check sample (eight rows)

| Row | Earlier adverse | Closing claim (current notes) | Spot-check |
| --- | --- | --- | --- |
| **I01** | PARTIAL | Generated Rust oracle + `rust-oracle.test.ts` compare the error codes, names, and messages (notes say "26") | **Evidence does not support the verdict as written.** Test named `matches every Rust error code and message` compares only `{ code }` objects; messages are unused. Oracle and TypeScript both define **29** codes, not 26. Codes/names set-equality exists; the message claim and the count do not. Files: `sdk-libs/ts/interface/test/vectors/rust-oracle.test.ts`, `sdk-libs/ts/interface/test/rust-oracle.json`. |
| **I02** | DIVERGENT | Ordered supported-shape list + first-cover selection vs Rust | **Supported.** Tests `shape > matches the Rust supported-shape list in order` and `selects the first shape that covers the request` exist and match the claim. |
| **I03** | PARTIAL | `merge-utils` hashes / `pack33` / rejection vs Rust | **Supported.** `merge utils` block asserts the claimed comparisons. |
| **I08** | DIVERGENT | Prefix guards removed; both directions accept/rebuild non-canonical merge prefix | **Supported.** Guards absent from `interface/src/codecs/index.ts`; rebuild test present; [`row-updates/merge-prefix.md`](row-updates/merge-prefix.md). |
| **I23** | DIVERGENT | Builder matches transact with no withdrawal and both settlement rails | **Supported.** Named builder test exists and exercises the rails. |
| **W02** | DIVERGENT → STALE → PARITY | Deposit commitment recomputed; SPL branch; tag controls; fixtures regenerated | **Supported.** `deposit-vector.test.ts` recomputes `ownerUtxoHash`, covers SPL and tag ≠ viewing-key x. |
| **W07** | DIVERGENT (Class 1; never reopened under the oracle bar) | Delegate-aware `senderViewingPublicKey`; registry test pins delegated case | **Evidence does not fully support the verdict as written.** Delegate rule exists in `registry.ts`, and a delegated test exists, but cited line ranges in the checklist cell are stale; the test asserts viewing key = latest epoch while `viewTag` remains the owner confidential view tag (and explicitly not `latestEpoch.x()`); empty-`entries` + active `syncDelegate` fallback claimed in notes is not covered; no Rust-generated oracle for the fund-losing sync-delegate rule. This is still pre-audit evidence shape. |
| **M01** | DIVERGENT (oracle-contradicted) | `merkle-semantics` generator + TS replay; sentinel closes indexed range | **Supported.** Generator, vector, and `sentinel-closes-the-indexed-range` replay exist. |

### Spot-check conclusion

The sample found **two rows whose written closing evidence does not support the
verdict as stated: I01 and W07.** Finding them is the purpose of this review.
Post-audit oracle re-closes in the sample (I02, I03, I08, I23, W02, M01) check
out. A release reviewer should treat I01's message/count claim and W07's
sync-delegate provenance as debt to clear before citing those cells as
strong parity evidence.

---

## 6. What a release reviewer may claim

Allowed on this revision, if the command ledger is green after HOLE-\* merges:

- Individual key-handling capabilities covered by K1-K10, with the residual list
  disclosed.
- Public-input assembly parity (P1) and prover-request parity for the seven
  TypeScript-reachable shapes (P2), with `address-append` disclosed as absent.
- Cryptographic verification for the P4 fast-gate shapes through the real prover
  and `groth16-solana`, with shielded-pool program execution still **HOLE-P5**.

Not allowed:

- "Complete proof and key-handling parity."
- "P3 certified" without naming the remaining synthetic off-curve / unknown-field / y1==0 exceptions (see P3 row; live G2 limb bug is closed in [`g2.md`](row-updates/g2.md)).
- "P5 certified" / "TypeScript prove-submit-verify on a local validator certified" until HOLE-P5 closes.
- "CI gates green" while the static gate and the P2 import path remain red.

When HOLE-P5, HOLE-STATIC-A001, and HOLE-FND-COMMIT land, append a dated
addendum with the new revision, updated matrix rows, and refreshed hashes.
Do not silently edit historical measurements above.
