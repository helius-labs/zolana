# 2026-07-25 22:35 UTC | transaction parity batch, thirty-one rows judged | `sdk-libs/transaction/`

- Baseline: HEAD `1222dd0a`; oracle `transaction/test/oracles/transaction-parity-v1.json` at `157ed768`; batch commits `6a7e1000`, `157ed768`, `d6e658e2`, merged as `3e0ca42c`
- Worker: Opus 5 reconciliation subagent, reading [row-updates/transaction-parity.md](../row-updates/transaction-parity.md) against the tree
- Explanation: This batch is the second one to do the thing that works. It generated ground truth from the production Rust path and compared TypeScript against it, rather than reading the two languages side by side, and it reports three rows at parity out of thirty-one. A batch that closes three rows and says so is worth more than one that closes thirty and cannot show why, which is the shape of the audit this queue is still paying for.
- Evidence: `sdk-libs/transaction/tests/ts_oracle.rs` builds the cases from the production Rust path and writes the committed oracle; without `ZOLANA_WRITE_TS_ORACLES=1` it verifies that file instead, so a Rust change that moves a recorded value fails the Rust suite rather than being absorbed into a regenerated fixture. `transaction/test/vectors/rust-oracle.test.ts` runs the TypeScript path over the same inputs. Neither side reads the other's source. I ran `npx vitest run sdk-libs/ts/transaction/test/vectors/rust-oracle.test.ts` at this HEAD after `npm run build` with `node_modules/.vite` cleared, and it passes.

## Three rows close

- Verdicts: `PARITY` for `T02`, `T03`, `T20`

`T02` closes on twelve `Data` cases whose encodings are byte-identical and whose four rejections raise the same code in both languages. The case list is chosen where a hand-written fixture goes wrong: a 300-byte memo across the `u8`-to-`u16` length boundary, an empty record body, a duplicate memo, a duplicate zone, and the three non-canonical orders.

`T03` closes on the seven scheme bytes round-tripping and the 249 unassigned byte values raising `TRANSACTION_BAD_DISCRIMINATOR` on both sides. That is the whole byte domain rather than a sample. The row's export residual is closed the way an export claim should be, by a test that imports `encryptedSchemeToByte` from the root entry point and would fail to resolve if it were withdrawn, instead of by an allowlist entry that only says a name is listed somewhere.

`T20` closes on 70 canonical selections over a 7-by-10 grid and 112 declared-shape resolutions over six declared shapes, agreeing on the selected shape and on the three rejection codes the sweep can reach, `TRANSACTION_UNSUPPORTED_SHAPE`, `TRANSACTION_TOO_MANY_INPUTS`, and `TRANSACTION_TOO_MANY_OUTPUTS_FOR_SHAPE`. Generating the fixture also gives `shape.rs` the direct Rust tests it had been missing.

## The divergences the oracle exposed, and why they matter more than the closures

- Verdict: `PARTIAL` for `T01`

The error map is the piece of this batch that will keep paying. `ts_code` matches on `TransactionError` exhaustively, so a variant added to Rust does not compile until it is mapped, which makes the TypeScript code set derived from current Rust instead of asserted to agree with it. Writing it found two Rust variants with no TypeScript counterpart, `OutputSlotOverflow` and `ExcessOutputSlots`, and a third case where `mergeUtxo` raised the registry's unknown-asset-*id* code for an unknown asset *field*. The three are naming errors on rejections both languages already made, and neither fix narrows an accepted set. No case was found where TypeScript refuses input Rust accepts, which is the failure this branch has produced before and the one worth hunting.

`T01` stays open on five declared codes with no producer. They are raised in Rust by the `from_utxos` conversions that `T04`, `T06`, and `T08` record as unported, so they should acquire producers when those rows close rather than being deleted now as dead codes.

## Rows advanced but held adverse

- Verdicts: `PARTIAL` for `T05`, `T09`, `T11`, `T12`, `T22`, `T27`

Each names the one thing still missing, so a reader can act on it. `T05` has the confidential output plaintext byte layout proven over four cases and still maps no decryption failure onto Rust's `Decrypt` categories. `T09` has its error-code divergence fixed and lacks export, browser, and proof-contribution evidence. `T11` has eight commitments, three owner commitments, and five blinding derivations compared byte for byte, and Rust still routes the zone rule through `with_zone` rather than one construction path. `T12` agrees on sixteen registry operations and waits on one API decision about `entries()`. `T22` and `T27` move off `DIVERGENT`: the slot-ordinal code mismatch is gone and `MERGE_INPUTS` is exported, so what is left in each is a missing export or a missing comparison rather than a disagreement between the languages.

- Verdict: `DIVERGENT` for `T25`

Advanced by the excess-slot fix and still adverse on three untouched clauses: padding location, dummy-rail sampling, and four absent symbols.

## `T29` is rewritten, because it described a guard that no longer exists

- Verdict: `DIVERGENT` for `T29`

The row said `PreparedZoneAuthority::new` rejects a public leg and that TypeScript raises `TRANSACTION_ZONE_AUTHORITY_WITHDRAWAL_NOT_ALLOWED`. I checked both claims against the tree. `zone_authority.rs:57-73` and `builders.ts:510-521` each enforce three rules, the nonzero zone and the two zone bindings, and a search finds that error code in no source file; the batch's exhaustive error map says the same from the Rust side, since no variant exists for it. `cda42f01` added the guard, the rejection-validation analysis found it over-strict against the circuit, and a later pass removed it from both languages.

Reintroducing it would make both SDKs refuse transactions the program and the circuit accept, so the correction leads the row rather than trailing it. The real divergence is the opposite of the recorded one, and TypeScript is the looser side: Rust `new` resolves the shape, computes the public amounts, and derives `payer_pubkey_hash` from the payer address, while `prepareZoneAuthority` accepts a caller-supplied payer hash and freezes it without resolving anything. Status moves to `needs_fix` because that has a concrete smallest fix.

- Gap and smallest fix: `T29`, derive the payer hash and resolve the shape inside `prepareZoneAuthority`. `T12`, record the `entries()` disposition. `T22`, export a counterpart for `encode_confidential_slots`. `T21`, an interface-owner decision on the `u16` preimage, with a boundary vector at `0xffff` and `0x10000` outputs, which no language has
- Row transitions: `needs_fix -> done` for `T02`, `T03`, `T20`; `DIVERGENT -> PARTIAL` for `T22` and `T27`; `needs_re_review -> needs_fix` for `T29`; evidence and fix commits recorded on `T01`, `T05`, `T09`, `T11`, `T12`, `T18`, `T21`, `T25`, `T30`, `T31` without a status change
- Progress: `64/145` after this entry; the transaction package is `3 of 31` closed
- Exact next file: `planning/typescript-sdk-port/row-updates/client-package.md`, rows `C01`, `C02`, `C04`, `C05`, `C21`, `C22`
- Full SDK parity claim: unsupported
