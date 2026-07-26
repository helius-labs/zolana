# Open questions, collected and answered the Light way

Worker for the owner's instruction of 2026-07-26: produce the register of what
is still undecided across the whole port, then answer each entry the way Light
Protocol answered it. Branch `port/open-questions` from `f4f4ee71`.

The register itself is [`../open-questions.md`](../open-questions.md). This file
records what changed in code, which rows it touches, and the control edits.

Scope held. Both commits are under `sdk-libs/ts/**`. Nothing in `programs/`,
`program-libs/`, `prover/`, `xtask/`, or `docs/spec.md` was touched, and
`review-checklist.md` was left to the reconciler.

## Two commits

| Commit | What it closed |
| --- | --- |
| `876c5bf5` | The indexer integer domain, both halves of Light's answer |
| `0e26c397` | Transaction size measurement, plus two of the five `compactU16` copies |

## C04, second half: the integer domain is no longer narrower than Rust's

The row carried four options and no way to choose between them, because
`docs/spec.md` says nothing about the JSON encoding, so no implementation could
be measured against it. Light settles it by meeting the same problem with the
same wire format, and its answer has two parts that work together.

At the transport it rewrites out-of-range numeric literals into quoted strings
before parsing (`js/stateless.js/src/rpc.ts:291-302`, applied at `:346`), so the
digits survive `JSON.parse`. At the decoder, `BNFromStringOrNumber` accepts a
string parsed base 10 unbounded, accepts a number only when
`Number.isSafeInteger` holds, and otherwise throws `Unsafe integer. Precision
loss` (`js/stateless.js/src/rpc-interface.ts:316-328`).

So the recorded option I2 is Light's answer, and I4's rejection survives as the
backstop rather than as the policy. Ported both parts: `quoteUnsafeIntegers`
runs before `JSON.parse` in `@zolana/api`, and `wireInteger` in
`@zolana/indexer-api` accepts a canonical decimal string.

This closes a divergence rather than opening one. Photon serializes `u64` and
`i64` as bare JSON numbers with no stringifier
(`sdk-libs/indexer-api/src/lib.rs`, and the `format: u-int64` entries in
`services/photon/src/openapi/specs/rings.yaml`), Rust's serde reads the full
range, and TypeScript refused anything past `2^53 - 1`. The port was the
stricter side.

### Two defects in Light's version, measured rather than assumed

Light's rewrite is the regex `/(":\s*)(-?\d+)(\s*[},])/g`. Running it directly
against four inputs shows two holes:

- `{"seqs":[1152921504606846976,1]}` is returned unchanged, because the pattern
  needs a key and a colon immediately before the number, so an array element
  still loses precision.
- `{"memo":"x\": 1152921504606846976,"}` becomes `{"memo":"x\": "1152921504606846976","}`,
  which `JSON.parse` rejects. A string whose content happens to look like a
  key-colon-number sequence is corrupted.

The version here is a scanner that skips string literals, so it quotes array
elements and leaves string contents alone. The same six inputs were run against
it, including a safe integer and a float, and each is either quoted correctly or
left alone.

Copying the regex verbatim would have been the more literal reading of "mimic
1 to 1". It would also have shipped a corruption bug into a package that carries
base64 payloads. The technique is Light's; the two holes are not part of the
answer.

### What pins it

`api/test/transport.test.ts`:

- `reads a u64 above the safe-integer bound without losing precision`, which
  builds the response body as raw text so the literal is not rounded before the
  transport sees it.
- `does not rewrite a digit run inside a string payload`, over a base64 payload
  of twenty digits.
- `leaves a safe integer, a quoted string, and a fractional number as they were
  sent`, which is the control: it passed before the change and must keep
  passing.

`indexer-api/test/schema.test.ts`:

- `decodes a u64 above the safe-integer bound carried as a decimal string`.
- `rejects a decimal string outside the field's range or in a non-canonical
  form`, over six inputs: past `u64::MAX`, negative, a leading zero, a decimal
  point, leading whitespace, and empty.
- `rejects a JSON number that lost precision before it reached the decoder`,
  which keeps Light's backstop.

Checked red before green. The first test in each file failed on the base commit;
the other four passed there and still pass, which is what distinguishes a
widened domain from a relaxed decoder.

One thing worth knowing for whoever runs the gates next: the first red run was
red for the wrong reason. `@zolana/api` resolves `@zolana/indexer-api` through
its `exports` map, so it reads `dist`, and the decoder change was invisible
until `npm run build`. That is the stale-`dist` trap the README records, hit
again.

### Not changed: the encode side

`toWireInteger` still refuses a `bigint` above `2^53 - 1` on the way out
(`codec.ts`), so a request carrying such a value fails locally. Left alone
deliberately: Light's own request path sends strings and its decode path is what
the divergence report is about, and no request field in the five methods carries
a value that can reach the bound. If one ever does, the fix is the mirror of this
one and belongs with it.

## The transaction size limit: measurement, not refusal

Nothing in the SDK compared a compiled message against 1232, and three of the ten
supported shapes exceed it today. [`../versioned-transactions.md`](../versioned-transactions.md)
recommended adding a check without settling what the check should do to a caller,
which is the part that matters, because a hard refusal in the compiler is the
stricter-than-Rust regression this project has reverted twice.

Light draws the line in a specific place and it transfers exactly.

Measurement is public: `MAX_TRANSACTION_SIZE` and `estimateTransactionSize` are
exported from the package root (`js/compressed-token/src/index.ts:34-38`,
`js/compressed-token/src/v3/utils/estimate-tx-size.ts:4`, `:63`).

The refusal is `@internal` and reaches only batches Light assembled itself, in
four modules: `v3/instructions/transfer-interface.ts:275`,
`v3/instructions/unwrap.ts:276`, `v3/instructions/approve-interface.ts:120`, and
`v3/actions/transfer-interface.ts:219`. Its message says why it is allowed to be
fatal there: "This indicates a bug in batch assembly."

The negative is clean. `buildTx` and `buildAndSignTx`, which compile whatever
instruction list a caller hands them, carry no size check; the only throw in
either is about a duplicated signer
(`js/stateless.js/src/utils/send-and-confirm.ts:26-39`, `:123-144`).

`compileLegacyTransaction` is the `buildTx` role. An oversized transaction there
is the caller's proof shape, not a bug in code Zolana wrote, so it measures and
does not refuse. Zolana can measure exactly where Light estimates, because it
owns its serializer.

### What pins it

`client/test/transaction-size.test.ts` compares `transactionSize` against the
byte length `SolanaRpc` actually submits, captured from the base64 payload, at
five signature counts: 0, 1, 2, 127 and 128. The last pair is the point of the
list, since 128 is where the compact-u16 count grows to two bytes and a
measurement assuming one byte agrees below it and disagrees above.

A sixth case asserts that a transaction past `MAX_TRANSACTION_SIZE` is still
measured and still submitted. That one exists to fail if a later worker turns the
measurement into a guard, which is the mistake this row is shaped to avoid.

Checked red before green: the seven assertions failed at the base commit, since
neither symbol existed.

## `compactU16`, two of five copies

`client/src/client.ts:735` and `client/src/solana-rpc.ts:627` held
character-identical implementations differing in one variable name. The size
measurement needed the same arithmetic, which would have made a sixth. Both now
read one function in the new `client/src/wire.ts`.

Light writes this encoder zero times. Searching its TypeScript for `compactU16`,
`encodeLength` and `shortvec` returns a single function, `compactU16Size`
(`js/compressed-token/src/v3/utils/estimate-tx-size.ts:40-44`), and it counts
bytes rather than emitting them; the emitter arrives inside the web3.js
serializer that `compileToV0Message` feeds. Zolana cannot take that dependency
without settling the `@solana/kit` question, but nothing required the arithmetic
to be written five times inside one repository, and that is independent of the
dependency decision.

The copies in `wallet/src/internal.ts:105` and
`test-kit/src/user-registry.ts:390` stay, along with the three message compilers.
Collapsing those needs a shared home in `@zolana/interface`, which widens a
published surface pinned by three allowlists, and it is the same decision as
merging `@zolana/api` with `@zolana/indexer-api`. Recorded as question 14 in the
register rather than half-done.

## Rows this touches

No row moves to `PARITY` here; that is the reconciler's call and this branch
produced no re-review.

| Row | What changed |
| --- | --- |
| `C04` | The integer-domain half is closed and executed. The `Context` field half is a specification amendment and is question 3 in the register. |
| `X01` | Unchanged in code. The register records that Light has no three-artifact conflict because it has no specification document, which is the state an amendment reaches. |
| `S01` | Unchanged. The register carries Light's partial answer under question 13: Light does refuse an oversized payload, but only where it assembled the payload itself. |
| `T28` | Unchanged. The register separates the three clauses, because Light answers the third and declines the first two, which the row text treated together. |
| `K11` | Unchanged. The register carries Light's answer, that its backend capability interface is synchronous and only signing is async, and names the owner question that decides whether it transfers. |
| `M02` | Unchanged. The register recommends closing the error-mapping residue without a mapping, since Light's own taxonomy is nine unused classes under a `// TODO: Clean up`. |
| `I08` `I09` `I20` `I21` | Confirmed still closed at this HEAD; the guards are absent and the oracle test pins both directions. Recorded for completeness. |

## Two corrections to earlier documents

**F8 in [`../light-protocol-comparison.md`](../light-protocol-comparison.md) is
wrong on one point.** It reports that validation exists inside `createBN254` and
"nothing routes values through it". One path does:
`BN254FromString` (`js/stateless.js/src/rpc-interface.ts:296-299`) sends every
base58 hash arriving from the indexer through `createBN254`, and `enforceSize`
throws at or above the field modulus (`js/stateless.js/src/state/BN254.ts:35-40`).
This matters beyond the correction, because it is the evidence for T28's third
clause: Light does enforce the field range, at the boundary where a value arrives
from outside.

**The merge-prefix row's "Light never validates" rule needs its edge stated.**
The rule established in [`merge-prefix.md`](merge-prefix.md) is about a
caller-supplied byte the program enforces, and it holds. It does not extend to a
value's numeric domain, where the correction above shows Light validating. Two
different questions that both look like "does the SDK check what the program
checks".

## Verification

Run at the tip of this branch.

```
npm run build && rm -rf node_modules/.vite && npm run test:unit
npm run check:static && npm run lint:packages
cargo check --workspace
```
