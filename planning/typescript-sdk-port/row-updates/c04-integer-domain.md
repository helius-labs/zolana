# C04: the two failures left on the tip after the per-field merge

Worker on `port/c04-fix` from `653db1a6`. Scope held to `sdk-libs/ts/api` and
`sdk-libs/ts/indexer-api`.

The per-field decoder itself is not this file's subject. It landed from
`port/rulings` and its field-by-field reasoning is in
[rulings-c04-and-size.md](./rulings-c04-and-size.md). This file records why the
two tests failed afterwards, which is a different question from whether the
split is right, and the two answers turned out to be unrelated to each other.

## The split was re-checked and stands

Verified against the tip rather than taken on trust, because a reconciliation
that leaves the central judgement unexamined is not a reconciliation. The
routing in `codec.ts` reads: `block_time`, both `slot` fields, both `root_seq`
fields, `seq` and `start_seq` through `unboundedU64` / `unboundedI64`;
`leaf_index` in both places, `low_element_index`, `high_element_index`, both
`root_index` fields and `tree_type` through the number-only path, with `limit`
on `checkedPageLimit`.

The caps behind that are real and independently confirmed: `STATE_TREE_HEIGHT`
is 32 and `NULLIFIER_TREE_HEIGHT` is 40 (`sdk-libs/client/src/rpc.rs:27-28`), so
a leaf position stays under `2^32` and an indexed-element position under `2^40`;
the two `u16` fields are capped by width; `limit` is 1 through 1000 in Photon's
own schema (`services/photon/src/openapi/specs/rings.yaml`, `Limit`). Nothing in
the protocol caps a slot, a block time, or a free-running sequence. No change.

## Failure 1: `schema.test.ts`, and it was the test

`decodes a u64 above the safe-integer bound carried as a decimal string` sets
`leaf_index` to a decimal string and asserts it decodes to a `bigint`. That is
the uniform reading of the ruling, written before the per-field one existed. A
leaf index is capped by the tree height and takes the number-only path, so the
decoder refuses the string and is right to.

The test asserted the behaviour the ruling corrected. Deleted, along with the
two cases beside it, because `integer-domain.test.ts` covers all three and
covers this one the right way round, in
`keeps the string form off fields a tree height or a width already caps`.
Leaving both files meant the concern was asserted twice with one of the two
wrong.

## Failure 2: `transport.test.ts`, and it was a stale `dist`

`reads a u64 above the safe-integer bound without losing precision` passes on
this tip. It passes on a clean `npm ci && npm run build`, and the whole unit
suite passes with it.

Reproduced rather than argued. Building `dist` from the source at `876c5bf5^`,
restoring the current source, and leaving `dist` untouched fails the test with:

```
ApiError: API result is invalid
 ❯ schemaError sdk-libs/ts/api/src/index.ts:547:10
 ❯ decodeResult sdk-libs/ts/api/src/index.ts:534:11
 ❯ ZolanaApi.#call sdk-libs/ts/api/src/index.ts:127:14
```

That is the reported symptom line for line. `@zolana/api` resolves
`@zolana/indexer-api` through its `exports` map, so it reads the built `dist`
rather than the sources next to it. When `dist` holds a decoder older than the
union, the transport quotes a large literal correctly and the decoder that
receives it refuses the string.

This also explains the part of the earlier diagnosis that looked impossible:
the test passed on `port/open-questions` and failed the moment that branch
merged, with an empty `git diff` over both packages across the merge. A merge
does not rebuild `dist`. Whatever `dist` happened to be on disk decided the
result, so no source in either package had to change for the verdict to flip.

The candidates that diagnosis named are cleared. `interface/src/codecs/index.ts`,
`interface/src/errors.ts`, `interface/src/state.ts` and
`sdk-libs/ts/fixtures/client/rpc-indexer-v1.json` are not involved, and none of
them was touched. Nothing needs to change in `@zolana/interface` or in a
fixture.

Worth knowing for whoever runs the gates next: the eighteen other failures
reported alongside these two do not reproduce here either. The suite is
`1883 passed | 1 skipped` on this tree. That is consistent with the same stale
`dist`, though it is not proof, since those failures were never observed here.
Rebuild before believing a cross-package failure.

## What changed

Two commits, tests and one comment. The decoder was not touched.

| Change | Why |
| --- | --- |
| Removed three cases from `indexer-api/test/schema.test.ts` | One asserted the corrected behaviour; the other two are covered in `integer-domain.test.ts` |
| Added `refuses an oversized value on a field the tree height caps, quoted or not` to `api/test/transport.test.ts` | The seam between the two layers had nothing holding it |
| Added `reads a JSON number at the safe-integer bound on a field of either kind` to `integer-domain.test.ts` | The backward-compatibility promise, pinned at the boundary |
| Added two encoder cases to `integer-domain.test.ts` | The encoder's single wire form was asserted nowhere |
| Comment on `toWireInteger` | Answers the question the string path now provokes on the encode side |
| `respondWith` helper in `transport.test.ts` | Four cases were repeating the same eight-line client construction |

### The seam is the part worth keeping

Two layers now decide the same question from opposite sides. `quoteUnsafeIntegers`
rewrites an unsafe integer literal before parsing without knowing which field it
belongs to, and the codec decides per field what a string may mean. Nothing held
them to the same answer, and a disagreement surfaces as `API_INVALID_RESULT` on a
payload that should have decoded, which is exactly the shape of the failure that
sent this task out.

They do agree, and the new case says so: an oversized value on `leaf_index`
arrives quoted and is refused at `$.proofs[0].leaf_index`, the same refusal it
would have got as a bare number before the transport existed. The quoting cannot
smuggle a value past a cap, which is the property that makes it safe to quote
without consulting the schema.

## The encoder is coherent

Confirmed as asked. `toWireInteger` emits a JSON number for every field and
reports `INDEXER_SCHEMA_UNSAFE_INTEGER` for a `bigint` it cannot represent as
one, including on the fields the decoder reads as strings. Photon's `serde`
installs no string acceptor on its `u64` and `i64` fields, and `encodeRequest`
feeds the body Photon parses, so emitting a string would produce a request the
Rust side refuses. The tolerance is one-directional by design.

The visible cost is that `encode(decode(x))` is not total: a `root_seq` read from
a decimal string has no JSON-number encoding. That asymmetry is Photon's own,
since Photon emits numbers and parses numbers, and the error names it rather
than rounding.

## Can C04 close

Yes, on the integer domain. Both halves are settled and now green:
`Context` is `block_time: i64` in the spec and in all three implementations, and
the decoder reads the ruled union applied per field, with the transport keeping
the digits intact and the encoder unchanged.

One thing for the row's owner rather than for this branch. The `Integer encoding`
paragraph in the RPC section of `docs/spec.md` still states option I3, capping a
JSON integer of any declared width at the IEEE-754 safe-integer range and calling
a service that exceeds it the defect. It was written at `1d6b9873` on
2026-07-25, ten hours before the ruling, and the ruling says the adopted encoding
"is neither of the two options originally offered" and removes the ceiling for an
uncapped field. As it stands the source of truth contradicts the decoder the
ruling requires. This branch does not touch `docs/spec.md`; the paragraph needs
rewriting to the union and the per-field test before C04 is closed on paper.

## Gates

Run on the final tree after a rebuild: `build`, `typecheck`, `lint:packages`,
`format:check`, `test:unit` (1883 passed, 1 skipped), `test:vectors`,
`test:property`, `test:cross`, `check:packaging`. All green.
