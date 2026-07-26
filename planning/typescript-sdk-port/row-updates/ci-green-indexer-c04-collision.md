# `typescript / suites` is red from the live C04 collision, not from CI plumbing

Reported by the `port/ci-green` tree. Not fixed here, deliberately: the failing
path is claimed by two running agents and the fix requires a ruling.

## The failure

`npm run check:suites` fails one case out of 1883:

```
FAIL sdk-libs/ts/indexer-api/test/schema.test.ts
  > indexer schema > decodes a u64 above the safe-integer bound carried as a decimal string
IndexerSchemaError: Invalid value at $.proofs[0].leaf_index
```

The case sends `leaf_index: ((1n << 53n) + 1n).toString()` and expects the
decoder to return the bigint. The merged `codec.ts` rejects it.

## Why it is a collision and not a bug with an obvious owner

The test and the decoder that rejects it arrived from different trees:

- the test, from `876c5bf5 fix(indexer-api): read the whole u64 domain Photon can send`
- the decoder, from `c631594e feat(indexer-api): accept a decimal string for uncapped integers`
  on top of `0f4a4ca4 wip(indexer-api): per-field integer domain, salvaged mid-flight`

`assignments.md` already names this pair as the collision it exists to prevent:
`port/rulings` and `port/c04-reconcile` were both dispatched at the C04 integer
domain six minutes apart, both rewrote `codec.ts` and
`integer-domain.test.ts`, and neither was told about the other. Both are listed
as running.

## The ruling that is owed

Whether `leaf_index` is an uncapped `u64` that may arrive as a decimal string,
or a capped field that must stay a JSON number, is the C04 question itself. The
two trees answered it differently and both answers are now merged. Picking one
inside a third tree would encode a parity decision by accident and would be the
fifth hand-out of the same row.

The coordinator has to keep one tree's answer and drop the other's, then make
the test and the decoder agree in that tree.

## Scope note

`typescript / suites` is not one of the six jobs `port/ci-green` was dispatched
to fix, and `sdk-libs/ts/indexer-api/**` is not among its paths.
