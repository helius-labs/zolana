# P3. Proof response parsing and compression

Suite P3 of [proof-and-key-parity.md](../proof-and-key-parity.md): gnark response
parsing, A negation, G1/G2 compression, commitment presence versus the requested
rail, and the rejection surface for malformed prover responses.

## Bottom line

P3 certifies the shared accept/reject surface for parsing and compression where
both languages already agreed, plus the Rust-generated fixture for parity-bit,
identity, leading-zero, structural row-count, truncated/extended, and
rail-confusion cases. Residuals have dispositions (see
[fnd-d5.md](./fnd-d5.md) and [g2.md](./g2.md)):

1. Off-curve G2 at compress — closed parsing defect (gnark `c1`-first limbs);
   TypeScript now matches the syscall range check and defers curve validity to
   the chain. Not a language-level policy divergence.
2. Unknown response fields — shared acceptance kept for prover forward
   compatibility; not a soundness gap.
3. `y1 == 0 && isLargest(y0)` — skipped with algebraic evidence that the curve
   locus lies outside the r-torsion; no short prime-order witness.

## What already covered P3

`sdk-libs/ts/client/test/vectors/proof-compression.test.ts` against
`fixtures/client/proof-validity-v1.json` already froze vanilla and BSB22
generator points through production Rust (`proof_from_gnark_json` via the mock
prover client, then `ProofCompressed::try_from`), including exact uncompressed
bytes after A negation, compressed A/B/C and commitment limbs, rail packing, a
malformed response with missing coordinate rows, a partial commitment, off-curve
G1 at compress, and a missing commitment on the P256 rail.

`sdk-libs/ts/client/test/vectors/proof-canonical-oracle.test.ts` against
`client/test/oracles/proof-canonical-v1.json` already froze coordinate
spellings, values at and above the BN254 base modulus, the four requested-versus
answered rail combinations, and half-commitment bodies. Those rows stay the
authority for those clauses; the new suite references them rather than rewriting
them.

`prover-edge-cases.test.ts` and `p256-malleability.test.ts` are assembly and
signature suites. They were left alone.

## What this suite built

`xtask/src/bin/proof-response-parity` writes
`sdk-libs/ts/vectors/proof-response-parity-v1.json` and supports `--check`. Every
accepted byte comes from production `ProverClient` parsing (which calls
`proof_from_gnark_json`) or `ProofCompressed::try_from`. Rejection rows start
from a Rust-parsed base and apply a named mutation recorded in the fixture.

`sdk-libs/ts/client/test/vectors/proof-response-parity.test.ts` replays that
fixture through public `parseProof` and `compressProof`, comparing uncompressed
bytes, compressed bytes, parity bits, rail, commitment presence, and stable
TypeScript error categories. Message text is not compared.

New valid vectors: identity points on both rails; leading-zero generator
coordinates; G1 compressed parity clear and set; G2 compressed parity clear and
`y1`-largest. New rejection vectors: missing and extra `ar`/`bs` rows; truncated
and extended G1 arrays; malformed hex; a coordinate at the modulus; commitment
without PoK and PoK without commitment; commitment on the eddsa rail; missing
commitment on the p256 rail; off-curve G1 at compress; a G2 limb at the modulus.
The unknown-field row records shared acceptance. The off-curve G2 row records
shared acceptance under `match-syscall-range-check` (see [g2.md](./g2.md)).

## Divergences

**Off-curve G2 at compress — not a divergence.** An earlier draft treated
TypeScript refusal of off-curve G2 as a deliberate fail-fast against Solana's
`Validate::No` compress. That framing was wrong twice: live prover points failed
because TypeScript read gnark Fq2 limbs in the wrong order, and the correct end
state is that both languages perform only the field-range check the syscall
performs. Fixture id `off-curve-g2-compress-shared-accept`. A G2 limb at or
above the base modulus is refused by both and is the shared rejection for that
clause.

**Error taxonomy.** Rust folds parse, point, and rail failures into
`ClientError::ProofParse`. TypeScript names `CLIENT_PROOF_PARSE`,
`CLIENT_PROOF_POINT`, and `CLIENT_PROOF_RAIL_MISMATCH`. The suite compares
categories inside each language's taxonomy and records the mapping in the
fixture; it does not pretend the strings match.

**Unknown response fields.** Serde ignores unknown keys on `GnarkProofJson`, and
TypeScript reads named fields only. Both accept a proof carrying
`unexpected_field`. Fixture id `unknown-response-field` pins
`disposition: "accept-forward-compat"`. Rejection would be a coordinated API
change with no soundness win; the Go prover's `ProofJSON` is additive-tolerant.

## Gaps

The `y1 == 0 && isLargest(y0)` G2 parity branch stays `unavailable`. An algebraic
solve finds on-curve points with `y.c1 == 0` (first hit at `x1 = 2`), but every
constructed point fails the r-torsion check arkworks enforces for prime-order
G2. Expected `|G2 ∩ locus|` is O(1) in a 2^254 group, so there is no short
prime-order witness. The skip is backed by that evidence, not a failed search.

P1 public-input assembly files were not touched; no handoff beyond staying out
of that worker's paths.

## Control edits

Each edit was applied to `sdk-libs/ts/client/src/prover/proof.ts`, the package
rebuilt, the new suite observed to fail, and the file reverted.

Disabling the rail mismatch guard failed `commitment-on-eddsa-rail` and
`missing-commitment-on-p256-rail` only. Skipping A negation failed the seven
non-identity valid rows whose uncompressed A depends on negation, and left the
identity rows green because negating zero is zero. Dropping the modulus check
failed only `coordinate-at-modulus`. Making `validateG1` a no-op failed only
`off-curve-g1-compress`. Requiring both commitment fields before treating a
commitment as present failed `commitment-only` and `pok-only`, which otherwise
would have become silent rail mismatches.

Those five edits are why this suite is evidence rather than decoration.

## Gates

From the repository root: `npm run build`, `npm run test:unit` (2091 passed),
and `npm run check:static` were green after the suite landed.
`cargo run -p xtask --bin proof-response-parity -- --check` and
`cargo clippy -p xtask --bin proof-response-parity -- -D warnings` were green.
`fixtures-check.mjs` lists the new binary. The full fixtures gate still fails on
a pre-existing `ts-fixtures --check` drift in `client/errors-v1.json` that
reproduces at the suite's base commit `3d846008` without these changes; it is
outside P3's scope.
