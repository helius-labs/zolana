# P3. Proof response parsing and compression

Suite P3 of [proof-and-key-parity.md](../proof-and-key-parity.md): gnark response
parsing, A negation, G1/G2 compression, commitment presence versus the requested
rail, and the rejection surface for malformed prover responses.

## Bottom line

**P3 does not fully certify.** The shared accept and reject surface for parsing
and compression is strong where both languages already agreed, and the new
Rust-generated fixture closes the parity-bit, identity, leading-zero, structural
row-count, truncated/extended, and rail-confusion gaps that the older suites
only partly covered. Two clauses remain open: unknown response fields are
accepted by both languages rather than rejected, and no frozen G2 point was
found for the `y1 == 0 && isLargest(y0)` compression branch within a 50 000
scalar search. One real divergence is recorded: TypeScript refuses an off-curve
G2 at compress while Rust's `alt_bn128_g2_compress_be` accepts it.

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
The unknown-field row records shared acceptance. The off-curve G2 row records the
Rust/TypeScript divergence.

## Divergences

**Off-curve G2 at compress.** Solana's `alt_bn128_g2_compress_be` does not
validate the G2 curve equation; the SIMD for that syscall says so explicitly.
TypeScript calls `bn254.G2.Point.fromAffine(...).assertValidity()` and refuses
the same bytes. Fixture id `off-curve-g2-compress-divergence` pins both
outcomes. This was not changed on either side. A G2 limb at or above the base
modulus is refused by both and is the shared rejection used for that clause.

**Error taxonomy.** Rust folds parse, point, and rail failures into
`ClientError::ProofParse`. TypeScript names `CLIENT_PROOF_PARSE`,
`CLIENT_PROOF_POINT`, and `CLIENT_PROOF_RAIL_MISMATCH`. The suite compares
categories inside each language's taxonomy and records the mapping in the
fixture; it does not pretend the strings match.

**Unknown response fields.** Serde ignores unknown keys on `GnarkProofJson`, and
TypeScript reads named fields only. Both accept a proof carrying
`unexpected_field`. P3 asked for a rejection vector here; the honest shared
behavior is acceptance, so the rejection clause stays unmet and the fixture pins
that both sides still accept.

## Gaps

The `y1 == 0 && isLargest(y0)` G2 parity branch has no frozen point. A search
over the first 50 000 scalar multiples of the G2 generator found none with
`y.c1 == 0`. The fixture marks that row `unavailable` and the TypeScript test
skips it. Closing it needs either a longer constructive search or an explicit
authoritative point from the compression implementation.

Unknown-field rejection remains open until an owner decides whether the parser
should `deny_unknown_fields` (Rust) and mirror that in TypeScript. That would be
a protocol/API change, not a silent port fix.

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
`fixtures-check.mjs` includes the new binary.
