# Poseidon parity: the TypeScript reimplementations against `zolana-hasher`

[queue-coverage-audit.md](queue-coverage-audit.md) found that
`program-libs/hasher/src/poseidon.rs` had been reimplemented four times in
TypeScript with no review row comparing any of them against the Rust. This is
that comparison, done by parameter and by fixture rather than by reading.

## Bottom line

**All of them agree with Rust, and with each other, on every input Rust will
accept.** The round constants and the MDS matrix are identical for all twelve
supported arities, not merely consistent on the vectors anyone had tried. Two
divergences exist and both are at the edge of the input domain rather than in
the digest:

1. **Arity 13 through 16.** The `keypair` and `transaction` tables carried four
   partial-round counts past the point where Rust stops, so `poseidon` returned
   a digest for thirteen inputs where `Poseidon::hashv` returns
   `InvalidWidthCircom { width: 14, max_limit: 13 }`. Fixed in this work; both
   tables now stop at twelve, matching the `interface` copy. Exposed by thirteen
   32-byte zero inputs, which produced
   `02f7b90db3c03568c7b147c50d927b1ef6271e78d8ee044e99381e67b2817fde` in
   TypeScript and an error in Rust.
2. **Inputs shorter than 32 bytes.** Rust rejects them outright
   (`InvalidInputLength { len: 31, modulus_bytes_len: 32 }`); `keypair`,
   `transaction`, and the `interface` copy read them as big-endian integers.
   This is a wider input domain, not a different digest, and it is now pinned:
   a 31-byte input has to produce the Rust hash of the same value right-aligned
   into 32 bytes. Left as it is, because every caller already right-aligns and
   because no input Rust accepts can take this path.

There is also a **fifth** reimplementation the audit did not count, in
`sdk-libs/ts/client/src/internal.ts`. It still carries the sixteen-entry table.
See [The fifth copy](#the-fifth-copy).

## What was compared

Not just outputs. Every parameter the digest depends on:

| Parameter | Rust | TypeScript | Verdict |
| --- | --- | --- | --- |
| Field modulus | BN254 `Fr`, `21888242871839275222246405745257275088548364400416034343698204186575808495617` | same literal in three copies, `bn254_Fr.ORDER` in `hashers.ts` | same |
| Round constants (`ark`) | `light_poseidon::parameters::bn254_x5`, hard-coded circom tables | regenerated from the Grain LFSR by `@noble/curves` | **identical, every element, arity 1 to 12** |
| MDS matrix | same source, Cauchy `1/(x_i + y_j)` | same construction in `grainGenConstants` | **identical, every element** |
| Full rounds | 8 | 8 | same |
| Partial rounds | `56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65` | same twelve; two copies had four more | fixed |
| S-box | `alpha = 5` | `sboxPower: 5` | same |
| Domain separation | state element 0 seeded with `Fr::zero()` | `[0n, ...values]` | same |
| Digest | state element 0 after the permutation | `[0]` of the returned state | same |
| Maximum arity | 12 (`MAX_X5_LEN = 13`, width = inputs + 1) | 12 after the fix | fixed |

The round-constant result is the load-bearing one and it was not obvious in
advance. Rust reads tables that were generated once and committed;
TypeScript regenerates them at runtime from the Grain LFSR seeded with
`(field, sbox, 254, t, R_F, R_P)`. Those are two different provenances for the
same numbers, and nothing had ever checked that they land in the same place.
They do, for all 6,798 round constants and 819 matrix entries across the twelve
arities.

## Where the four sit

| File | Table | Field handle | Arity reach | How it is reached |
| --- | --- | --- | --- | --- |
| `keypair/src/poseidon.ts` | 12 entries (was 16) | `Field(BN254_MODULUS)` | 1 to 12 | `hash.ts`, `nullifier-key.ts`, `merge/core.ts` |
| `transaction/src/internal.ts` | 12 entries (was 16) | `Field(BN254_MODULUS)` | 1 to 12 | `utxo.ts`, `instructions/transact.ts`, `hashChain` |
| `interface/src/merge-utils.ts` | 12 entries | `Field(BN254_MODULUS)` | 1 to 12 | private; `ciphertextHash`, `pkFieldCompressed` |
| `merkle-tree/src/hashers.ts` | 56 and 57 inline | `bn254_Fr` | 1 and 2 | `poseidonHasher.hash`, `.hashBytes` |

`merkle-tree` is the odd one and the strictest. It takes its field from
`@noble/curves`'s exported `bn254_Fr` rather than rebuilding one from the
modulus literal (the two coincide, and the test now asserts that), it only
builds the two permutations a Merkle tree needs, and it is the only copy that
requires exactly 32 bytes, so it refuses everything Rust refuses.

### The duplication

`keypair/src/poseidon.ts` and the Poseidon block of
`transaction/src/internal.ts` are the same code. The constant, the `Fp`, the
permutation cache, the `permutation()` body, and the `poseidon()` body match
line for line; they differ only in the error type thrown (`KeypairError`
against `TransactionError`) and in `keypair` also range-checking `inputCount`
before the table lookup. `interface/src/merge-utils.ts` is a third instance of
the same code with `InterfaceError` and a private, unexported `poseidon`.

**Recommendation, not performed here:** collapse the three onto
`@zolana/keypair`'s `poseidon`, which would mean exporting it (it is currently
internal to the package) and letting the two callers wrap its error. That is a
public-surface change touching three packages and an `api:check` report, and
the tables are load-bearing, so it wants its own change with its own review.
The fixture added here makes that refactor safe to attempt: any drift in the
consolidation fails 100 vectors and 12 parameter digests per package.

`merkle-tree/src/hashers.ts` should **not** be folded in. It is deliberately
narrower and stricter, and it is the only copy that does not depend on the
modulus being retyped correctly.

## The fifth copy

`sdk-libs/ts/client/src/internal.ts:26` holds a fourth
`PARTIAL_ROUNDS = [56, 57, ..., 65, 70, 60, 64, 68]` and a `poseidon` that takes
and returns `bigint` instead of bytes. It is used by `prover/assembly.ts`,
`prover/merge.ts`, and the client's `hashChain`, all at arity 2 and 4.

Its parameters are the same as the other four, so it produces the same digests,
but it still carries the four over-wide entries. The same one-line narrowing
applies:

```ts
const PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65] as const;
```

Left alone because `sdk-libs/ts/client` sits outside this task's paths. It
should get the change and a copy of the vector test; the fixture is already
package-agnostic.

The audit's count of four should read five, and the recommended
`program-libs/hasher/src/poseidon.rs` row should name all five TypeScript
owners.

## The fixtures

Generated by `xtask/src/bin/poseidon-parity.rs`, written to
`sdk-libs/ts/vectors/poseidon-parity-v1.json`:

```bash
cargo run -p xtask --bin poseidon-parity            # regenerate
cargo run -p xtask --bin poseidon-parity -- --check  # fail on drift
```

It deliberately does **not** live under `sdk-libs/ts/fixtures`. That tree is the
frozen P00 set, and `xtask/src/bin/ts-fixtures.rs` verifies it by comparing the
whole directory listing against what it regenerates, so an extra file there
fails `npm run fixtures:check` by existing. (That check is already unable to run
on this branch for an unrelated reason: `assert_frozen_sources` sees drift in
`sdk-libs/client/src/prover` and `sdk-libs/transaction`.)

What the fixture carries:

| Section | Contents |
| --- | --- |
| `field` | modulus as decimal and as bytes, and modulus − 1 |
| `parameters.perArity` | width, partial rounds, constant counts, and SHA-256 over every round constant and every MDS entry in big-endian row-major order, for arity 1 to 12 |
| `vectors` | 100 hashes: all-zero, all-one, ascending fill, all modulus − 1, modulus − 1 in the first slot only, in the last slot only, an ascending counter, and a deterministic pseudo-random set, for each of the twelve arities, plus four arity-2 order-sensitivity pairs |
| `rejects` | six inputs Rust refuses, each tagged with a `kind` so a port can be checked against the ones it must reproduce |
| `shortInputs` | four sub-32-byte inputs pinned to the Rust hash of their right-aligned form |
| `ciphertextHashes` | 18 lengths covering every chunk count 1 to 12 plus the 1, 15, 17, 31, 33 and 191-byte boundaries, and three lengths that need a thirteenth input |
| `mergeUtils.pkFields` | `pk_field_compressed` and `owner_pk_field_compressed` for an even-y and an odd-y compressed P256 key |

The parameter digests are what make this a parameter comparison rather than a
spot check. A test that regenerates its constants and hashes them the same way
compares all 949 round constants and 169 matrix entries of the widest arity in
one assertion, so a single wrong constant fails.

The vectors were chosen for the failure modes a matching-on-easy-inputs
implementation still has. All-zero and all-one catch a wrong domain tag.
Modulus − 1 in the first and in the last slot separately catches an input
loaded into the wrong state element. The ascending counter and the arity-2
`(0,1)` against `(1,0)` pair catch a reversed input order, which every
symmetric vector hides. Every arity is present because the partial-round count
changes per arity and a single wrong entry only shows at that width.

### Coverage per package

| Package | Tests | Reaches Poseidon through |
| --- | --- | --- |
| `@zolana/keypair` | 124 | `poseidon` directly: 12 parameter digests, 100 vectors, 5 rejects, 4 short inputs, field and arity-bound assertions |
| `@zolana/transaction` | 122 | `poseidon` from `internal.ts`: 12 parameter digests, 100 vectors, 5 rejects, 4 short inputs, field assertion |
| `@zolana/merkle-tree` | 29 | `poseidonHasher.hash` and `.hashBytes`: 2 parameter digests, 20 arity-1 and arity-2 vectors, the 4 rejects it can reach |
| `@zolana/interface` | 37 | `ciphertextHash` at every chunk count 1 to 12, its three rejections, and the two P256 field hashes; plus 12 parameter digests |

### That the fixture bites

Changing the arity-12 partial-round count from 65 to 64 in
`keypair/src/poseidon.ts` fails the eight arity-12 vectors
(`poseidon-zeros-12`, `-ones-12`, `-fill-12`, `-max-12`, `-max-first-12`,
`-max-last-12`, `-counter-12`, `-pseudo-12`) and nothing else. The parameter
digests survive it, because they rebuild the constants from the round count the
fixture carries rather than from the one the module holds, which is why the
vectors and the digests are both needed. Reverted immediately; this was a
control, not a change.

## Method

The parity claim rests on two independent comparisons, not on one.

**Parameters.** A probe built against `light-poseidon` 0.4.0 dumped `ark` and
`mds` for every arity 1 to 12 as big-endian hex, and a Node probe regenerated
the same tables through `grainGenConstants` and compared element by element.
All twelve arities matched on both, with no shortfall in length. That
comparison is what the `arkSha256` and `mdsSha256` fields now preserve.

**Values.** The same probes hashed the zero, identity, ascending, and
modulus − 1 inputs at every arity 1 to 16 in TypeScript and 1 to 12 in Rust,
plus the arity-0, 31-byte, 33-byte, modulus, and above-modulus edges. Rust and
all four TypeScript copies agreed everywhere both produced a value. The three
arities Rust cannot reach are what became finding 1.

`zolana-hasher` delegates its non-Solana path to `light_poseidon::Poseidon::<Fr>::new_circom`,
so the probe and the committed generator exercise the same code; the generator
calls `zolana_hasher::Poseidon::hashv` rather than the crate underneath it.

## Verification

| Command | Result |
| --- | --- |
| `cargo test -p zolana-hasher --all-features` | pass |
| `cargo clippy -p xtask --bin poseidon-parity -- -D warnings` | clean |
| `cargo fmt -p xtask -- --check` | clean |
| `cargo run -p xtask --bin poseidon-parity -- --check` | verified, fixture reproduces |
| `npm run build` | pass |
| `npm run typecheck` | pass |
| `npm run test:vectors` | 9 suites pass, 312 of the tests new |
| `npm run test:cross` | pass |
| `eslint` and `prettier --check` on the touched files | clean |
| `npm run test:unit` | 776 pass, 2 fail |

The two unit failures are `client/test/merge.test.ts`, on compiled transaction
bytes. They are not from this work: restoring the sixteen-entry tables,
rebuilding, and rerunning reproduces both failures unchanged, so they belong to
another worker's in-flight change to the merge path.

## For the checklist owner

The recommended `program-libs/hasher/src/poseidon.rs` row can be opened at
`PARITY`, with these qualifications:

- Parity holds across the whole Rust input domain, established by parameter
  digest and by 100 Rust-generated vectors per port, not by sampling.
- Name five TypeScript owners, not four; `client/src/internal.ts` is the fifth.
- The arity divergence was found and closed here for `keypair` and
  `transaction`; `client` still carries it and needs the one-line follow-up
  above before the row can claim all five.
- The sub-32-byte input domain is deliberately wider in three ports than in
  Rust, is pinned to the right-aligned Rust digest, and no caller relies on it.
- The three-way duplication is real and should be consolidated in a separate
  change. `merkle-tree/src/hashers.ts` is not part of that.
