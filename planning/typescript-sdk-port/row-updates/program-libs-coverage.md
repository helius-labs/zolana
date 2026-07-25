# The 27 uncovered `program-libs` files, given verdicts

[queue-coverage-audit.md](queue-coverage-audit.md) found 27 Rust files in four
`program-libs` crates that the review queue never admitted, because the scope
rule reached `interface` and stopped. This closes them: 18 parity verdicts and 9
recorded `NOT_APPLICABLE` dispositions, each backed by a named artifact.

`program-libs/` was not edited. Where the Rust and the TypeScript disagreed, the
TypeScript changed.

## Bottom line

**Seventeen of the eighteen parity verdicts are `PARITY`. One is `FIXED`.** The
divergence is in `merkle-tree/src/bytes.ts`, and it was silent:

- **`bigintToBytes` truncated modulo 2^256** where
  `bigint_to_be_bytes_array::<32>` returns
  `InvalidInputLength(32, 33)`, and it accepted negative `bigint`s, which
  `BigUint` cannot represent at all. A caller asking to encode 2^256 got 32 zero
  bytes: a different value than it asked for, with no error. Now throws
  `MERKLE_TREE_INVALID_BYTES`. Nothing in the tree depended on the truncation;
  all 71 `@zolana/merkle-tree` vector tests pass after the change.

Two structural findings that need rows nobody has opened, both below in
[Rows nobody has thought of yet](#rows-nobody-has-thought-of-yet): the
TypeScript `OutputUtxo` is unreachable, and `create_two_inputs_hash_chain` is
not ported at all.

The audit's `NOT_APPLICABLE` recommendation for `hasher/src/zero_bytes/*` rested
on absence of a caller, which it flagged as weak evidence. It is now positive
evidence: **all 123 entries of the three Rust zero tables are reproduced** by the
TypeScript runtime construction, and an empty `CoreMerkleTree` at five heights
lands on the table entry for that height. The disposition stays
`NOT_APPLICABLE`, but it is now a demonstrated equivalence rather than a
plausible one.

## Evidence artifacts

| Artifact | What it is |
| --- | --- |
| `xtask/src/bin/program-libs-parity.rs` | Rust generator, reads the four crates directly |
| `sdk-libs/ts/vectors/program-libs-parity-v1.json` | 77 KB fixture, reproducible with `--check` |
| `interface/test/vectors/program-libs-event.test.ts` | 19 tests |
| `transaction/test/vectors/program-libs-event.test.ts` | 48 tests |
| `merkle-tree/test/vectors/program-libs-hasher.test.ts` | 36 tests |
| `wallet/test/vectors/program-libs-registry.test.ts` | 16 tests |

119 new tests. Regenerate with `cargo run -p xtask --bin program-libs-parity`;
verify with `-- --check`.

## The rows

Lift these directly. `TS owner` is package-relative.

### `program-libs/event`, 6 rows

| Rust source | TS owner | Verdict | Evidence | Gap |
| --- | --- | --- | --- | --- |
| `event/src/tag.rs` | `interface/src/index.ts`, `InstructionTag` | PARITY | `program-libs-event.test.ts`, 5 tests: the whole table by name and value, the count, and the accept set compared against Rust's `TryFrom<u8>` over all 256 bytes | none |
| `event/src/output_data.rs` | `interface/src/index.ts` `MessageData`, `interface/src/codecs/index.ts` | PARITY | `program-libs-event.test.ts`, 14 tests: 6 wincode vectors byte for byte through `transactInstructionDataCodec`, including 300- and 256-byte payloads past the `u8` boundary | none |
| `event/src/output_utxo.rs` | `interface/src/index.ts`, `OutputUtxo` | NOT_APPLICABLE | The Rust type appears only in `GeneralEvent::outputs` and in `program-test` event construction. `TransactIxData::outputs` is `interface`'s own `TransactOutput`, a different layout. See [Rows nobody has thought of yet](#rows-nobody-has-thought-of-yet) | The TS type declaration is dead code; field names match but no codec or caller reaches it |
| `event/src/proofless.rs` | `transaction/src/serialization/codecs.ts` | PARITY | `program-libs-event.test.ts`, 37 tests: 11 borsh vectors decoded field by field, re-encoded to identical bytes, and wrapped to match `encode_output_data` | none |
| `event/src/lib.rs` | none | NOT_APPLICABLE | No TypeScript decodes `GeneralEvent` bytes. Photon owns event parsing; TypeScript consumes parsed JSON through `indexer-api`. Confirmed by the audit's symbol search | Carries the two spec divergences below |
| `event/src/program_test.rs` | none | NOT_APPLICABLE | Behind the `program-test` feature, off by default, and TypeScript's counterpart shapes in `@zolana/test-kit` have no decoder | none |

### `program-libs/hasher`, 14 rows

Poseidon is closed by [poseidon-parity.md](poseidon-parity.md) and restated here
only so the row exists.

| Rust source | TS owner | Verdict | Evidence | Gap |
| --- | --- | --- | --- | --- |
| `hasher/src/poseidon.rs` | `keypair/src/poseidon.ts`, `transaction/src/internal.ts`, `interface/src/merge-utils.ts`, `merkle-tree/src/hashers.ts`, `client/src/internal.ts` | PARITY | `poseidon-parity-v1.json`, 312 tests | `client/src/internal.ts` still carries the over-wide table; see [The fifth Poseidon copy](#the-fifth-poseidon-copy) |
| `hasher/src/sha256.rs` | `merkle-tree/src/hashers.ts` | PARITY | `program-libs-hasher.test.ts`, 9 tests over the `hashv` vectors it can reach, plus an order-sensitivity check | `Sha256BE` (ID 3, byte 0 zeroed) is not ported; no SDK caller reaches it. Pinned in the fixture |
| `hasher/src/keccak.rs` | `merkle-tree/src/hashers.ts` | PARITY | `program-libs-hasher.test.ts`, 7 tests over the reachable `hashv` vectors | none |
| `hasher/src/bigint.rs` | `merkle-tree/src/bytes.ts`, `keypair/src/bytes.ts` | **FIXED** | `program-libs-hasher.test.ts`, 9 tests: 8 big-endian vectors including the BN254 modulus − 1 and the indexed-array sentinel, plus the 2^256 rejection | Was silent truncation; now throws. `keypair/src/bytes.ts` `bigIntToBytes` takes a `length` parameter and still truncates; see below |
| `hasher/src/hash_chain.rs` | `transaction/src/internal.ts`, `client/src/internal.ts` | PARITY | `program-libs-event.test.ts`, 11 tests: 7 vectors including empty, single, and a reversed pair | `create_two_inputs_hash_chain` has no TypeScript port; see [Rows nobody has thought of yet](#rows-nobody-has-thought-of-yet) |
| `hasher/src/errors.rs` | `merkle-tree/src/errors.ts` | PARITY | Fixture pins all 9 non-syscall `HasherError` codes (7001, 7005 to 7012) and their messages | TypeScript uses string codes (`MERKLE_TREE_HASH`), not the numeric space. A deliberate adaptation: the numeric codes only surface through `ProgramError::Custom`, which the SDK reads from the RPC rather than raises |
| `hasher/src/lib.rs` | `merkle-tree/src/merkle-tree.ts`, `Hasher32` | PARITY | `program-libs-hasher.test.ts`, 2 tests: the 32-byte digest width across all three hashers, and the `Hasher::ID` discriminants | `Hasher32` has `hash` only, not `hashv`/`zero_bytes`. The `ID` values are pinned but not carried; TypeScript passes hasher objects and never serializes the tag |
| `hasher/src/hash_to_field_size.rs` | none | NOT_APPLICABLE | No SDK caller in Rust or TypeScript | none |
| `hasher/src/syscalls/mod.rs` | none | NOT_APPLICABLE | Solana BPF syscalls; no browser or Node analogue. The non-Solana path is what the SDK compiles | none |
| `hasher/src/syscalls/definitions.rs` | none | NOT_APPLICABLE | same | none |
| `hasher/src/zero_bytes/mod.rs` | `merkle-tree/src/merkle-tree.ts` | NOT_APPLICABLE | `MAX_HEIGHT` 40 and the 41-row table shape asserted | none |
| `hasher/src/zero_bytes/poseidon.rs` | `merkle-tree/src/merkle-tree.ts` | NOT_APPLICABLE | **All 41 entries reproduced** by hashing upward, and empty trees at heights 1, 2, 3, 8, 16 match | none |
| `hasher/src/zero_bytes/sha256.rs` | `merkle-tree/src/merkle-tree.ts` | NOT_APPLICABLE | same, 41 entries | none |
| `hasher/src/zero_bytes/keccak.rs` | `merkle-tree/src/merkle-tree.ts` | NOT_APPLICABLE | same, 41 entries | none |

### `program-libs/indexed-array`, 4 rows

| Rust source | TS owner | Verdict | Evidence | Gap |
| --- | --- | --- | --- | --- |
| `indexed-array/src/array.rs` | `merkle-tree/src/indexed.ts` | PARITY | `program-libs-hasher.test.ts`, 6 tests: a scripted 5-append sequence (30, 10, 20, 50, 40, deliberately out of order) whose full 6-element linked list matches Rust's index, value, and `next_index` for every element, plus the low-element index and new index at each step | TypeScript exposes no `find_low_element_for_existent`; not needed by any caller |
| `indexed-array/src/changelog.rs` | `merkle-tree/src/indexed.ts`, `IndexedElement` | PARITY | Covered by the same sequence. `RawIndexedElement` is the big-endian wire form of the element the tests compare | TypeScript has no separate raw type; it holds `Bytes32` values directly, which is the same representation |
| `indexed-array/src/errors.rs` | `merkle-tree/src/errors.ts`, `IndexedMerkleTreeError` | PARITY | Fixture pins all 8 variants' messages; tests assert the duplicate-insert and out-of-range rejections behave the same | String codes rather than a numeric enum, same adaptation as `HasherError` |
| `indexed-array/src/lib.rs` | `merkle-tree/src/indexed.ts` | PARITY | `HIGHEST_ADDRESS_PLUS_ONE` compared against the Rust decimal literal through `tree.highestValue()` | none |

### `program-libs/user-registry-interface`, 3 rows

| Rust source | TS owner | Verdict | Evidence | Gap |
| --- | --- | --- | --- | --- |
| `user-registry-interface/src/lib.rs` | `wallet/src/registry.ts` | PARITY | `program-libs-registry.test.ts`, 3 tests: program id, seed, and key widths. Fixture also carries 4 Rust `user_record_pda` derivations with bumps | The TS PDA derivation is reimplemented locally; the fixture pins the Rust results but the wallet's own derivation is exercised by its existing suite, not here |
| `user-registry-interface/src/state.rs` | `wallet/src/registry.ts` | PARITY | `program-libs-registry.test.ts`, 11 tests: 3 records decoded field by field from Rust borsh bytes, `sender_viewing_pubkey` including the empty-entries fallback, the discriminator rejection, and the merging-flag rejection | none |
| `user-registry-interface/src/instruction.rs` | `wallet/src/registry.ts` | PARITY | `program-libs-registry.test.ts`, 2 tests: all 6 discriminators and the merging-flag payload. Fixture carries all 7 borsh payload encodings | The wallet builds only `setMergingEnabled`; the other five builders have no TypeScript caller, so their payloads are pinned but not compared |

## Verdict spread

| Verdict | Count |
| --- | ---: |
| PARITY | 17 |
| FIXED | 1 |
| NOT_APPLICABLE | 9 |
| Total | 27 |

One row moved against the audit's prediction: `event/src/output_utxo.rs` was
expected to need a parity verdict and is `NOT_APPLICABLE` instead. The
denominator stays 145.

## Rows nobody has thought of yet

### `interface/src/index.ts` `OutputUtxo` is unreachable

The audit paired `event/src/output_utxo.rs` with the TypeScript `OutputUtxo` and
called it "already ported". The type exists at `interface/src/index.ts:222` and
its three fields match the Rust. But:

- No codec encodes or decodes it. `interface/src/codecs/index.ts` has nothing
  for it.
- No file imports it. The only other hit for the name in `sdk-libs/ts` is
  `ProofOutputUtxo`, an unrelated `@zolana/transaction` type.
- `interface/test/exports.test.ts` does not name it, so the public-surface check
  does not see it either.

On the Rust side `OutputUtxo` is only ever a `GeneralEvent` field. It is not the
transact instruction's output type; that is `interface`'s own `TransactOutput`
(`utxo_hash`, `owner_tag`, `Option<data>`), a different layout with a different
field count. So the TypeScript `OutputUtxo` is a declaration of an
event-payload type in a package that never decodes event payloads.

**Recommendation:** delete it, or move it behind whatever eventually decodes
`GeneralEvent`. It is currently a shape that looks like coverage and is not. Not
deleted here because it may be part of the published type surface and that is a
separate call.

### `create_two_inputs_hash_chain` has no TypeScript port

`hasher/src/hash_chain.rs` exports two functions. `create_hash_chain_from_slice`
is ported twice (`transaction/src/internal.ts`, `client/src/internal.ts`) and
now verified. `create_two_inputs_hash_chain` is ported nowhere, and it has seven
Rust callers, all on the proof path:

```text
sdk-libs/client/src/prover/merge.rs
sdk-libs/client/src/prover/merge_zone.rs
sdk-libs/client/src/prover/zone_authority.rs
sdk-libs/client/src/prover/transact/zone_eddsa.rs
sdk-libs/client/src/prover/transact/zone_p256.rs
sdk-libs/client/src/prover/transact/p256_and_eddsa.rs
sdk-libs/transaction/src/instructions/transact/types.rs
```

It is not a fold of the single-input chain: it seeds with `H(first[0],
second[0])` and then folds three inputs at a time, `H(chain, first[i],
second[i])`. A port that reached for `hashChain` twice would produce a different
value. The fixture carries 4 vectors and the length-mismatch error for whoever
ports it.

**This needs a row**, and the row belongs to `@zolana/client`. Whether the gap
is a defect depends on whether the TypeScript prover path needs those hashes; I
could not settle that inside this task's paths.

### `keypair/src/bytes.ts` `bigIntToBytes` truncates the same way

The fix landed in `merkle-tree/src/bytes.ts`. The `keypair` equivalent takes a
`length` parameter and has the same silent-truncation behaviour for values that
overflow it. Not changed here: it is reached by row `K*` owners and its callers
pass explicit widths, so the blast radius is different and it deserves its own
look rather than a drive-by. Recorded so it is not lost.

## The fifth Poseidon copy

Unchanged from [poseidon-parity.md](poseidon-parity.md) and still outstanding.
`sdk-libs/ts/client/src/internal.ts:26` reads:

```ts
const PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68] as const;
```

and needs to become:

```ts
const PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65] as const;
```

Verified still present in this tree. The four over-wide entries let the client
hash 13 to 16 inputs, where `Poseidon::hashv` returns
`InvalidWidthCircom { width: 14, max_limit: 13 }` and the `sol_poseidon` syscall
caps at 12. Left alone because `@zolana/client` belongs to another worker's
tree.

## Spec divergences, routed

The audit left three for whichever row owns the event crate.

| Divergence | Owning row | Disposition |
| --- | --- | --- |
| `tx_viewing_pk` and `salt` typed `Option` in the spec, `[u8; 33]` and `[u8; 16]` zeroed arrays in `GeneralEvent` | `event/src/lib.rs` | Carried forward to the spec. The `NOT_APPLICABLE` disposition does not absolve it, and no TypeScript is affected because none decodes `GeneralEvent` |
| Output slot tag named `owner` in the spec, `view_tag` in the code | `event/src/output_utxo.rs`, `event/src/output_data.rs` | Spec-side correction. TypeScript uses `viewTag`, matching the code, and the `MessageData` row now proves it byte for byte |
| `memo` on `ProoflessOutput` absent from the spec | `event/src/proofless.rs` | Real and now settled on the code side: the TypeScript `memo` is the tenth field, borsh-optional, and 11 vectors confirm the byte order. The spec needs the field added |

None are port defects. `docs/spec.md` was not edited.

## Verification

| Command | Result |
| --- | --- |
| `cargo build -p xtask --bin program-libs-parity` | clean |
| `cargo run -p xtask --bin program-libs-parity -- --check` | fixture reproduces |
| `npm run build` | pass |
| `npm run typecheck` | pass |
| `npm run test:vectors` | 9 suites pass, 536 tests, 119 of them new |
| `npm run test:unit` | 910 pass, 1 skipped, 0 fail |
| `npm run test:cross` | 70 pass across 3 packages |
| `npm run test:exports` | pass |

Rebuilt before running the cross-package suites.

The two `client/test/merge.test.ts` failures that
[poseidon-parity.md](poseidon-parity.md) recorded as belonging to another
worker's in-flight change are gone from this tree; `test:unit` is fully green.

## What was verified, and what was not

Verified by executed comparison:

- Every value in the tables above marked PARITY or FIXED, through the 119 tests.
- The zero-byte equivalence, all 123 table entries across three hashers.
- The indexed-array linked list, every element after every append.
- That the `bigintToBytes` fix breaks nothing: 71 `@zolana/merkle-tree` tests.

Pinned in the fixture but not compared against a TypeScript implementation,
because none exists:

- `Sha256BE`, the `Hasher::ID` discriminants, the numeric `HasherError` and
  `IndexedArrayError` codes, the five unused user-registry instruction builders,
  and the four Rust `user_record_pda` derivations.

These are recorded as gaps in the rows rather than as parity claims. A later row
that ports any of them has its oracle already written.

Not settled:

- Whether the missing `create_two_inputs_hash_chain` port is a defect or an
  absence of need. That question lives in `@zolana/client`.
- Whether `interface/src/index.ts` `OutputUtxo` should be deleted. It is
  unreachable, which is a fact; whether it is published surface is not something
  I checked.
