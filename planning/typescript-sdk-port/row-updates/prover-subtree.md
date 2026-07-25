# Prover subtree: C06-C20

What the TypeScript `@zolana/client` prover subtree does, measured against
`sdk-libs/client/src/prover/` rather than read against it. Every verdict below
names the thing that demonstrates it. Where a row is not closed, the reason is
recorded instead of a verdict.

Two artifacts carry most of the weight:

- `sdk-libs/client/tests/ts_prover_oracle.rs`, a Rust `#[test]` generator that
  runs the production `assemble` and the production `prover::field` helpers and
  writes what they returned to `sdk-libs/ts/client/test/oracles/`. Regenerate
  with `ZOLANA_UPDATE_TS_ORACLES=1 cargo test -p zolana-client --test
  ts_prover_oracle`; the test fails if the committed file is stale, so the
  oracle cannot drift from the Rust it came from.
- The TypeScript tests that rebuild the same inputs from the same seeds and
  assert equality: `test/vectors/prover-edge-cases.test.ts`,
  `test/vectors/field-alignment.test.ts`, `test/prover/circuit-types.test.ts`,
  `test/prover/client.test.ts`.

## Verdicts

| Row | Verdict | Evidence |
| --- | --- | --- |
| C06 `field.rs` | PARITY on alignment, decode, and the length bound; one asymmetry pinned | `test/vectors/field-alignment.test.ts` against `oracles/field-alignment-v1.json` |
| C07 `inputs.rs` | PARITY for the dummy witness, including an interior dummy | `test/vectors/prover-edge-cases.test.ts` cases 2 and 3 |
| C08 `proof.rs` | Three rejection divergences fixed; one deliberate strictness left | `test/prover.test.ts`, commit `52ca1e25` |
| C09 `json.rs` | NOT CLOSED for the merge body | reason below |
| C10 `witness.rs` | PARITY on the four cases the shape sweep cannot reach | `test/vectors/prover-edge-cases.test.ts` |
| C11 `eddsa.rs` | PARITY | same, case 1 (eddsa rail, SPL public leg) |
| C12 `p256_and_eddsa.rs` | PARITY | same, cases 2-4 (mixed rails, two real P256 inputs) |
| C13 `zone_eddsa.rs` | Deferral confirmed | `test/prover/circuit-types.test.ts` |
| C14 `zone_p256.rs` | Deferral confirmed | same |
| C15 `transact/mod.rs` | PARTIAL, dispositions recorded | `test/prover/exports.test.ts`, `test/prover/circuit-types.test.ts` |
| C16 `merge.rs` | Aliasing closed | `test/merge.test.ts` "does not let a caller reach the instruction through the assembly buffers" |
| C17 `merge_zone.rs` | NOT CLOSED on values | reason below |
| C18 `zone_authority.rs` | Deferral confirmed | `test/prover/circuit-types.test.ts` |
| C19 `client.rs` | Poll bound closed | `test/prover/client.test.ts`, nine cases |
| C20 `prover/mod.rs` | PARTIAL, dispositions recorded | `test/prover/exports.test.ts` |

## The assembly cluster (C10, C11, C12)

`fixtures/client/prover-shapes-v1.json` pins twenty shapes, but each one is
built the same way: one real input in slot 0, dummies padding the tail, SOL-only
public amounts. The branches where the two languages could most plausibly
disagree were all outside that sweep. The new oracle adds four cases and
compares, per case, the whole witness (every `TransferInput` and
`TransferOutput` field, both rails), `publicInputHash`, the per-slot
`eddsaSignerIndex`, the nullifiers, the root indexes, and the serialized
`transact` instruction bytes:

1. `eddsa-public-spl-2-3`: an SPL public withdrawal with a trailing dummy.
2. `mixed-interior-dummy-eddsa-first-3-3`: a dummy between two real inputs
   owned by keys on different signature schemes, eddsa first.
3. `mixed-interior-dummy-p256-first-3-3`: the same with the order swapped, so
   the signer a dummy slot inherits differs between the two cases.
4. `p256-two-real-inputs-public-spl-2-2`: two real P256 inputs and an SPL leg.

Cases 2 and 3 are the discriminating pair for the per-slot signer index: a
dummy inherits the *first real input's* signer, so the two cases must produce
different `eddsaSignerIndexes`, and they do. A port that consumed
`realInputs[realSignerIndex++]` in map order rather than per padded slot would
produce the same list for both.

On the specific leads raised for this packet:

- **`findPublicSplAsset` is not a re-derivation risk.** Rust does not skip the
  scan; `SppProofInputs::public_amounts` calls `check_public_spl_asset` itself
  when `spl != 0`, over `input_utxos` chained with `output_utxos`, returning
  `MultiplePublicSplAssets` and `MissingPublicSplAsset`
  (`sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs:127-160`).
  The TypeScript scan is the same iteration order over the same two collections
  with the same two errors, gated on the same `spl !== 0`. What is true is that
  the TypeScript `PublicAmounts` carries no `asset` field, so the scan lives in
  `assembly.ts` while Rust's lives in the transaction crate. That is a
  duplication, not a behavioral difference, and oracle cases 1 and 4 exercise it
  with a real SPL leg and a dummy input in the scanned set.
- **The `privateTxHash` third chain is correct.** `PrivateTxHash::hash` with
  `address_hashes: None` builds `create_hash_chain_from_slice(&vec![[0u8; 32];
  input_hashes.len()])`
  (`sdk-libs/transaction/src/instructions/transact/types.rs:222-241`), which is
  what `assembly.ts:173` does. The value is compared per case by the oracle.
- **Dummy inputs agree.** The oracle carries each dummy's full `TransferInput`,
  so the computed nullifier, the zero `nullifierSecret`, the inherited roots and
  owner hash, and the padded path lengths are all compared, not just the shape.
- **`owner.is_zero()` and `isDummy()` select the same slots** on every case the
  oracle covers, including the interior dummies; had they differed, the proof
  count check would have consumed the spend proofs in a different order and the
  nullifier list would not match.

## C06, `prover::field`

`right_align_slice` pads on the left, rejects more than 32 bytes with
`FieldTooLong`, and `be` reads the result big-endian. Neither mentions the BN254
modulus. The port's `bytesField` adds the range check.

`oracles/field-alignment-v1.json` holds what Rust returned for eight inputs: the
empty slice, one byte, a leading-zero pair, 31 bytes, and four 32-byte values at
and around the modulus, plus the 33-byte rejection. The TypeScript test asserts
the same alignment and the same decoded value for each, and pins the single
difference: at `modulus` and at `0xff…ff`, Rust returns the number and
`bytesField` raises `CLIENT_INVALID_FIELD`.

That difference does not reject an assembly Rust completes. The values reaching
`bytesField` are 31-byte nullifier secrets, Poseidon outputs, and
caller-supplied `dataHash`/`zoneDataHash` values, and a caller-supplied hash at
or above the modulus already fails inside Poseidon when either language hashes
the UTXO (`ProofInputUtxo::hash` at `sdk-libs/transaction/src/utxo.rs:135-149`
feeds `data_hash` straight to `poseidon`). Both languages refuse it; they differ
only in which error names it.

## C08, `proof.rs`: three rejections relaxed

All three are the failure mode this packet was told to hunt for, TypeScript
refusing input Rust accepts, and all three are reachable, because `parseProof`
is exported from the public `./prover` subpath while `proof_from_gnark_json` is
`pub(crate)`.

| Input | Before | Rust |
| --- | --- | --- |
| a gnark response carrying any key outside the five known ones | `CLIENT_PROOF_PARSE` | `serde_json` ignores it |
| `"proof_commitment": []` on the eddsa rail | read as a commitment, then `CLIENT_PROOF_RAIL_MISMATCH` | `#[serde(default)] Vec<String>` plus `is_empty()`: no commitment |
| a coordinate written without the `0x` prefix | `CLIENT_PROOF_PARSE` | `hex_to_be_32` trims the prefix if present and parses the digits either way |

Fixed in `52ca1e25`; each is pinned by a case in `test/prover.test.ts`.

One divergence is left in place deliberately: `parseProof` still requires the
commitment's presence to match the requested rail. Rust infers the rail from
field presence, so an eddsa request answered with a commitment-bearing proof
builds a `TransactProof::P256` in Rust that cannot verify on chain. TypeScript
rejecting it is the better behavior and it rejects nothing legal.

## C16, the merge assembly's own buffers

`MergeAssembly` is frozen, but `Object.freeze` seals the object and the
nullifier array without sealing the `Uint8Array`s inside them, and those were
the buffers the `instructionData` closure read on every call. A caller holding
the frozen assembly could change what a later `instructionData()` emitted.

The checklist attributes the fix to Rust owning its `Vec<[u8; 32]>` by value.
That is not quite the argument: `MergeProofResult::instruction_data(&self)`
reads `self.nullifiers` too, so a `mut` binding has the same reach in Rust. The
reason to copy is that the TypeScript surface is frozen and therefore claims an
immutability it did not have. The fix copies every buffer the closure reads
(`outputHash`, the nullifiers, `privateTxHash`, `encryptedUtxo`) in both
directions, so two emissions cannot reach each other either. The test fails on
each of the four buffers if the copy is removed; that was checked by removing it.

## C19, the status poll

The prove request carried the 600 s bound; the status GET carried none, while
Rust's status GET goes through the same `reqwest::Client` that holds the
timeout. A status endpoint that accepts the connection and never answers hung
the TypeScript poll indefinitely, because `maxWaitMs` is only re-checked between
attempts. Fixed by composing a per-request timeout around the status fetch, and
the loop now fetches before it sleeps, as `poll_async` does.
`test/prover/client.test.ts` pins nine behaviors against the Rust arms:
completion, `failed`, the wait bound, a malformed body, an invalid `job_id`, a
4xx as final, a 5xx as transient, a transport failure as transient, and a
non-JSON body as final.

## C13, C14, C18: the deferral, as a property

`prover::json` writes eight circuit types. The shipped client can produce four.
`test/prover/circuit-types.test.ts` asserts both halves: `proverRequest` emits
`transfer-confidential` and `transfer-p256-confidential` for the two transfer
rails (run through the real `assemble`), and no `.ts` file under
`sdk-libs/ts/client/src` contains the quoted literal `"transfer-zone"`,
`"transfer-p256-zone"`, `"transfer-zone-authority"`, or `"address-append"`. The
test fails the moment a source file can name one, so the deferral stops being an
assertion about today's code and becomes a property of the package.

This is also the evidence for `BatchAddressAppendInputs` under C07 and for the
six absent prove entry points under C19: they are unreachable because nothing
can address the circuits they exist to reach.

## Rows not closed

**C09, the merge request body.** The transfer bodies are pinned against Rust
(`fixtures/api/prover-request-v1.json` plus the twenty shapes), and the merge
body shares the same `inputJson`, `outputJson`, and `hex` encoders as the
transfer body, so the encoding is covered transitively. What is not covered is
the merge key set and field naming, which rests on parallel hand-written lists
in `test/merge.test.ts` and in `json.rs`'s own unit test. I could not generate a
Rust merge body: `to_json_merge` and `to_json_merge_zone` are `pub(crate)`
(`sdk-libs/client/src/prover/json.rs:308-320`), so no integration test under
`sdk-libs/client/tests/` can call them, and reaching them through
`AsyncProverClient::prove_merge` requires standing up a mock HTTP server plus a
hand-built `MergeInputs`. Smallest fix, in a file I do not own: make those two
functions `pub` (or `pub(crate)` plus `#[cfg(any(test, feature = "test-utils"))]
pub`), after which the same generator pattern closes the row in a few lines.

**C17, `merge_zone.rs`.** The entry-point and zone-stamp findings hold as
recorded, and `test/merge.test.ts` pins the zone circuit type, the zone
instruction, and the message order against `oracles/merge-message-order-v1.json`.
There is still no Rust-generated oracle for the merge or merge-zone *values*
(the public input chain, the ciphertext contribution): `fixtures/client/merge.json`
and `merge_zone.json` are promised by `inventory.json` and absent, and both the
inventory and the xtask generator are outside this packet. The merge chain
therefore stays pinned by the frozen `fixtures/transaction/merge-v1.json` only.

**C15 and C20, the surface rows.** `test/prover/exports.test.ts` freezes the
runtime name set, and every omitted symbol now has a disposition: the zone
prover/result/witness types are the C13/C14/C18 deferral, `BatchAddressAppendInputs`
belongs to the forester, and `AsyncProverClient` has no counterpart because the
TypeScript client is already asynchronous. What keeps these rows off PARITY is
that `inventory.json` still names files that do not exist
(`src/prover/transact/index.ts`, `src/prover/merge-zone.ts`,
`src/prover/field.ts`), and that file is generated by `xtask`, which this packet
may not touch.

## Divergences found, with the input that exposes each

| # | Divergence | Triggering input | Status |
| --- | --- | --- | --- |
| 1 | `parseProof` rejected any unknown JSON key | a gnark response with one extra field, e.g. `{"proof": {...}, "note": "x"}` | fixed, `52ca1e25` |
| 2 | `parseProof` read `[]` as a present commitment | `"proof_commitment": []` on an eddsa proof | fixed, `52ca1e25` |
| 3 | `parseCoordinate` required the `0x` prefix | `"ar": ["1", "0"]` | fixed, `52ca1e25` |
| 4 | status poll had no per-request bound | a status endpoint that accepts the connection and never responds | fixed, `d9bd0eb2`/`52ca1e25` |
| 5 | frozen `MergeAssembly` buffers reachable from `instructionData` | `assembly.nullifiers[0].fill(0xff)` before `instructionData(proof)` | fixed, `423ddd79` |
| 6 | `bytesField` range-checks where `be` does not | a 32-byte value at or above the BN254 modulus | pinned as a one-way asymmetry, not reachable with input Rust would carry to a proof |
| 7 | the public SPL asset scan is duplicated in the client | none; behavior is identical | recorded, no change |

## Commands

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test -p zolana-client --test ts_prover_oracle          # regenerates and pins both oracles
npm run build && npm run test:unit && npm run test:vectors
npm run typecheck && npm run test:exports && npm run lint:packages
```
