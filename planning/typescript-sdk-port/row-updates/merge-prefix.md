# The merge encrypted-UTXO prefix (I08, I09, I20, I21)

Worker for the one open question the interface stragglers left behind, on branch
`port/merge-prefix` from `515a2fb4`. Scope held: every change is under
`sdk-libs/ts/`. Nothing in `programs/`, `program-libs/`, `prover/`, `xtask/`, or
`docs/spec.md` was touched, and the program's rejection stands unaltered.

**Light Protocol settled it, and it settled both halves the same way: relax
both.** That overrides the previous worker's recommendation, which was to relax
decode and keep encode, per the standing rule that where a row recommends one
thing and Light does another, Light wins and the row changes.

## Contents

- [Step 1: the problem is real](#step-1-the-problem-is-real)
- [Step 2: what Light does](#step-2-what-light-does)
- [Why the encode half falls the same way](#why-the-encode-half-falls-the-same-way)
- [What changed](#what-changed)
- [What pins it](#what-pins-it)
- [What the rows should now say](#what-the-rows-should-now-say)
- [Two things the next worker should know](#two-things-the-next-worker-should-know)

## Step 1: the problem is real

Checked against current source on both sides rather than taken from the row.

`MERGE_ENCRYPTED_UTXO_TYPE_PREFIX` is `2`
(`program-libs/interface/src/instruction/instruction_data/merge_transact.rs:17`)
and it is not part of the serialized layout. `encrypted_utxo` is a
`containers::Vec<u8, FixIntLen<u16>>` (`merge_transact.rs:34-35`), so the length
prefix decides the parse and the first byte selects nothing.

Neither Rust decoder looks at it. `MergeTransactIxDataRef::from_bytes` calls
`validate_shape`, which checks three vector lengths and the blob length and
nothing else (`merge_transact.rs:80-98`); `MergeTransactIxData::deserialize` is a
bare `wincode::deserialize_exact` (`:46-48`). The crate's own round-trip test
builds `encrypted_utxo` as `(0..110).map(|i| i as u8)` (`:159-161`), whose first
byte is `0`, and expects it to parse.

The shielded-pool program is what refuses it, at
`programs/shielded-pool/src/instructions/merge/processor.rs:32-34` and
`merge_zone/processor.rs:39`, with `InvalidMergeOutputScheme`. That is correct
and it stays.

TypeScript refused the same byte at both ends of
`sdk-libs/ts/interface/src/codecs/index.ts`, in `writeMergeData` and
`readMergeData`, which both merge codecs route through.

One correction to the question as posed: `InvalidMergeOutputScheme` is **7020**,
not 7014 (`interface/src/errors.ts:33`, matching `oracle.errors`). The number in
the row text is stale; the pinning test compares against the oracle, so it was
already right.

## Step 2: what Light does

The question generalises to: when a byte is not part of the layout and the
program is what enforces it, does the SDK enforce it too, and does it do so
symmetrically? Light has met this repeatedly and answers **no** to the first,
which makes the second moot.

**Its decoders slice past a program-enforced discriminator without ever
comparing it.** All three system-program decoders take the constant's `.length`
as an offset and discard the bytes:

```240:246:js/stateless.js/src/programs/system/layout.ts
export function decodeInstructionDataInvoke(
    buffer: Buffer,
): InstructionDataInvoke {
    return InstructionDataInvokeLayout.decode(
        buffer.slice(INVOKE_DISCRIMINATOR.length + 4),
    );
}
```

`decodeInstructionDataInvokeCpiWithReadOnly` (`layout.ts:234-238`) and
`decodeInstructionDataInvokeCpi` (`:248-254`) are the same shape, as is
`decodeMintActionInstructionData`
(`js/token-interface/src/instructions/layout/layout-mint-action.ts:355-361`).
Hand any of them a buffer whose discriminator is garbage and it decodes the
payload happily.

**Its indexer decoder validates nothing at all.**
`deserializeAppendNullifyCreateAddressInputsIndexer` (`layout.ts:441-514`) walks
counts and fixed-span layouts for 74 lines and contains no check of any kind,
including of the `is_invoked_by_program` and `bump` meta bytes the program
constrains. This is the decode path an indexer runs, which is the consumer the
decode half of this question is about.

**Dispatch is not validation.** `parseLightTransaction`
(`js/stateless.js/src/test-helpers/test-rpc/get-parsed-events.ts:233-259`)
compares the leading eight bytes to pick a decoder and *skips* an instruction
that matches none. It never throws on an unrecognised one. This distinction
matters for Zolana: dispatching on the SPP instruction tag is right, and it is
not what I08 is about.

**A caller-supplied byte the program enforces is a plain unvalidated field.**
This is the closest analogue to `encryptedUtxo[0]`, because the caller supplies
it rather than the codec:

```30:39:js/compressed-token/src/v3/layout/layout-transfer2.ts
// CompressionMode enum values
export const COMPRESSION_MODE_COMPRESS = 0;
export const COMPRESSION_MODE_DECOMPRESS = 1;
export const COMPRESSION_MODE_COMPRESS_AND_CLOSE = 2;

/**
 * Compression struct for Transfer2 instruction
 */
export interface Compression {
    mode: number;
```

`mode` is `number`, encoded as a bare `u8` (`:292`), and the program certainly
rejects a fourth value. Nothing validates it. Canonical values arrive from
convenience helpers (`createCompressSpl` sets `mode: COMPRESSION_MODE_COMPRESS`,
`:447`), never from a guard. The same holds for the `version` byte on
`MultiInputTokenDataWithContext` (`:69`) and for the 8-byte account
`discriminator` carried inside `CompressedAccountLayout`
(`js/stateless.js/src/programs/system/layout.ts:37`).

**The negative is clean.** `js/stateless.js/src/programs/system/layout.ts` and
`program.ts` contain zero `throw`s between them, as does the whole of
`js/token-interface/src/instructions/layout/`. Every throw in
`programs/system/` is in `pack.ts` or `select-compressed-accounts.ts` and is
about composition rather than wire bytes: insufficient balance, an unsupported
tree type, two contradictory arguments. Searching all of `js/` for an "invalid
discriminator", "invalid tag", "invalid mode", or "invalid version" rejection
returns nothing.

Two candidates that look like counter-examples and are not, checked because the
brief asked for library-imposed checks to be told apart from deliberate ones:

- `rustEnum` (`layout-mint-action.ts:71`, `:118`) will throw on an unknown
  variant index, but that is `@coral-xyz/borsh` behaviour, and it applies to a
  genuine layout discriminant, where the variant selects which fields follow.
  Zolana's merge prefix selects nothing.
- `toMintInstructionDataWithMetadata`
  (`js/compressed-token/src/v3/layout/layout-mint.ts:754-764`) throws, but on a
  missing extension, which is a shape precondition, not a canonical byte.

Also worth recording, since it is the exact shape of the question: Light's
decoders are tolerant of payloads its own builders would never produce. The
builders prepend the discriminator themselves
(`encodeInstructionDataInvoke`, `layout.ts:96-109`), so a non-canonical one
cannot come from Light, and the decoders read it anyway.

## Why the encode half falls the same way

Light's builders emit the canonical byte because they *write* it, not because
they check a caller's. Where the byte is the caller's, as `mode` is, Light
neither writes nor checks it. `encryptedUtxo[0]` is in the second category:
`writeMergeData` receives the whole 110-byte blob from the caller. So Light's
answer for this shape is no encode guard, and the previous worker's asymmetry
does not survive contact with it.

The argument for keeping the encode guard was real and is worth naming rather
than dismissing: it converts a transaction the program will reject into a local
error. Three things weigh against it, beyond Light.

The guard is not the only thing between a caller and that mistake, and it is the
weakest. The blob is assembled by `merge_encrypted_utxo`
(`sdk-libs/client/src/prover/merge.rs:348-354`), which pushes the scheme byte
itself. A caller reaching `writeMergeData` with a wrong prefix has hand-built a
110-byte payload, and that caller is a tool, not an application.

It also blocked a legitimate operation with no substitute: taking a failed
merge instruction off-chain, decoding it, and re-encoding it byte for byte.
Keeping encode meant TypeScript could read the payload and not write it back,
which is a worse position than either symmetric one.

And the codec is one function pair shared by both merge instructions, so an
asymmetry there is a permanent claim to maintain in prose. It would have needed
the row text to say plainly that the languages do not agree, which is a cost the
symmetric answer does not carry.

## What changed

Two guards deleted from `sdk-libs/ts/interface/src/codecs/index.ts`, in
`writeMergeData` and `readMergeData`. Both merge codecs share that pair, so this
covers `mergeTransactInstructionDataCodec` and
`mergeZoneInstructionDataCodec` at once. A four-line comment above
`writeMergeData` records that the absence is deliberate and who owns the check,
because a missing guard is invisible to the next reader.

Everything else in those functions stays. The vector-length and blob-length
checks mirror Rust's `validate_shape` exactly and are parity, not strictness.

Nothing else in the ten packages held a copy: a search of `sdk-libs/ts` for
`typePrefix`, `encryptedUtxo[0]`, and `INTERFACE_CODEC` around the merge path
found the guard only in those two places.

Commit `78039fe9`.

## What pins it

In `interface/test/vectors/rust-oracle.test.ts`, replacing the old
`pins the merge encrypted-UTXO prefix asymmetry against Rust`, which asserted
the behaviour that is now gone:

`reads and rebuilds the non-canonical merge prefix Rust reads`. It uses the
oracle's `mergeNonCanonicalPrefixBytes` and `mergeZoneNonCanonicalPrefixBytes`,
which the generator produces by serializing the canonical merge payload in Rust
and setting the prefix to `0` (`xtask/src/bin/ts-interface-oracle.rs:1101-1120`),
and asserts four things:

- Rust accepts them, from the oracle's own recorded verdict.
- They differ from `oracle.instructionData.mergeTransact` at exactly one offset,
  and that offset holds `MERGE_ENCRYPTED_UTXO_TYPE_PREFIX` in the canonical
  bytes. This is what makes the prefix, rather than some other field, the reason
  the payload is non-canonical.
- TypeScript decodes them, and the decoded `encryptedUtxo[0]` is not the
  canonical prefix.
- TypeScript re-encodes the decoded value back to the same bytes, for both the
  merge and the merge-zone codec.

The last two are the evidence the brief asked for, one per side. Checked red
before green: reinstating the encode guard fails at the re-encode assertion,
reinstating the decode guard fails at the decode. Both were run.

The test keeps its assertion that `ShieldedPoolError.InvalidMergeOutputScheme`
matches the oracle, so the record of who does reject the payload survives the
change.

One test elsewhere had to lose three cases.
`interface/test/interface.test.ts`, in `rejects merge-shape mutations`, asserted
the encode guard and both decode guards by flipping byte 557 and byte 589, the
prefix offsets. Those are deleted. Its shape coverage is untouched, and the
decode-side shape rejection it also carried lives on at
`interface.test.ts:605-608`, which corrupts the nullifier count instead.

## What the rows should now say

I08, I09, I20, and I21 are **parity**, not `pinned_divergence`. There is no
remaining asymmetry to describe: TypeScript now accepts on decode and emits on
encode exactly what Rust accepts and emits, and the program rejects the payload
in both languages' path. The row text should stop describing a guard that no
longer exists, and the checklist's I08 and I09 entries currently cite
`codecs/index.ts:454` and `:525` for it.

I have not edited `review-checklist.md`; the reconciler owns it.

## Two things the next worker should know

**This collides with `port/interface-b`.** That branch's commit `ee6aa10b`
refactors the same two guards into a shared `checkMergeOutputScheme` in a new
`interface/src/constants.ts`, described in
[`interface-keypair-stragglers.md`](interface-keypair-stragglers.md). It is
behaviour-neutral and was written to make the ruling a one-line edit. The ruling
deletes the function it created, so whoever merges the two should take this
branch's deletion and drop `checkMergeOutputScheme`. Whether `constants.ts`
survives is independent of this row: it also de-duplicates the `8` and `110`
literals, which are parity checks that stay.

**The rule this establishes is narrower than "SDK codecs never validate."** It
is that a codec follows the language it ports. Where Rust validates, TypeScript
should too, and does: `sdk-libs/transaction/src/serialization/` checks
`type_prefix` on deserialize and raises `BadDiscriminator`
(`split.rs:91-97`, `plaintext.rs:129-135`), and its TypeScript twin raises
`TRANSACTION_BAD_DISCRIMINATOR` on both sides
(`transaction/src/serialization/codecs.ts:547-549`, `:608-614`, `:631-633`).
That is parity and it should not be relaxed on the strength of this row.
