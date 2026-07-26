# The zone read path, the C04 amendment, and the size constant

Worker on `port/zone-read` from `ts-sdk-port`. Touches
`sdk-libs/transaction`, `sdk-libs/ts/{transaction,client,smart-account-client}`,
`docs/spec.md` for the C04 amendment only, and this directory.

Rows: T04, T07 and T15 for the read path; C04 for the specification; C22 for the
ledger line and the duplicated constant.

## The read path: real, and the opposite way round

The finding in [transaction-surface.md](./transaction-surface.md) is right that
the two implementations disagree and wrong about which one is permissive. The
consequence it names, a crafted plaintext-transfer payload landing a
spendable-looking note in a TypeScript wallet, does not happen at
`ts-sdk-port` and did not happen before it.

`Utxo`'s constructor carried the rule. It refused any construction whose `Data`
held a zone data record without a zone program id (`utxo.ts:146-148` before this
branch), and every read path builds its UTXOs through that constructor, so the
plaintext-transfer and proofless slots the finding names were refused too. Wallet
sync catches the throw and counts the slot undecryptable, which is exactly what
Rust does with `MissingZoneProgramId`. Four of the six read paths therefore
agreed already, by a mechanism Rust does not have rather than by the one it does.

Two disagreed, and both are the constructor being stricter than Rust rather than
laxer:

- **A supplied id with no zone data.** `resolve_zone_program_id` returns `None`
  when `Data::zone_data()` is empty, discarding an id the caller passed
  (`sdk-libs/transaction/src/utxo.rs:49-60`). TypeScript kept it, so a
  `Split` or `AnonymousRecipient` rebuild under a zone-configured reader produced
  a UTXO bound to a zone its plaintext never mentioned. `Utxo::hash` folds
  `zone_program_id` into the commitment, so the two languages computed different
  commitments for the same plaintext. Nothing in the suite compared them.
- **The proofless rail.** `Proofless::into_utxos` performs no resolution at all
  (`serialization/proofless.rs`); the binding rides in the payload as its own
  `zone_program_id` field, and zone data with no id is a shape Rust accepts.
  TypeScript's constructor refused it, so a payload Rust reads as a UTXO was
  counted undecryptable.

So the audit found a real divergence while mischaracterising it, which is the
useful outcome: the mechanism it pointed at was not where the rule lived, and
looking for the rule is what turned up the two cases that do differ.

### What changed

`resolveZoneProgramId(zoneProgramId, data)` in `utxo.ts` is Rust's function, and
the constructor invariant is gone. Each read path calls it where Rust calls it:
`plaintextTransferUtxos`, `splitBundleUtxos`, `anonymousRecipientUtxo` and
`anonymousSenderUtxos`. `confidentialUtxo` gets the inline check Rust's
`ConfidentialOutputPlaintext::into_utxo` has rather than the shared helper,
because that rail reads the id from its own plaintext. `prooflessUtxo` resolves
nothing.

Removing the constructor invariant moves one assertion. A `Utxo` may now hold a
`zoneDataHash` with no `zoneProgramId`, and `hash()` refuses it, which is where
Rust refuses it too; `transaction-vectors.test.ts` was repointed accordingly.

The two capability cells are cleared rather than deleted: `plaintextTransferUtxos`
and `prooflessUtxo` are lifted out of `wallet/sync.ts` into
`serialization/codecs.ts` and exported, so wallet sync and an external caller now
run the same function.

### The test that would have caught it

`ts/transaction/test/zone-resolution.test.ts` and
`sdk-libs/transaction/tests/zone_resolution.rs` are the same three cases in both
languages.

The crafted-payload case is the one that matters. It publishes a
plaintext-transfer slot whose data record carries zone data, against the leaf
hash an honest payload for the same UTXO would have produced, and asserts the
wallet receives nothing and counts one undecryptable slot. The hashes match
because neither the data records nor the zone id reach the commitment on that
rail, which is what makes the payload craftable in the first place; a test that
let the commitment diverge would pass for the wrong reason. Deleting the refusal
makes the case fail with the note stored, so it detects the divergence rather
than merely describing it.

The other two pin the cases that were wrong: a supplied id dropped when the
plaintext carries no zone data, and the proofless rail keeping a payload's own
binding without resolving it.

## C04 can close

The last item in [c04-integer-domain.md](./c04-integer-domain.md) is done. The
`Integer encoding` paragraph in the RPC section of `docs/spec.md` stated option
I3, capping every RPC integer at the safe-integer range while citing the decoder
line that had become the string grammar. Under the owner's `amend_both`, it now
describes the decoder:

- A JSON number outside `-(2^53 - 1)` through `2^53 - 1` has already lost
  precision before a decoder sees it, so it is refused. That half of the old
  paragraph survives, with the reason stated rather than the range.
- A field whose domain nothing in the protocol bounds below `2^53` also accepts a
  decimal string: `block_time`, both `slot` fields, both `root_seq` fields. The
  table names each with why it is unbounded.
- Every other integer is a number only, with the caps that make it so: the tree
  height for a leaf index and for the non-inclusion element indices, the width
  for `tree_type` and `root_index`, the schema for `limit`. The paragraph states
  the test that decides a field it does not name, so a field added later has an
  answer.
- A value the encoder cannot write as a safe number is reported rather than
  emitted, so no payload carries a truncated integer, and the asymmetry is
  Photon's own.

No other paragraph of `docs/spec.md` was touched. C04 is reportable as closed on
both halves; the row is the reconciler's to move.

## C22: the ledger line and the third copy of 1232

Both halves of the `MERGE_INPUTS` entry are fixed in `public-exports.md`. The
`@zolana/interface` section records `MERGE_INPUT_COUNT`, which is what that
package exports, and the `@zolana/transaction` section gains `MERGE_INPUTS`
beside the merge builders that use it.

The duplicated size rule and the dead client export are one problem. `@zolana/client`
exported `MAX_TRANSACTION_SIZE` and `transactionSize` from `wire.ts`; nothing
inside the package imported either, because `client.ts` calls
`checkedTransactionSize` from `@zolana/interface`, which owns the same rule as
`TRANSACTION_SIZE_LIMIT`, `transactionSize` and `checkedTransactionSize`. Two
packages exporting the same measurement under two names is a question a caller
should not have to answer, and the client's pair answered it worse: it measured
without offering the refusal the client itself relies on.

Withdrawn. `wire.ts` keeps `compactU16`, which three modules do use, and the two
`crate-root-exports.test.ts` dispositions for the withdrawn names are removed
with them. `client/test/transaction-size.test.ts` stays and now measures
`@zolana/interface`'s function against the bytes `SolanaRpc` submits, which is
the cross-check that was worth having and is now pointed at the surviving
implementation.

The remaining literals read from the constant: `solana-rpc.ts`'s base58
length search, where the packet limit bounds instruction data because the data
rides inside a transaction, and `smart-account-client`'s
`MAX_INSTRUCTION_DATA_SIZE`, for the same reason one level in. That package's
import of `@zolana/interface` becomes a value import, which its declared
dependency and `sideEffects: false` make safe.

## Gates

`npm run build` before every run. `@zolana/transaction` unit (475) and vectors
(436), `@zolana/client` unit (459) and vectors (323), `@zolana/interface` unit
(133), `@zolana/smart-account-client` unit (41), workspace `typecheck`, `eslint`
over the touched sources, and `cargo test -p zolana-transaction --test
zone_resolution`. All green.
