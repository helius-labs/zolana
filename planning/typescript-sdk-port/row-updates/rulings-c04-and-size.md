# Two owner rulings: the u64 integer domain (C04) and the size check

Worker on branch `port/rulings` from `a212c852`. Both rulings were decided before
this branch existed; nothing here re-opens either. Scope held: every change is
under `sdk-libs/ts/`. Nothing in `programs/`, `program-libs/`, `prover/`,
`xtask/`, or `docs/spec.md` was touched, and
`planning/typescript-sdk-port/review-checklist.md` was left to its reconciler.

## Contents

- [Ruling 1: the string-or-number union](#ruling-1-the-string-or-number-union)
  - [How the fields were divided](#how-the-fields-were-divided)
  - [Why the physical-reachability test was rejected](#why-the-physical-reachability-test-was-rejected)
  - [What changed, and what did not](#what-changed-and-what-did-not)
  - [The asymmetry this creates with Rust](#the-asymmetry-this-creates-with-rust)
- [Ruling 2: refuse an unsendable transaction](#ruling-2-refuse-an-unsendable-transaction)
  - [One place, not three](#one-place-not-three)
  - [What a caller sees now](#what-a-caller-sees-now)
  - [Rust has the same hole, and the fix is blocked](#rust-has-the-same-hole-and-the-fix-is-blocked)
  - [`resolveShape` should keep offering all ten shapes](#resolveshape-should-keep-offering-all-ten-shapes)
- [What pins each behaviour](#what-pins-each-behaviour)
- [Housekeeping: a commit this worker did not write](#housekeeping-a-commit-this-worker-did-not-write)

## Ruling 1: the string-or-number union

`sdk-libs/ts/indexer-api/src/codec.ts` now accepts a decimal string alongside a
JSON number on the fields whose value can exceed `2^53`, keeps refusing a number
that has already lost precision, and leaves every other field on the
number-only path. This is Light's `BNFromStringOrNumber`
(`js/stateless.js/src/rpc-interface.ts:316-328`) applied per field, as the
ruling directs.

### How the fields were divided

The ruling says to work the division out from Zolana's own domains rather than
copy Light's field list. The test used: **is there an invariant in the Zolana
protocol or in its data structures that caps this value below `2^53`?** If yes,
the field cannot overflow and does not acquire a parse path. If no, it takes the
union.

Capped, so number-only:

| Field | What caps it |
| --- | --- |
| `MerkleProof.leaf_index`, `RingsOutputContext.leaf_index` | State tree height 32, so under `2^32` leaves (`sdk-libs/client/src/rpc.rs:27`) |
| `NonInclusionProof.low_element_index`, `high_element_index` | Nullifier tree height 40, so under `2^40` (`rpc.rs:28`) |
| `root_index`, `merkle_context.tree_type` | Declared `u16` (`sdk-libs/indexer-api/src/lib.rs:617`, `:631`) |
| `limit` | 1 through 1000 (`codec.ts:97-116`) |

Uncapped, so number or decimal string:

| Field | Why nothing caps it |
| --- | --- |
| `EncryptedUtxoMatch.slot`, `IndexedShieldedTransaction.slot` | A Solana slot. Zolana echoes the chain's own `u64` counter and bounds nothing |
| `Context.block_time` | A validator-chosen Unix time, `i64` (`sdk-libs/indexer-api/src/lib.rs:474-479`) |
| `MerkleProof.root_seq`, `NonInclusionProof.root_seq` | A root sequence advanced per tree update, with no ceiling in the account |
| `NullifierQueueElement.seq`, `GetNullifierQueueElementsRequest.start_seq` | The input-queue sequence, the same free-running counter, read from and written to the same domain |

`start_seq` is a request field rather than a response field, and the SDK's own
encoder never emits a string for it. It takes the union anyway, because the
division is a property of the field's domain and not of the direction it
travels; a decoder that accepted `seq` as a string but refused `start_seq`
would be inconsistent for no reason a caller could predict.

### Why the physical-reachability test was rejected

The obvious reading of "can genuinely exceed `2^53`" is physical: can a real
deployment produce such a value? Applied to this schema it yields the empty set.
Light's clearest case is `lamports`, an amount that spans the full `u64` range
by construction, and the Zolana indexer schema has no amount field at all. Its
widest values are a slot and two counters, and `2^53` slots at 400ms is about
114 million years. Under that test no field takes the coercion and the ruling
changes nothing, which cannot be what was ruled.

The invariant test is the one that both produces a non-empty answer and draws a
line a reader can check: the tree indices are capped by a height the protocol
fixes, and the slots and sequences are not capped by anything Zolana owns. It
also happens to reproduce Light's own `leafIndex`-is-plain-`number` choice from
first principles rather than by imitation.

Where it departs from Light is `slot`, which Light declares as plain `number()`
(`rpc-interface.ts:429`) while also coercing `slotCreated`. Light is not
self-consistent there, so it gives no signal to copy; the invariant test puts
both on the union side.

### What changed, and what did not

`wireInteger` keeps the exact refusal it had. The range check moved into a
shared `inRange` so both entry points report the same message, and
`unboundedWireInteger` adds only the string arm. A string must be a canonical
decimal integer: no leading zero, no `+`, no `-0`, no exponent, no hex, no
surrounding space. A naive `BigInt(value)` would accept `""` as `0`, `" 1"` as
`1`, `"01"` as `1`, `"0x10"` as `16`, and `"-0"` as `0`, which is five spellings
of a value the wire should carry one way; the regexp is what refuses them, and
the control edit below confirms it.

The encoders were deliberately left alone. `toWireInteger` still emits a JSON
number and still refuses a `bigint` it cannot represent as one
(`INDEXER_SCHEMA_UNSAFE_INTEGER`). Photon deserializes these fields with plain
`serde`, which does not accept a JSON string for a `u64`, so an SDK that started
emitting strings would break the request path. The union is an acceptance
widening, in the decode direction only.

`i64` is gone: `block_time` was its only caller and it now takes
`unboundedI64`. The signed path needed no special case, because a string parses
to a `bigint` and the existing `I64_MIN`/`I64_MAX` range check rejects a sign
the field cannot hold.

A number payload decodes exactly as before. This is pinned by a control test
that decodes `block_time: 1700000000` and `slot: 42` through
`getEncryptedUtxosByTagsMethod` and by the 34 pre-existing `indexer-api` tests,
all of which feed numbers and all of which still pass unchanged.

### The asymmetry this creates with Rust

C04 recorded the TypeScript refusal as the SDK being stricter than Rust. After
this change the direction reverses for the four uncapped groups: TypeScript
accepts `number | string` where `zolana-indexer-api` accepts only `number`. That
is the same asymmetry Light carries against its own Rust, and it is safe in the
sense that Photon never emits a string, so no live payload exercises the
difference. Making Rust symmetric means `serde(with = ...)` on those fields plus
a matching OpenAPI change and an update to the round-trip assertions in
`services/photon/src/api/method/rings.rs:85-211`. The ruling scoped itself to
the TypeScript decoder, so that was not done here. It is the natural follow-up.

## Ruling 2: refuse an unsendable transaction

### One place, not three

The study asks the question first: three hand-written compilers and five copies
of `compactU16`, so is the check one edit or three? It is one.

All three compilers already depend on `@zolana/interface`, which owns the
`Transaction` boundary type (`sdk-libs/ts/interface/src/index.ts:76-79`). The
new `sdk-libs/ts/interface/src/transaction-size.ts` holds the whole rule: the
limit, the serialized-length arithmetic, and the refusal. Each compiler ends
with one call:

- `sdk-libs/ts/client/src/client.ts:700`, the transact, merge, and merge-zone path.
- `sdk-libs/ts/wallet/src/internal.ts:206`, deposit, user registry, ATA creation.
- `sdk-libs/ts/test-kit/src/user-registry.ts:383`, the harness registry setup.

Three call sites, one rule. The thing that could drift if it were copied, the
arithmetic, is not copied. Consolidating the compilers themselves is still worth
doing and is still a separate job; this change does not depend on it and does
not make it harder.

The error is `InterfaceError`, thrown from the interface package, rather than a
new `ClientError`, `WalletError`, and `TestKitError` triple. That is not a
shortcut: `buildUnsignedTransaction` already lets an `InterfaceError` from
`transactInstruction` escape uncaught, so the client's error surface already
includes this class, and a per-package code would have needed the same message
written three times with three registries to keep in step.

`checkedTransactionSize` returns the transaction it was given, so a compiler
wraps its result rather than growing a branch.

### What a caller sees now

Before, a one-input transfer to six recipients compiled to a transaction past
the limit, went to the RPC, was dropped at ingestion, and came back as
`CLIENT_CONFIRMATION_TIMEOUT` after the full confirmation poll. The caller could
not tell an unsendable shape from a slow network.

Now `buildUnsignedTransaction` throws before returning:

```
InterfaceError: INTERFACE_TRANSACTION_TOO_LARGE
  details: { size: 1793, limit: 1232, inputs: 1, outputs: 8 }
```

The shape is present on the transact path because that is where the caller has a
lever: `data.inputs.length` and `data.outputs.length` are the counts
`resolveShape` picked, and sending to fewer recipients is the fix. The wallet
and test-kit compilers pass no shape, because a deposit or a registry write has
no proof shape to change; their failure would come from an oversized `utxo_data`
or `memo`, and `size` against `limit` is the whole story there.

Measured through the real builder rather than modelled: a single 1,000,000
lamport SOL note spent to one recipient compiles to 1051 bytes and passes; to
three or six recipients it resolves to 1 in 8 out and compiles to 1793 bytes and
fails. Three recipients is enough, because two sender slots plus three
recipients is five outputs and the first shape holding five is 1 in 8 out, which
then pads to eight. So the reachable boundary is narrower than the study's
six-recipient example: **a one-input transfer to three recipients is already
unsendable.**

These numbers sit below the study's 2108 for the same shape because the study
measures the bare `transact` instruction against three accounts, while the SDK
also emits a compute-budget instruction and pads the empty output slots with
length-matched random ciphertexts rather than full recipient bundles. The
conclusion is identical either way and both are far past 1232.

### Rust has the same hole, and the fix is blocked

Rust has it, confirmed against source rather than taken from the study.
`build_unsigned_solana_transaction` calls `Message::new` and
`SolanaTransaction::new_unsigned` with no length comparison
(`sdk-libs/client/src/client.rs:774-776`); so do
`sdk-libs/wallet/src/actions/deposit.rs:195-197`,
`sdk-libs/wallet/src/user_registry.rs:219-221`, and the
`create_and_send_transaction` default (`sdk-libs/client/src/rpc.rs:230-232`).
Searching the Rust workspace for `1232` or `PACKET_DATA_SIZE` returns only
comments in `sdk-tests`, none of which guards a compile. The submission surface
taking `VersionedTransaction` does not help: nothing between compiling and
sending measures.

The fix was not written, and the reason is a scope collision rather than a
judgement.

A meaningful refusal needs a named variant, `ClientError::TransactionTooLarge`,
because the repo forbids reusing an unrelated variant as a catch-all and no
existing variant fits. `ClientError` is not `#[non_exhaustive]`, and
`xtask/src/ts_fixtures_client.rs:202-402` matches it exhaustively with no
wildcard arm to generate the cross-language error fixture. Adding the variant
therefore fails `cargo check --workspace` until `xtask` gains one arm, and this
task forbids touching `xtask`. Routing the failure through
`zolana_transaction::TransactionError` instead would compile, since `xtask` only
formats that enum with `Debug`, but it would file a Solana packet-format failure
under the shielded-transaction builder crate, which is the wrong home chosen for
a codegen reason.

What the follow-up needs, in one commit:

1. `ClientError::TransactionTooLarge { size: usize, limit: usize, inputs: usize, outputs: usize }` in `sdk-libs/client/src/error.rs`.
2. One arm in `xtask/src/ts_fixtures_client.rs` mapping it to `CLIENT_TRANSACTION_TOO_LARGE`, plus the variant in the sample list at `:88-120` so the fixture covers it.
3. The matching code in `sdk-libs/ts/client/src/error.ts`, and a regenerated `sdk-libs/ts/fixtures/client/errors-v1.json`.
4. The check itself at the four compile sites, measuring `compact_u16_len(signatures) + 64 * signatures + message.serialize().len()` exactly as the TypeScript side does.

Steps 2 and 3 are the reason it is a follow-up rather than part of this branch.

### `resolveShape` should keep offering all ten shapes

It should not narrow, for three reasons, in order of weight.

**The list is not the TypeScript SDK's to narrow.** `SPP_SUPPORTED_SHAPES`
(`sdk-libs/ts/interface/src/shape.ts:12-23`) is a port of
`SPP_SUPPORTED_SHAPES` in `program-libs/interface/src/shape.rs:68`, the same
constant the proving keys, the
Go prover, and the on-chain verifier are generated against, and this task
forbids editing that crate. Narrowing only the TypeScript copy would put it out
of step with the protocol definition, and `rust-oracle.test.ts:299-308` pins the
two against each other from a Rust-generated oracle, so the divergence would
show up as a parity failure rather than as a feature.

**Sendability is not a property of the shape.** The study's own table has 5 in 3
out sendable as a transfer at 1100 bytes and unsendable as a withdrawal at 1240,
and has 4 in 3 out sendable while 4 in 4 out is not. The predicate depends on
the withdrawal leg, the ciphertext sizes, and the compute-budget instructions,
none of which `resolveShape(inputs, outputs)` can see. A shape list cannot
encode an answer that a shape does not determine.

**The size check already answers it, with more information.** A narrowed list
would report `TRANSACTION_UNSUPPORTED_SHAPE` for a request that is arithmetically
fine at the coming ciphertext format; the size check reports 1793 against 1232
for the transaction actually built. And when the ciphertext format lands, nine of
the ten shapes come back under the limit and a narrowed list would have to be
widened again, whereas the measurement simply stops firing.

So: leave `resolveShape` alone. It answers "which proving system covers these
counts", the size check answers "will this transaction reach the network", and
they should stay separate questions.

## What pins each behaviour

Every test below was watched failing before the change it pins.

| Behaviour | Test | Control that proved it has teeth |
| --- | --- | --- |
| A decimal string decodes on the uncapped fields | `indexer-api/test/integer-domain.test.ts`, first two cases | Failed on `$.context.block_time` before the change; 5 of the 7 cases already passed, which is the backward-compatibility claim showing up as a pre-existing pass |
| Only a canonical decimal string is accepted | same file, "refuses a string that is not a canonical decimal integer" | Loosening the regexp to `/^-?[0-9]+$/` made it fail |
| The capped fields keep the number-only path | same file, "keeps the string form off fields a tree height or a width already caps" | Pointing `u64` at `unboundedWireInteger` made it fail |
| A number payload is unchanged | same file, "leaves a JSON number payload decoding exactly as before", plus the 34 existing `indexer-api` tests | Every existing test feeds numbers and none was edited |
| The size arithmetic and the refusal boundary | `interface/test/transaction-size.test.ts` | Four cases, all failing before the module existed; the limit case passes at exactly 1232 and fails at 1233 |
| A six-recipient transfer is refused with the numbers and the shape | `client/test/vectors/oversized-transaction.test.ts` | Failed with `thrown === undefined` before the change |
| A shape that fits still compiles | same file, second case | Passed before and after, which is the point |

Gates run on the final tree, each after a rebuild and with `node_modules/.vite`
removed: `npm run build`, `npm run test:unit` (1821 passed, 1 skipped),
`npm run check:static`, `npm run lint:packages`, `cargo check --workspace`,
`cargo test -p zolana-indexer-api -p zolana-transaction`. Also
`npm run test:inventory`, `test:exports`, and `api:check`, because the branch
adds a source file and two public exports.

One existing test needed editing and it was widened rather than weakened:
`interface/test/exports.test.ts` pins the interface package's runtime exports by
name, so `TRANSACTION_SIZE_LIMIT`, `checkedTransactionSize`, and
`transactionSize` were added to the list. No assertion was relaxed.

## Housekeeping: a commit this worker did not write

`0f4a4ca4`, "wip(indexer-api): per-field integer domain, salvaged mid-flight",
landed on `port/rulings` at 02:19:19 while this worker was running the unit
suite. It was not written here. Its content was checked line by line against
`a212c852` and is entirely this worker's own in-progress edits to
`codec.ts` and `integer-domain.test.ts`, so nothing foreign entered the branch
and the work was continued on top of it. `git worktree list` shows
`port/rulings` checked out only at `/Users/tilohelius/Workspace/zolana-ts-rulings`.
Recorded because the branch-name guard passes for it and the history guard does
not, which is exactly the case the guard exists to surface.
