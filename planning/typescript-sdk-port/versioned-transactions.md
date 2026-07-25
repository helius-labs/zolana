# Versioned transactions and address lookup tables

**The account limit is nowhere near being reached. The transaction size limit is
exceeded today. A Zolana shielded transfer names three accounts at any supported
proof shape, against a runtime ceiling of 128 account locks, so the account
arithmetic has roughly forty times the headroom it needs. What fails is the
1232-byte size cap: at the current ciphertext format, three of the ten
supported shapes compile to transactions that cannot be sent, and the widest of
them reaches 2108 bytes. Versioned transactions do not fix that. A lookup table
costs a shielded transfer 5 bytes and saves an SPL withdrawal 57, because a
transfer has exactly one address a table is allowed to compress. The change that
recovers the headroom is the already-specified ciphertext format, which brings
nine of the ten shapes under the limit. Recommendation: do not schedule v0 for
the size problem, add a size check to the compiler now, and revisit v0 when a
second pool tree ships or a wallet integration demands it.**

Written 2026-07-26 on branch `port/versioned-tx`, merged to the `ts-sdk-port`
integration tip (`03584e8e`). The size figures are reproduced from the `tx-size`
xtask command shown below, not estimated. This study answers the
lookup-table paragraph of finding F1 in
[`light-protocol-comparison.md`](light-protocol-comparison.md) and corrects three
of its claims.

## Goal

Decide whether the TypeScript SDK needs `VersionedTransaction` support and
address lookup tables, and if so, what should trigger the work. The question is
explicitly outside the parity scope, so the deliverable is a decision record
rather than a change.

## The situation before

### Where the legacy decision is embedded

The TypeScript SDK depends on no Solana library. It compiles wire-format
messages by hand, and it does so in three places rather than one:

| Function | File | Callers |
| --- | --- | --- |
| `compileLegacyTransaction` | `sdk-libs/ts/client/src/client.ts:620` | transact, withdraw, merge (`:575`, `:587`, `:608`) |
| `compileTransaction` | `sdk-libs/ts/wallet/src/internal.ts:120` | deposit, user registry, ATA creation |
| `compileTransaction` | `sdk-libs/ts/test-kit/src/user-registry.ts:300` | test harness registry setup |

Each writes the legacy layout directly: a three-byte header of
`(requiredSignatures, readonlySigners, readonlyUnsigned)`, a compact-u16 account
count, the account addresses inline at 32 bytes each, the blockhash, then the
instructions (`client.ts:676-698`, `internal.ts:183-204`). The legacy decision is
not a configuration value anywhere. It is the absence of a version byte in those
two byte-assembly blocks, so switching versions means editing the assembly code,
not flipping a flag.

Both production copies sort accounts to match `solana_message::Message::new`,
which compiles through `CompiledKeys` and hands each privilege class back in
ascending address order with the fee payer lifted to the front
(`client.ts:655-666`). The two copies have drifted slightly: the wallet copy
breaks address ties on insertion order (`internal.ts:172`) where the client copy
returns zero (`client.ts:710`). The tie is unreachable with distinct addresses,
so this is latent rather than a live bug.

The guard in both compilers counts accounts and stops at 256
(`client.ts:667`, `internal.ts:174`). No code path compares the compiled message
length against 1232. Searching the SDK source for that constant returns an
instruction-data cap in `smart-account-client/src/instructions.ts:31` and the
loop bound of a base58 length search in `solana-rpc.ts:609`, neither of which
guards a compiled transaction.

The read path is already versioned-aware. `messageAccountKeys` resolves account
indexes against the static message keys followed by `meta.loadedAddresses`,
writable before readonly (`sdk-libs/ts/client/src/solana-rpc.ts:554`, `:572-577`),
which is the resolution order a v0 message requires. So the SDK can already read
back a transaction it cannot yet build.

### The account count stays far below the cap, and does not grow with shape

A shielded transfer names three accounts: the payer, the tree, and the
shielded-pool program itself, which is present so the `emit_event` self-invocation
can load it (`program-libs/interface/src/instruction/builders/transact.rs:57-80`).
Counting the other instruction shapes from the same builders:

| Instruction | Accounts |
| --- | --- |
| `transact`, shielded transfer | 3 |
| `merge_transact` | 4 |
| `deposit`, SOL | 5 |
| `transact`, SOL withdrawal | 6 |
| `deposit`, SPL | 7 |
| `transact`, SPL withdrawal | 8 |
| `zone_transact`, SPL withdrawal | 9 |

Adding the compute-budget program puts the ceiling at ten. The runtime caps a
transaction at 128 account locks (`MAX_TX_ACCOUNT_LOCKS`), and the hand-written
compilers refuse above 256. Roughly forty times the headroom at the widest
account layout the program has, and none of it is consumed by widening the proof
shape.

That last clause is the structural reason Zolana does not have Light Protocol's
problem, and it is worth stating precisely because it is the load-bearing claim
of this study. Light's compressed transaction names a state tree and a queue per
input account, so its account list scales with input count. Zolana's `transact`
takes exactly one `tree` account whatever the shape:
`TransactAccounts::validate_and_parse` reads a payer and a single tree, then
hands the iterator to settlement parsing
(`programs/shielded-pool/src/instructions/transact/account.rs:24-27`). The
nullifier tree lives inside that same account rather than beside it. Going from
one input to five adds 38 bytes of instruction data and zero accounts, because
`InputUtxo` carries a `tree_index: u8`
(`program-libs/interface/src/instruction/instruction_data/transact.rs:86`) rather
than an account reference.

So the premise in the question, that Zolana's shielded transfers have the same
shape as the Light transactions that forced v0, does not hold. The shapes differ
in the specific respect that matters.

### The size limit is exceeded today

Signed transaction size in bytes, measured at the current ciphertext format
(AES-GCM, recipient and sender public keys repeated inside each ciphertext,
192-byte proof). Bold marks a shape past the 1232-byte limit. A transfer needs at
least one recipient and recipients start at output slot 2, so shapes below three
outputs have no transfer column.

| Shape | ix data | Transfer | Transfer, ALT | Withdraw | Withdraw, ALT |
| --- | --- | --- | --- | --- | --- |
| 1 in 1 out | 476 | | | 821 | 764 |
| 1 in 2 out | 511 | | | 856 | 799 |
| 2 in 2 out | 549 | | | 894 | 837 |
| 2 in 3 out | 781 | 986 | 991 | 1126 | 1069 |
| 3 in 3 out | 819 | 1024 | 1029 | 1164 | 1107 |
| 4 in 3 out | 857 | 1062 | 1067 | 1202 | 1145 |
| 4 in 4 out | 1089 | **1294** | **1299** | **1434** | **1377** |
| 5 in 3 out | 895 | 1100 | 1105 | **1240** | 1183 |
| 5 in 4 out | 1127 | **1332** | **1337** | **1472** | **1415** |
| 1 in 8 out | 1903 | **2108** | **2113** | **2248** | **2191** |

Reproduce with:

```bash
cargo run -p xtask -- tx-size 1:1 1:2 2:2 2:3 3:3 4:3 4:4 5:3 5:4 1:8
```

The tool builds real `TransactIxData`, compiles it into both a legacy and a v0
message through `solana_message`, and reports the bincode length of the signed
transaction (`xtask/src/main.rs:326-660`). It is measurement rather than
modelling: `legacy_tx_len` and `v0_tx_len` call the same `Message::new` and
`v0::Message::try_compile` the runtime uses (`:491-501`).

Marginal costs follow from the differences and agree with the codecs. One more
input costs 38 bytes, matching `InputUtxo` at 32 + 2 + 2 + 1 + 1
(`transact.rs:78-87`). One more recipient costs 232 bytes at the current
ciphertext format.

Three of the ten shapes cannot be sent as transfers today, and a fourth
withdrawal shape joins them. This is current behaviour, not a projection. The
1 in 8 out row is reachable from the public API without doing anything unusual:
`TransferBuilder.withShape` resolves
`resolveShape(inputs, SENDER_SLOT_COUNT + recipients.length)`
(`sdk-libs/ts/transaction/src/instructions/transact.ts:561-564`) with
`SENDER_SLOT_COUNT = 2` (`:57`), and `selectSppShape` picks the first shape in
`SPP_SUPPORTED_SHAPES` that fits (`sdk-libs/ts/interface/src/shape.ts:32-42`). A
single-input transfer to six recipients therefore selects 1 in 8 out and produces
a 2108-byte transaction. Nothing refuses it. The transaction reaches the RPC,
which rejects it, and because confirmation cannot distinguish a rejected
transaction from a dropped one (finding F2 in the comparison study), the caller
is told the confirmation timed out.

### Why lookup tables cannot help a shielded transfer

A v0 message replaces a 32-byte inline address with a 1-byte index and pays a
fixed overhead of 37 bytes: one version byte, one byte of lookup count, the
32-byte table address, and two compact-u16 index-array lengths. Break-even is two
compressible addresses. One saves 32 and costs 37, a net loss of 5.

A shielded transfer has exactly one compressible address. The fee payer is a
signer, and a lookup table cannot supply a signer. The shielded-pool program is
the instruction's program id, and program ids cannot be loaded from a lookup
table, because transaction ingestion computes fees and compute limits by static
analysis before resolving tables
([solana-labs/solana#25034](https://github.com/solana-labs/solana/issues/25034)).
That leaves the tree. The measured `+5` in the transfer column is that
arithmetic, byte for byte, and the measurement confirms the reasoning rather than
the other way round.

An SPL withdrawal has three compressible protocol-owned addresses, the tree, the
vault, and the recipient, so it saves 96 and pays 39, a net 57 bytes. Across the
ten shapes that rescues one: a 5 in 3 out withdrawal at 1240 bytes drops to 1183
and becomes sendable. It moves no transfer under the limit and it moves the three
oversized shapes nowhere near it.

### What actually moves the number

The specified ciphertext format (AES-256-CTR without an authentication tag, owner
and sender public keys dropped from the ciphertexts, proof as a one-byte rail tag
plus 128 bytes on the eddsa rail) is described in `xtask/src/main.rs:347-353` and
measured by the same tool:

| Shape | ix data | Transfer | Withdraw |
| --- | --- | --- | --- |
| 1 in 1 out | 362 | | 707 |
| 1 in 2 out | 397 | | 742 |
| 2 in 2 out | 435 | | 780 |
| 2 in 3 out | 551 | 756 | 896 |
| 3 in 3 out | 589 | 794 | 934 |
| 4 in 3 out | 627 | 832 | 972 |
| 4 in 4 out | 743 | 948 | 1088 |
| 5 in 3 out | 665 | 870 | 1010 |
| 5 in 4 out | 781 | 986 | 1126 |
| 1 in 8 out | 1093 | **1298** | **1438** |

Nine of the ten shapes fit, the widest of them using 1126 of 1232 bytes. The P256
rail adds 64 bytes for the BSB22 commitment and its proof of knowledge, which
keeps the same nine inside the limit. A recipient costs 116 bytes instead of 232,
so the format change is worth roughly seven recipients of budget against the 5
bytes a lookup table costs a transfer. The comparison is not close, and it is the
reason this study recommends against scheduling v0 for size.

The remaining 1 in 8 out overflow is a property of the multi-recipient layout
rather than of the shape. Under the split layout, where one sender bundle covers
each output slot, the same 1 in 8 out shape compiles to 812 bytes as a transfer.

## How the same problem was handled at Light Protocol, and three corrections

**Light did not migrate to v0; it started there.** Its JavaScript SDK has built
v0 messages since its first transaction code. Within `js/stateless.js/src`,
`compileToV0Message` first appears in `a6e67a04e` (2024-03-12, "feat: JS
compressed-token", #513), and the string appears in the wider repository as far
back as `16300a3bc` (2022-11-07). `new Transaction()` appears at no point in the
history of `js/stateless.js/src`. There is no migration commit, so there is no
recorded trigger, and the premise that a growing account count forced Light's
hand is not supported by its history. F1's sentence "it does so because it had
to" should be struck. One nearby commit is easy to misread as the origin:
`e76b1b80f` (2024-03-07) added `test-utils/send-and-confirm.ts` but introduced no
v0 compilation, so it is not the first v0 usage.

**`state-tree-lookup-table.ts` is a discovery registry, not a size measure.** F1
cites it as creating lookup tables that hold state tree and queue addresses
"because compressed transactions run out of account slots". The code does
something else. Its three exported functions, `createStateTreeLookupTable`,
`extendStateTreeLookupTable`, and `nullifyLookupTable`, are marked `@internal`, and
the tables are read back by `getAllStateTreeInfos`
(`js/stateless.js/src/utils/get-state-tree-infos.ts:144-200`), which walks the
addresses in groups of three, tree then queue then cpi context, to build the
`TreeInfo` list the SDK selects a tree from. `extendStateTreeLookupTable`
enforces that grouping by rejecting a table whose length is not a multiple of
three (`state-tree-lookup-table.ts:90-92`). A second table, written by
`nullifyLookupTable`, records which trees have rolled over. Neither table is
passed to `compileToV0Message`. Light is using a lookup table as a cheap
append-only address registry, reading it with `getAddressLookupTable`, and taking
no transaction-size benefit from it.

**Optional lookup tables arrived later, for a different program.** `2b9542d63`
(2024-08-14, "feat: lookuptable support + batch compress", #1087) added the
optional `lookupTableAccounts` parameter to `buildTx`
(`js/stateless.js/src/utils/send-and-confirm.ts:26-39`), which forwards it to
`compileToV0Message`. The commit body is "add lut / cleanup / cleanup", so the
reason is not recorded. The co-changed files are compressed-token's `program.ts`,
`mint-to.ts`, `compress.ts`, and a new `create-token-program-lookup-table.ts`,
which is consistent with batch compression to many recipients, where each
recipient is an account in the list. Zolana's `transact` has no equivalent
pressure, because its recipients are commitments inside the instruction data
rather than accounts.

On the mechanics the owner's standing rule would have us copy:

Light creates the state-tree tables with
`AddressLookupTableProgram.createLookupTable`, taking a payer and a separate
authority keypair, and appends with `extendLookupTable`
(`state-tree-lookup-table.ts:22-128`). The resulting pair of addresses is pinned
in `js/stateless.js/src/constants.ts` as a `StateTreeLUTPair`, so the state tree
registry is a protocol-owned singleton set rather than something a user creates.
The payer is whoever runs the protocol tooling. The compressed-token table is the
other kind: `createTokenProgramLookupTable` is public and caller-created, holds
the token program's default accounts plus whichever mints the caller passes, and
is paid for by that caller.

When a needed address is not in a table, Light throws. `getTreeInfoByPubkey`
fails with a message telling the caller to set `activeStateTreeInfos` from the
latest tree accounts, or to configure custom trees manually
(`get-state-tree-infos.ts:39-59`). There is no fallback and no on-demand
extension. Copying that behaviour is cheap, which matters if Zolana later needs
it.

**Light's newest package is not a transaction-layer move to `@solana/kit`.** F1
reads `js/token-interface/package.json` correctly: it depends on `@solana/kit`,
`@solana/compat`, and `@solana/instruction-plans`. What that dependency does is
narrower than the framing suggests. The package builds legacy web3.js
`TransactionInstruction` values and converts them at the boundary with
`fromLegacyTransactionInstruction`
(`js/token-interface/src/instructions/_plan.ts:1-24`), exposing a `./kit` entry
point that returns kit-shaped instructions. It compiles no transactions with kit
and keeps `@solana/web3.js` as a peer dependency, so it is an interop shim over a
web3.js core. "Light adopted kit, so should we" is not an argument this code
supports; a kit decision has to stand on Zolana's own constraints.

## What it would cost

### The hand-written compiler in TypeScript

A v0 message is the legacy message with a `0x80` version prefix in front and an
address-table-lookups vector on the end, each entry being a 32-byte table address
plus two byte-index arrays. Adding that to `compileLegacyTransaction` is roughly
40 lines. Doing it for the wallet and test-kit copies as well is roughly 40 more,
unless the three are consolidated first, which they should be.

The larger piece is that using a table means reading one. The SDK would need a
hand-written decoder for the address lookup table account layout, a discriminator
plus authority, deactivation slot, last-extended slot and fields, then the
address array. That is the same category of hand-maintained layout parsing that
F1 objects to, so this path buys the capability at the cost of deepening the
problem F1 names.

### The signing path and the wallet surface

Neither moves. The public type is
`Transaction = { messageBytes: Uint8Array; signatures: readonly (Signature |
undefined)[] }` (`sdk-libs/ts/interface/src/index.ts:72-75`), and a v0 message is
still bytes. Signing covers the serialized message including its version byte, so
a signer that signs `messageBytes` today signs a v0 message correctly with no
change. This is the single most important cost finding in the study, because it
is what decouples the v0 decision from everything else: the boundary type does
not encode the message version, so adopting v0 does not ripple into callers.

The exception is a wallet that speaks web3.js types rather than bytes. Phantom
and wallet-adapter expect `Transaction` or `VersionedTransaction` objects, and
bridging to them requires constructing the right one. That is an
interoperation requirement, not a size requirement.

### The same constraint in Rust

The Rust SDK has the same constraint and is already half-converted, which was not
previously recorded. Its submission surface takes `VersionedTransaction` already
(`sdk-libs/client/src/client.rs:404`, `:428`, `:621`, `:644`;
`sdk-libs/client/src/rpc.rs:198`, `:217`, `:407`, `:429`), but its compilers build
legacy messages: `build_unsigned_solana_transaction` calls `Message::new` and
`SolanaTransaction::new_unsigned` (`client.rs:774-776`), and the wallet actions do
the same (`sdk-libs/wallet/src/actions/deposit.rs:195`,
`sdk-libs/wallet/src/user_registry.rs:219`).

So the Rust change is materially smaller than the TypeScript one. Rust has
`v0::Message::try_compile` from `solana-message` available, and `xtask` already
calls it (`xtask/src/main.rs:498`), so the compiler change is a few lines per site
with no hand-written layout work. The two languages would need the change at the
same time only if a shared fixture pins compiled output, which is the next
question.

### Fixtures and oracles

The oracle surface is smaller than it looks, for a reason worth stating.

Two cross-language oracles pin compiled message structure:
`legacy-message-order-v1.json` and `merge-message-order-v1.json`, generated by
`legacy_message_account_order_oracle` and `merge_message_account_order_oracle`
(`sdk-libs/client/src/client.rs:1144`, `:1234`) and consumed by
`sdk-libs/ts/client/test/vectors/legacy-message-order.test.ts`. Both pin the
header counts, the account key list, and the compiled instruction indexes. Their
own note records the boundary: "Account keys and compiled indexes only; the
instruction data bytes belong to the interface rows"
(`client.rs:1209`). They are regenerated with `ZOLANA_WRITE_ORACLES=1`.

Because they pin account keys and indexes rather than raw message bytes, adding a
version prefix without using a table leaves both oracles valid unchanged. Only
moving an address into a lookup table renumbers the indexes and shortens the
static key list, and only then do they need regeneration. That splits the work
cleanly: v0 support alone is oracle-neutral, and lookup-table use is not.

Six fixture files do pin raw `messageBytes`: `wallet/deposit.json`,
`wallet/user_registry.json`, `wallet/create_associated_token_account.json`, and
the `workflows/action-merge-v1.json`, `action-split-v1.json`, and
`action-ata-idempotent-v1.json` workflow records. These cover wallet and workflow
instructions rather than `transact`. They change only if those specific
instructions switch version, so a `transact`-only v0 rollout leaves them alone.

### Rough size

Splitting by what is actually being bought:

A size check in the compilers is an afternoon. Consolidating the three
hand-written compilers into one is one to two days. Adding v0 emission without
lookup tables, given the consolidation, is one to two days across both languages
and disturbs no oracle. Adding lookup table support on top, including the account
layout decoder, table lifecycle, and oracle regeneration, is roughly a week.
Adopting `@solana/kit` instead is a different decision with a different
justification and belongs with F1.

## Testing the claim that waiting gets more expensive

The claim is right, for a reason other than the one usually given.

The usual reason, that a version change ripples through call sites, does not
apply here. The boundary type is bytes (`interface/src/index.ts:72-75`), so
callers, signers, and the wallet surface are indifferent to message version.
Adding v0 does not touch them, today or in six months. On that axis the cost is
flat, and the 18 TypeScript files that reference `messageBytes` are not a
migration burden.

What does accrete is the hand-written compiler itself, and the accretion is
measurable. The five copies of this logic in the SDK were created on a single day:

| Copy | Commit | Date |
| --- | --- | --- |
| `client/src/client.ts` compiler and `compactU16` | `13cb30ec` | 2026-07-24 |
| `client/src/solana-rpc.ts` `compactU16` | `13cb30ec` | 2026-07-24 |
| `wallet/src/internal.ts` compiler and `compactU16` | `48da6682` | 2026-07-24 |
| `test-kit/src/user-registry.ts` compiler and `compactU16` | `e20d0469` | 2026-07-24 |
| `e2e/instructions/acceptance.test.ts` `compactU16` | `9905e992` | 2026-07-24 |

One message compiler became three and one `compactU16` became five, across four
commits, in a package that is two days old. The pattern is that each new package
needing to build or parse a transaction writes its own copy, because there is no
shared one to import. If that rate continues even slowly, a v0 change that costs
40 lines in one compiler costs 40 lines in each of six by the time it is done,
and the copies drift in the meantime, which they already have in the tie-break
comparator.

So the accurate version of the owner's claim is narrower and more actionable than
the original. What gets more expensive is not the version migration, it is the
duplication the version migration has to cross. That reframes the interim work:
consolidating the compilers captures most of the value of acting early, and it is
worth doing whether or not v0 is ever scheduled.

The public API shape is the one place the claim does not hold. Because
`Transaction` is bytes, no amount of waiting makes the API harder to change,
since it does not have to change.

## The situation after, sequenced

**Add a compiled message size check. An afternoon, and nothing depends on it.**
Compare the message length plus the signature array against 1232 in the
compilers, and throw a named error carrying the measured size and the limit.
Before: a six-recipient transfer builds, submits, is rejected, and reports
`CLIENT_CONFIRMATION_TIMEOUT`. After: it fails in the SDK at the point where the
caller can still change the shape, with the two numbers that explain why. The SDK
currently builds unsendable transactions and misreports the failure, so this is
the one item here that is a defect fix rather than a design choice.

**Decide what the shape list advertises.** `SPP_SUPPORTED_SHAPES` lists ten
shapes (`shape.ts:12-23`) and `selectSppShape` will return any of them, including
three the current ciphertext format cannot send. Either narrow what the builder
resolves to, or record the three as known-unsendable until the format change
lands. Leaving resolution free to pick 1 in 8 out while nothing can send it is
the state that produced the misreported failure above.

**Consolidate the three compilers into one.** One to two days, justified by the
measured duplication rather than by v0. It also removes the tie-break divergence
and turns any future version change into a single edit.

**Land the ciphertext format change, on the protocol schedule.** It is what buys
the headroom: nine of ten shapes inside the limit, the widest at 1126 bytes, and
116 bytes per recipient instead of 232. Its scheduling belongs to the protocol
work rather than to this document, but this document is the measurement saying
the size problem is that change's to solve.

**Leave versioned transactions unscheduled.** At the specified ciphertext format
there is 106 bytes of headroom on the widest sendable shape, and a lookup table
would spend 5 of them on a transfer. Building v0 support now would add a
hand-written account layout decoder to maintain and would move no shape from
unsendable to sendable.

## Triggers that should change this answer

Revisit when one of these becomes observable, rather than on a date.

**A second pool tree is deployed.** This is the most likely trigger and the one
worth watching. `InputUtxo::tree_index` is a `u8` that is zero everywhere today
because `TransactAccounts` loads one tree (`account.rs:24-27`). The moment a spend
can name two trees, a transfer has two compressible protocol-owned addresses,
which is exactly the lookup-table break-even, and a five-input spend across five
trees would put four more 32-byte addresses inline. At that point the account
count starts scaling with input count and Zolana acquires the shape of the
problem Light solved.

**`OwnerTag::Account` starts being used.** The field comment already names the
case: `Account` "indexes the raw account list ... so an address-lookup table can
compress self-owned outputs"
(`program-libs/interface/src/instruction/instruction_data/transact.rs:90-96`). If
outputs begin referencing accounts, the account list grows with output count and
the arithmetic in this study stops holding.

**Multi-owner spends reach the account list.** `eddsa_signer_index` selects a
signer account per input, so a spend of five inputs owned by five different
ed25519 keys names five signer accounts. Signers cannot come from a lookup table,
so this consumes bytes no table can recover. It is a size argument, and an
argument for the ciphertext format change, rather than a lookup-table argument.

**A wallet integration requires `VersionedTransaction`.** Phantom and
wallet-adapter speak web3.js types. This is F1's interoperation argument and a
real reason to build v0 support. It is not a size reason and should be decided
with F1.

The check is cheap and already written. Re-run the `tx-size` xtask shown earlier,
passing whichever shapes are of interest, after a change to the ciphertext
format, the proof layout, or the `transact` account list, and compare against the
tables above.

## What is uncertain

The size measurements are reproduced from committed code and can be re-run, so
the arithmetic is not where the risk is. Three things are less settled.

Whether the ciphertext format change is scheduled. This study recommends
against v0 partly because that change makes v0 unnecessary for size. If it slips
indefinitely, three shapes stay unsendable and the recommendation to narrow
`SPP_SUPPORTED_SHAPES` becomes more than bookkeeping. What would settle it: a
date, or an owner, for the format work.

Whether a second pool tree is planned, and on what horizon. The whole account
arithmetic rests on `TransactAccounts` loading one tree. This study could not find
a roadmap statement either way. What would settle it: a yes or no from whoever
owns tree rollover.

Whether the 40-line estimate for v0 emission survives contact with the address
lookup table account decoder. The message assembly side is well understood and
the estimate there is firm. The decoder is the part that has not been prototyped,
and hand-written account layout parsing has been the source of the SDK's slower
work so far. What would settle it: an afternoon spent writing the decoder against
a real table account.

## References

Read in this worktree at `03584e8e`:

- `sdk-libs/ts/client/src/client.ts:620-703`, the client compiler; `:667`, the
  account-count guard that is its only size check; `:735`, `compactU16`.
- `sdk-libs/ts/wallet/src/internal.ts:105`, `:120-211`, the wallet compiler.
- `sdk-libs/ts/test-kit/src/user-registry.ts:300`, `:390`, the test-kit copy.
- `sdk-libs/ts/client/src/solana-rpc.ts:554`, `:572-577`, the versioned-aware read
  path; `:609`, the base58 length search; `:627`, `compactU16`.
- `sdk-libs/ts/interface/src/index.ts:72-75`, the `Transaction` boundary type.
- `sdk-libs/ts/interface/src/shape.ts:12-42`, the ten shapes and their selection.
- `sdk-libs/ts/transaction/src/instructions/transact.ts:57`, `:561-564`, shape
  resolution from recipient count.
- `sdk-libs/client/src/client.rs:774-776`, the Rust legacy compiler; `:404`,
  `:428`, the versioned submission surface; `:1144`, `:1234`, the two message
  order oracles.
- `sdk-libs/wallet/src/actions/deposit.rs:195`,
  `sdk-libs/wallet/src/user_registry.rs:219`, the other Rust compile sites.
- `program-libs/interface/src/instruction/builders/transact.rs:57-80`, the account
  layout.
- `program-libs/interface/src/instruction/instruction_data/transact.rs:78-87`,
  `InputUtxo`; `:90-103`, `OwnerTag`.
- `programs/shielded-pool/src/instructions/transact/account.rs:24-27`, the single
  tree account.
- `xtask/src/main.rs:326-660`, the size measurement tool; `:491-501`, the two
  compile paths it measures.

Light Protocol, read at `b7936408b`:

- `js/stateless.js/src/utils/send-and-confirm.ts:26-39`, `buildTx`.
- `js/stateless.js/src/utils/state-tree-lookup-table.ts:22-220`, the registry
  tables.
- `js/stateless.js/src/utils/get-state-tree-infos.ts:39-59`, `:144-200`, where
  they are read back and what happens on a miss.
- `js/token-interface/src/instructions/_plan.ts:1-24`, the kit conversion.
- Commits `16300a3bc` (2022-11-07, earliest v0 usage in the repository),
  `a6e67a04e` (2024-03-12, first v0 usage in `js/stateless.js/src`), and
  `2b9542d63` (2024-08-14, optional lookup tables).

Solana:

- `MAX_TX_ACCOUNT_LOCKS = 128`, `solana-transaction-3.1.0/src/sanitized.rs:21`.
- Static program ids:
  [solana-labs/solana#25034](https://github.com/solana-labs/solana/issues/25034).
