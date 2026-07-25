# Versioned transactions and address lookup tables

**The wall is real, it arrived before this study started, and versioned
transactions are not the thing that removes it. The binding limit is the
1232-byte transaction size, not the account count. Zolana's widest shape (1 in,
8 out) compiles to a 2108-byte transfer today, and a lookup table makes it 2113.
Three of the ten supported shapes cannot be sent right now, in either message
version. The fix is the ciphertext format, which is already specified and which
brings nine of the ten shapes under the limit; v0 and lookup tables buy 5 bytes
of harm on a pure transfer and 57 bytes of help on an SPL withdrawal. Do not
schedule v0 for the size problem. Do add a size check to the compiler this week,
because the SDK currently builds unsendable transactions and reports them as
confirmation timeouts.**

Written 2026-07-26 on branch `port/versioned-tx` at the integration tip
(`515a2fb4`). This document answers finding F1's lookup-table paragraph in
[`light-protocol-comparison.md`](light-protocol-comparison.md) and corrects two of
its claims. It does not settle the wider `@solana/kit` question, which is F1's
main body and which turns out to rest on different grounds than the ones stated
there.

## Goal

Decide whether the TypeScript SDK needs `VersionedTransaction` support and
address lookup tables, and when. The SDK depends on no Solana library and
compiles messages by hand in `compileLegacyTransaction`
(`sdk-libs/ts/client/src/client.ts:620-702`), so it produces legacy messages
only.

## What is true now

Numbers in this section are measured, not estimated. `xtask tx-size` builds real
`TransactIxData`, compiles it into both a legacy and a v0 message, and reports
the bincode length of the signed transaction (`xtask/src/main.rs:326-660`). Run
it with:

```bash
cargo run -p xtask -- tx-size 1:1 1:2 2:2 2:3 3:3 4:3 4:4 5:3 5:4 1:8
```

### The account count is not the constraint, and it does not grow with shape

A shielded transfer names three accounts: payer, tree, and the shielded-pool
program itself, which is present so the `emit_event` self-invocation can load it
(`program-libs/interface/src/instruction/builders/transact.rs:57-80`). The widest
account layout in the program is an SPL withdrawal at eight, and a zone SPL
withdrawal at nine.

| Instruction | Accounts |
| --- | --- |
| `transact`, shielded transfer | 3 |
| `merge_transact` | 4 |
| `deposit`, SOL | 5 |
| `transact`, SOL withdrawal | 6 |
| `deposit`, SPL | 7 |
| `transact`, SPL withdrawal | 8 |
| `zone_transact`, SPL withdrawal | 9 |

Add the compute-budget program and the ceiling is ten. The runtime caps a
transaction at 128 account locks
(`MAX_TX_ACCOUNT_LOCKS`, `solana-transaction-3.1.0/src/sanitized.rs:21`), and
`compileLegacyTransaction` refuses above 256 (`client.ts:667`). Roughly thirteen
times the headroom, and none of it is consumed by widening the shape.

That last clause is the structural reason Zolana does not have Light's problem.
Light's compressed transaction names a state tree and a queue per input account,
so its account list scales with input count. Zolana's `transact` takes exactly
one `tree` account whatever the shape
(`programs/shielded-pool/src/instructions/transact/account.rs:24-27`), and the
nullifier tree lives inside that same account rather than beside it
(`programs/shielded-pool/src/instructions/transact/processor.rs:211-220`). Going
from one input to five adds 38 bytes of instruction data and zero accounts.

### The message size is the constraint, and three shapes already exceed it

Signed transaction size, current ciphertext format (AES-GCM, recipient and
sender public keys repeated inside each ciphertext, 192-byte proof). Bold marks
a shape past the 1232-byte limit. A transfer needs at least one recipient, and
recipients start at output slot 2, so shapes below three outputs have no transfer
column.

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

Marginal costs, derived from the differences and confirmed against the codecs:
one more input costs 38 bytes (`InputUtxo` is 32 + 2 + 2 + 1 + 1,
`program-libs/interface/src/instruction/instruction_data/transact.rs:78-85`), and
one more recipient costs 232 bytes at the current format.

The 1 in 8 out row is reachable from the public API. `TransferBuilder.send` can
be called repeatedly, and `withShape` resolves
`resolveShape(inputs, SENDER_SLOT_COUNT + recipients.length)`
(`sdk-libs/ts/transaction/src/instructions/transact.ts:561-580`), so a single-input
transfer to six recipients selects the 1 in 8 out shape and produces a 2108-byte
transaction. Nothing in the SDK refuses it: the only size guard in
`compileLegacyTransaction` counts accounts (`client.ts:667`), and no code path
compares `messageBytes.length` against 1232. The transaction reaches the RPC,
which rejects it, and because confirmation cannot distinguish a rejected
transaction from a dropped one (F2 in the comparison study), the caller is told
the confirmation timed out.

### Why lookup tables cannot help a shielded transfer

A v0 message replaces a 32-byte inline address with a 1-byte index, and pays for
the privilege with a fixed 37 bytes: 1 version byte, 1 byte of lookups count, the
32-byte table address, and two compact-u16 index array lengths. Break-even is
therefore two compressible addresses. One saves 32 and costs 37, for a net loss
of 5.

A shielded transfer has exactly one compressible address. The fee payer is a
signer, and a lookup table cannot supply a signer. The shielded-pool program is
the instruction's program id, and program ids cannot be loaded from a lookup
table, because transaction ingestion has to compute fees and compute limits by
static analysis before resolving tables
([solana-labs/solana#25034](https://github.com/solana-labs/solana/issues/25034),
[`v0::Message` docs](https://docs.rs/solana-program/latest/solana_program/message/v0/struct.Message.html)).
That leaves the tree. The measured `+5` in the transfer column is that
arithmetic, byte for byte.

An SPL withdrawal has three compressible protocol-owned addresses (tree, vault,
recipient), so it saves 96 and pays 39, a net 57 bytes. Across the ten shapes
that rescues precisely one: a 5 in 3 out withdrawal at 1240 bytes drops to 1183
and becomes sendable. It moves no transfer under the limit and it moves the three
oversized shapes nowhere near it.

### The ciphertext format is what moves the number

The specified format (AES-256-CTR, no authentication tag, owner and sender public
keys dropped from the ciphertexts, proof as a 1-byte rail tag plus 128 bytes on
the eddsa rail) is already described in `xtask/src/main.rs:347-353`. Measured at
that format:

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
so the format change is worth roughly seven recipients' worth of budget, against
the 5 bytes a lookup table costs a transfer.

The remaining 1 in 8 out overflow is a property of the multi-recipient layout
rather than of the shape. When one sender bundle covers each output slot, the
split layout, the same 1 in 8 out shape compiles to 812 bytes as a transfer and
952 as a withdrawal.

## Two corrections to the comparison study, and what Light actually did

**Light did not move to v0.** Its JavaScript SDK has built v0 messages since its
first transaction code. `compileToV0Message` appears in `e76b1b80f`
(2024-03-07), the commit that brought the JS packages up to the Rust changes, and
`new Transaction()` appears at no point in the history of `js/stateless.js/src`.
There is no migration commit, so there is no recorded trigger, and the premise
that a growing account count forced Light's hand is not supported by its history.
F1's sentence "it does so because it had to" should be struck.

**`state-tree-lookup-table.ts` is a discovery registry, not a size measure.** F1
cites it as creating lookup tables that hold the state tree and queue addresses
"because compressed transactions run out of account slots". What the code does is
different. The module is marked `@internal`, and its tables are read back by
`getAllStateTreeInfos` (`js/stateless.js/src/utils/get-state-tree-infos.ts:144-200`),
which walks the addresses in groups of three (tree, queue, cpi context) to build
the `TreeInfo` list the SDK selects a tree from. A second table,
`nullifyLookupTable`, records which trees have rolled over. Neither is passed to
`compileToV0Message`. Light is using a lookup table as a cheap append-only
address registry, reading it with `getAddressLookupTable`, and taking no
transaction-size benefit from it.

**Optional lookup tables came later, for a different program.** `2b9542d63`
(2024-08-14, "feat: lookuptable support + batch compress", #1087) added the
optional `lookupTableAccounts` parameter to `buildTx`
(`js/stateless.js/src/utils/send-and-confirm.ts:26-39`). The commit body is
"add lut / cleanup / cleanup", so the reason is not recorded. The co-changed
files are compressed-token's `program.ts`, `mint-to.ts`, `compress.ts`, and a new
`create-token-program-lookup-table.ts`, which is consistent with batch
compression to many recipients, where each recipient is an account in the list.
Zolana's `transact` has no equivalent pressure: its recipients are commitments
inside the instruction data, not accounts.

Answers to the questions the plan asked about Light's mechanism:

- **Where the table comes from.** `createStateTreeLookupTable` calls
  `AddressLookupTableProgram.createLookupTable` with a payer and an authority
  keypair, and `extendStateTreeLookupTable` appends triples
  (`js/stateless.js/src/utils/state-tree-lookup-table.ts:22-125`). Both are
  `@internal`, and the resulting pair of addresses is pinned in
  `js/stateless.js/src/constants.ts` as a `StateTreeLUTPair`, so the state tree
  registry is a protocol-owned singleton set rather than per-user. The
  compressed-token table is the other kind: `createTokenProgramLookupTable` is
  public, caller-created, and holds the token program's default accounts plus
  whichever mints the caller passes.
- **What happens when an address is missing.** `getTreeInfoByPubkey` throws, with
  a message telling the caller to set `activeStateTreeInfos` from the latest tree
  accounts or to configure custom trees manually
  (`get-state-tree-infos.ts:38-58`). There is no fallback and no on-demand
  extension.

**Light's newest package is not a transaction-layer move to `@solana/kit`.** F1
reads `js/token-interface/package.json` correctly: it depends on `@solana/kit`,
`@solana/compat`, and `@solana/instruction-plans`. What that dependency does is
narrower than the framing suggests. The package builds legacy web3.js
`TransactionInstruction` values and converts them at the boundary with
`fromLegacyTransactionInstruction`
(`js/token-interface/src/instructions/_plan.ts:1-24`), exposing a `./kit`
entry point that returns kit-shaped instructions
(`js/token-interface/src/kit/index.ts`). It compiles no transactions with kit and
keeps `@solana/web3.js` as a peer dependency. So it is an interop shim over a
web3.js core. "Light adopted kit, so should we" is not an argument this code
supports; a kit decision has to stand on Zolana's own constraints.

## What v0 would cost

Two paths, and the important thing about them is that they cost very differently
and only one of them incurs F1's price.

**Path A, extend the hand-written compiler.** A v0 message is the legacy message
with a `0x80` version prefix in front and an address-table-lookups vector on the
end, each entry being a 32-byte table address plus two byte-index arrays. The
signing surface does not move, because `Transaction` is `{ messageBytes,
signatures }` and a v0 message is still bytes, so the type at the boundary of
`@zolana/client` and `@zolana/wallet` survives untouched. The reading side is
already v0-aware: `instructionGroups` resolves account indexes against the
message keys followed by `meta.loadedAddresses`, writable before readonly
(`sdk-libs/ts/client/src/solana-rpc.ts:475-490`, `:568-580`). The new work is
roughly 40 lines in the compiler plus a hand-written decoder for the address
lookup table account layout, which is the same category of hand-maintained
layout parsing that F1 objects to. Small, and it deepens the problem F1 names.

**Path B, adopt `@solana/kit`.** Measured rather than guessed:
`@solana/transaction-messages`, `@solana/transactions`, and `@solana/addresses`
at 7.0.0, bundled with esbuild under the `browser` condition and minified, come
to 51.5 kB, or 16.2 kB gzipped. Running the exact `NODE_GLOBAL` pattern from
`sdk-libs/ts/config/browser-check.mjs:17` against that bundle passes: no
`Buffer`, no `require(`, no `process` member access. The two apparent hits are
`ArrayBuffer` and the words "processing" and "processed" inside error strings,
and the gate's word boundaries already exclude them. So the browser objection to
kit does not survive measurement, and against the 585 kB Poseidon artifact
accepted in [`poseidon-wasm-and-packaging.md`](poseidon-wasm-and-packaging.md),
16.2 kB is not what decides this.

What decides it is the boundary type. Adopting kit's `compileTransaction` deletes
`compileLegacyTransaction`, both `compactU16` copies, the base58 length search,
and supplies `compressTransactionMessageUsingAddressLookupTables` at no
additional cost, but it changes the public `Transaction` shape, so each caller
and each test moves with it. That is F1's cost, it is real, and this document
does not argue for paying it. It argues that the lookup-table question is not a
reason to pay it, because Path A reaches the same capability without touching the
boundary.

## What else is downstream of owning the transaction layer

Three consequences, and only the first is urgent.

**No size check.** Covered above. The SDK compiles a transaction it cannot send
and the failure surfaces as a timeout.

**A base58 decoder that searches for its own length.** `decodeBase58UnknownLength`
tries each length from 1 to 1232 until one parses
(`sdk-libs/ts/client/src/solana-rpc.ts:608-617`), on the confirmation path, once
per instruction. It is correct and it is a strange thing to own.

**`compactU16` implemented twice**, at `client.ts:730` and `solana-rpc.ts:627`.
The README records what duplicated arithmetic did to the Poseidon tables
(`README.md:132-141`).

These argue for adopting a library, and they argue for it independently of
lookup tables. They are F1's argument, not this document's, and they are not made
more or less urgent by anything measured here.

## What would be true after

Sequenced by when it has to happen.

**Before the SDK is used in production. Add a message size check.** Compare
`messageBytes.length` plus the signature array against 1232 in
`compileLegacyTransaction`, and throw a named error carrying the measured size
and the limit. Before: a six-recipient transfer builds, submits, is rejected, and
reports `CLIENT_CONFIRMATION_TIMEOUT`. After: it refuses in the SDK, at the point
where the caller can still change the shape, with the two numbers that explain
why. This is an afternoon and it does not depend on any decision below.

**Before the SDK is used in production. Decide what the shape list advertises.**
`SPP_SUPPORTED_SHAPES` lists ten shapes
(`sdk-libs/ts/interface/src/shape.ts:12-23`) and `resolveShape` will select any of
them, including three the current ciphertext format cannot send. Either narrow
what the builder will resolve to, or record the three as known-unsendable until
the format change lands. Leaving `resolveShape` free to pick 1 in 8 out while
nothing can send it is the state that produced the confusing failure above.

**Schedule soon, and not for this reason. Land the ciphertext format change.** It
is the change that buys the headroom: nine of ten shapes inside the limit, the
widest at 1126 bytes, and 116 bytes per recipient instead of 232. It is already
specified. Its scheduling belongs to the protocol work rather than to this
document, but this document is the measurement that says the size problem is its
to solve.

**Genuinely fine to leave. Versioned transactions and lookup tables.** At the
specified ciphertext format there is 106 bytes of headroom on the widest sendable
shape and a lookup table would spend 5 of them on a transfer. Building a v0
compiler now would add a hand-written account layout decoder to maintain and
would move no shape from unsendable to sendable.

## The signal that should change this answer

Revisit when any of these becomes observable, rather than on a calendar.

**A second pool tree is deployed.** `InputUtxo::tree_index` is a `u8` that is
zero everywhere today because `TransactAccounts` loads one tree
(`account.rs:24-27`). The moment a spend can name two trees, a transfer has two
compressible protocol-owned addresses, which is exactly the lookup-table
break-even, and a five-input spend across five trees would put four more 32-byte
addresses inline. This is the most likely trigger and the one worth watching.

**Multi-owner spends reach the account list.** `eddsa_signer_index` selects a
signer account per input (`processor.rs:266-278`), so a spend of five inputs
owned by five different ed25519 keys names five signer accounts. Signers cannot
come from a lookup table, so this consumes bytes that no table can recover, and
it is a size argument rather than a lookup-table argument.

**`OwnerTag::Account` starts being used.** The field comment already names the
case: it "indexes the raw account list ... so an address-lookup table can
compress self-owned outputs"
(`program-libs/interface/src/instruction/instruction_data/transact.rs:88-92`). If
outputs begin referencing accounts, the account list grows with output count and
the analysis in this document stops holding.

**A wallet integration requires `VersionedTransaction`.** Phantom and
wallet-adapter speak web3.js types. This is F1's interoperation argument and it
is a real reason to build v0 support; it is not a size reason, and it should be
decided with F1 rather than here.

The check itself is cheap and already written. Re-run the `xtask tx-size` command
shown above, passing the shapes to measure, after a change to the ciphertext
format, the proof layout, or the `transact` account list, and compare against the
tables here.

## References

Zolana:

- `sdk-libs/ts/client/src/client.ts:620-702`, the hand-written legacy compiler;
  `:667`, the account-count guard that is the only size check.
- `sdk-libs/ts/client/src/solana-rpc.ts:475-490`, `:568-580`, the v0-aware read
  path; `:608-617`, the base58 length search; `:627` and `client.ts:730`, the two
  `compactU16` copies.
- `sdk-libs/ts/transaction/src/instructions/transact.ts:561-580`, shape resolution
  from recipient count.
- `sdk-libs/ts/interface/src/shape.ts:12-23`, the ten supported shapes.
- `program-libs/interface/src/instruction/builders/transact.rs:57-80`, the account
  layout; `deposit.rs:50-67`, `merge_transact.rs:30-35`, `zone_transact.rs:50-74`
  for the others.
- `program-libs/interface/src/instruction/instruction_data/transact.rs:78-92`,
  `InputUtxo` and `OwnerTag`; `:113-175`, `TransactIxData`.
- `programs/shielded-pool/src/instructions/transact/account.rs:24-27`, the single
  tree account; `processor.rs:211-220`, the nullifier tree inside it.
- `xtask/src/main.rs:326-660`, the size measurement tool.

Light Protocol, at `b7936408`:

- `js/stateless.js/src/utils/send-and-confirm.ts:26-39`, `buildTx`.
- `js/stateless.js/src/utils/state-tree-lookup-table.ts`, the registry tables.
- `js/stateless.js/src/utils/get-state-tree-infos.ts:38-58`, `:144-200`, where they
  are read back.
- `js/token-interface/src/instructions/_plan.ts:1-24`, the kit conversion.
- Commits `e76b1b80f` (2024-03-07, first v0 usage) and `2b9542d63` (2024-08-14,
  optional lookup tables).

Solana:

- `MAX_TX_ACCOUNT_LOCKS = 128`, `solana-transaction-3.1.0/src/sanitized.rs:21`.
- Static program ids: [solana-labs/solana#25034](https://github.com/solana-labs/solana/issues/25034),
  [`v0::Message`](https://docs.rs/solana-program/latest/solana_program/message/v0/struct.Message.html).
