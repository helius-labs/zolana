# C03 `rpc.rs` against `rpc.ts`: the scope question, settled

Branch `port/c03`, from `9cddc3f5`. The row was left `DIVERGENT` by
[`stragglers.md`](stragglers.md#c03-rpcrs-against-rpcts-divergent-needs-a-scope-decision)
on the ground that it needed an owner's scope decision. It did not: the standing
rule in [`remaining-work.md`](../remaining-work.md#resolve-an-open-question-the-way-light-protocol-resolved-it)
decides it, and applying that rule dissolves most of the row.

| Was | Now | Needed |
| --- | --- | --- |
| DIVERGENT | PARITY on the surface question, with one pinned divergence outside the row | implemented here |

## Summary

Fifteen methods were recorded as having no TypeScript home. **Eight of them are
unimplemented, uncalled stubs in Rust**, so there is nothing to port. **One has a
TypeScript home under a different name**, and the TypeScript one works where the
Rust one does not. **Five are plain Solana reads** that Light Protocol never
ported either, because it inherits them; Zolana has nothing to inherit from, so
they are written onto the concrete transport, which is where Light keeps them.
**One is a real convenience with real callers** and is now a free function,
which is where Light keeps its equivalent.

The row's own headline was right that "11 of 30" is the wrong measure. It was
also wrong about which two methods matter, which is the part worth reading.

## 1. Revalidating the finding

`sdk-libs/client/src/rpc.rs` declares `Rpc` and `AsyncRpc` with every method
defaulting to `unsupported(..)`. A method appearing on the trait says nothing
about whether anything implements or calls it. Counting implementors and callers
rather than declarations moves eight of the fifteen off the list.

**Never implemented anywhere, and never called.** Only the trait default exists,
plus a `ZolanaClient` delegation to another default:

| Method | Implementors outside the trait | Callers |
| --- | --- | --- |
| `get_transaction_slot` | none | none |
| `send_versioned_transaction_with_config` | none | none |
| `process_transaction` | none | none |
| `process_transaction_with_context` | none | none |
| `process_versioned_transaction` | none | none |
| `create_and_send_versioned_transaction` | none | none |
| `send_and_prove` | none | none |
| `subscribe_to_shielded_transactions_by_tags` | none | none |

Porting any of these means writing a TypeScript method that rejects with
`CLIENT_UNSUPPORTED_RPC_METHOD`, which is what `SolanaRpc.getMerkleProofs`
already does and is not parity with anything. Rust reaching them returns
`ClientError::UnsupportedRpcMethod`; TypeScript not declaring them is a compile
error at the call site, which is the better of the two failures. **Nothing is
owed here.**

Two of the eight are worth a sentence each because the row singled them out.
`send_and_prove` is a trait declaration with no body beyond `unsupported(..)`:
there is no Rust behaviour to compare against, so "TypeScript is missing
`send_and_prove`" describes a name rather than a capability. The subscription is
the same, and is treated separately in section 5 because the reason to leave it
out survives even if Rust implements it later.

**`should_retry` already has a TypeScript home, and the row missed it.** Rust
declares it on both traits with a `false` default, `ZolanaClient::should_retry`
delegates to `self.rpc.should_retry(error) || indexer.should_retry(error)`, and
neither `SolanaRpc` nor `ZolanaIndexer` overrides it. **`should_retry` therefore
returns `false` for every error in Rust today**, which
[`pr-158-impact.md`](pr-158-impact.md) independently records. The port exports
`retryCause` and `isRetryable` from `@zolana/client`, which implement
`ClientError::retry_cause`. That is the classification `should_retry` was meant
to expose and does not reach. TypeScript is ahead here, not behind.

**The row's claim about `get_minimum_balance_for_rent_exemption` does not hold.**
It says the method is "called by the account-creating actions, so [it is] SDK
flow rather than harness". `sdk-libs/wallet` does not call it anywhere. Its
callers are `cli/`, `xtask/`, `sdk-libs/program-test` (the test harness),
`sdk-tests/`, and `program-tests/`. It is harness and operator tooling. That
does not mean it should not be ported, and section 4 gives the consumer that is
structurally blocked without it, but the reason the row gave for prioritising it
was not the true one.

**`create_and_send_transaction` is the one entry the row got exactly right.** It
is the only method on the trait with a body of its own rather than a default
rejection, and it has six callers in `sdk-libs/wallet`: `actions/submit.rs:133`,
`actions/deposit.rs:167`, `actions/create_associated_token_account.rs:32`, and
three in `user_registry.rs`.

## 2. What Light Protocol does

`js/stateless.js/src/rpc.ts:689`:

```ts
export class Rpc extends Connection implements CompressionApiInterface {
```

That one line answers the row's first question. Light's protocol interface,
`CompressionApiInterface`, declares only `getCompressed*`, `getValidityProof`,
and the indexer methods. Not one plain Solana read appears in it. `getSlot`,
`getSignatureStatuses`, `getMinimumBalanceForRentExemption` and the send
variants come from web3.js's `Connection`, which `Rpc` extends. Light's own code
calls `rpc.getSignatureStatuses` and `rpc.getSlot` freely
(`src/utils/send-and-confirm.ts:97,106`) without ever declaring them.

So the split Light draws is not "protocol methods and plain reads both on one
interface". It is **plain Solana surface on the concrete transport, protocol
surface on the interface**, and the class is the thing that has both.

Light's answer to `create_and_send_transaction` is equally explicit and is *not*
a method. `buildTx`, `buildAndSignTx` and `sendAndConfirmTx` are free functions
in `src/utils/send-and-confirm.ts`, in the same package as `Rpc`, taking the rpc
as a parameter. Light's actions compose them the same way. In
`src/actions/compress.ts:41-62`: read a blockhash, build the instruction, build
and sign, send and confirm.

Light has **no subscription** and **no retry classification** anywhere in
`js/stateless.js/src`. Searching its sources for `subscribe`, `WebSocket`,
`onLogs`, `onAccountChange`, `shouldRetry` and `retry` returns nothing outside
tests.

**Where the premise this row was handed turns out to be wrong.** The suggestion
was that our reads "come free from the underlying connection" and were never
Light's to port, so exposing the underlying RPC would close most of the row. The
first half is right about Light and wrong about us: **the TypeScript SDK depends
on neither `@solana/kit` nor `@solana/web3.js`**. There is no such dependency
anywhere under `sdk-libs/ts`. `SolanaRpc` is a hand-rolled JSON-RPC client over
`fetch`, chosen for the browser and bundle-size constraints in
`security-and-release.md`. There is no `Connection` to inherit from and no
underlying object to expose, so the free reads are not free. Light answers
*where* they belong; it cannot answer *whether to write them*, because it never
had to.

## 3. What was implemented

### The five plain reads, on `SolanaRpc` and not on `Rpc`

`getSlot`, `getBlockHeight`, `getSignatureStatuses`,
`getMinimumBalanceForRentExemption` and `getHealth` are now methods on the
`SolanaRpc` class. These are exactly the five that Rust's `SolanaRpc` implements
and TypeScript lacked; the trait's other reads were already carried.

They are deliberately **not** added to the `Rpc` interface, following Light's
split. Declaring them there would oblige `ZolanaClient`, `ZolanaIndexer` and
every caller's mock to answer chain-state questions they have no transport for,
which is the fat-trait shape Rust carries, thirty methods each defaulting to a
rejection, and the shape this port split apart on purpose. A caller who holds
a `ZolanaClient` reaches the transport through its public `rpc` field, which is
the closest thing this design has to Light's `Rpc is-a Connection`.

`health()` ships as `getHealth()`. Rust's name is the outlier: the wire method
is `getHealth` and so is web3.js's, and every other method in this class is
named for its wire method.

### `createAndSendTransaction`, a free function

Exported from `@zolana/client`, beside the existing `buildUnsigned*Transaction`
family, and composed exactly as Rust's default body composes: read a blockhash,
compile a legacy message with the payer as fee payer, hand it to the signer,
send.

It takes a `sign` callback where Rust takes `&[&Keypair]`. No SDK surface here
holds key material, which is a settled port decision (`TransactionSigner` in
`@zolana/wallet`) and is also how Light splits it. It refuses to submit a
transaction whose signer left a slot unfilled, with a new
`CLIENT_INCOMPLETE_SIGNATURES`. That is not TypeScript being stricter than Rust
in the sense
[step 5](../remaining-work.md#step-5-transaction-fifteen-rows) warns about:
`Transaction::new` fills every reserved slot by construction, so Rust cannot put
such a transaction on the wire at all. The same guard already existed inline in
`wallet/src/submit.ts`.

### The oracle

`xtask/src/bin/solana-rpc-reads.rs` writes
`sdk-libs/ts/vectors/solana-rpc-reads-v1.json`. Two mechanisms:

- For the reads, a real Rust `SolanaRpc` is pointed at a `TcpListener` that
  records the request body and answers with a canned response. The recorded
  request is therefore the JSON `solana_rpc_client` actually sends, which is not
  visible from our source, since that crate chooses the parameter list and the
  commitment.
- For `create_and_send_transaction`, a recorder implements only
  `get_latest_blockhash` and `send_transaction`, so the trait's **default body
  itself runs** and the transaction it compiled is captured verbatim.

This is the mock-RPC generator vehicle that
[`stragglers.md`](stragglers.md#c05-solana_rpcrs-against-solana-rpcts-partial)
records as the missing piece for C05's grouping oracle. It is not the same
fixture, but the harness now exists in `xtask` and C05 can reuse it.

**The oracle earned its keep immediately: it caught two request shapes this
change had guessed wrong.** `getMinimumBalanceForRentExemption` sends the data
length alone, with no commitment, and `getSignatureStatuses` sends the signature
list alone, with no config object. Both had been written with the trailing
config that every neighbouring method carries, which reads correct and is not.
`getHealth` sends `params: null` rather than `[]`, which the port now matches.

The transaction case is discriminating rather than incidental: its two readonly
unsigned accounts are introduced high address first, so a compiler ordering by
first appearance instead of by address produces different bytes.

### Control edits, each applied and observed to fail

| Edit | Caught by |
| --- | --- |
| restore the commitment on `getMinimumBalanceForRentExemption` | the rent read |
| restore `searchTransactionHistory` on `getSignatureStatuses` | the statuses read |
| send `[]` rather than `null` for `getHealth` | the health read |
| order compiled accounts by first appearance | the compiled message |
| drop the unfilled-signature guard | the refusal case |
| decode an absent status as a zero slot rather than `undefined` | the statuses read |
| drop `searchTransactionHistory` from `confirmTransaction` | the pinned divergence |

## 4. Decisions taken, for the owner to overrule

Light answers the placement question and not every scoping one. These are mine.

**The five reads are ported despite having no TypeScript consumer in this
repository.** The reasoning is not parity for its own sake. A TypeScript caller
holding a `SolanaRpc` has no fallback: there is no `Connection` beneath it and
the `fetch` and URL are private, so a plain `getSlot` is unreachable rather than
merely unported. Light's user never faces that, which is why Light's silence
cannot be read as "do not write them".

**`getMinimumBalanceForRentExemption` has a blocked consumer, and it is not the
one the row named.** Rust's `program-test::create_tree_instructions(rpc, ..)`
fetches the rent itself (`sdk-libs/program-test/src/instructions.rs:40`). The
TypeScript port of that function,
`test-kit/src/instructions.ts::createTreeInstructions`, takes `lamports` as a
caller-supplied parameter instead, and **has no caller anywhere in the
repository**, because nothing can compute the number to pass it. That is a
`test-kit` change rather than a `@zolana/client` one, so it is recorded here
rather than made: give `createTreeInstructions` the rpc and let it fetch, as
Rust does.

**`send_transaction_with_config` is not ported.** Rust implements it and nothing
calls it. Light's equivalent is `Connection.sendTransaction(tx, options)`, again
inherited. A config parameter with no consumer on either side is new surface
rather than parity, which is the same reasoning that left `Balances` and
`get_balance` unported under T14. If a caller needs to vary preflight or
commitment, the argument for adding it will come with a use.

**The versioned variants stay unported**, and this is not really C03's call:
[step A](../remaining-work.md#step-a-decide-about-address-lookup-tables-and-versioned-transactions)
has already ruled that v0 messages are not scheduled. Both are also among the
eight Rust never implemented.

## 5. The subscription, said deliberately

`subscribe_to_shielded_transactions_by_tags` is **not ported, and should not be
until something asks for it.** Three reasons, in decreasing order of weight.

1. **Rust does not have it either.** It is a trait declaration returning
   `unsupported(..)`, with no implementor and no caller. Porting it would mean
   inventing the behaviour in TypeScript first and then claiming parity with a
   Rust method that has none. That inverts the authority order.
2. **Light does not offer one.** There is no subscription anywhere in
   `js/stateless.js/src`, and Light has had a production indexer for longer than
   this project has existed. Where Light needs to wait, it polls:
   `confirmTx` runs a `setInterval` against `getSignatureStatuses`, and
   `confirmTransactionIndexed` polls the indexer's slot. This port already has
   that shape in `pollUntil` and `waitForIndexer`.
3. **A subscription is a different kind of surface from a request**, and the
   difference costs. It needs a transport this package does not have, a
   WebSocket where every other call is `fetch`, plus reconnection, backfill
   across the gap a reconnect leaves, and a cancellation contract. None of that
   is expressible as `RequestContext`, which is the abort mechanism every other
   method takes. `@zolana/client` is browser-targeted, so it would also need a
   second implementation or a polyfill boundary.

If a subscription is wanted, the honest route is to specify it against the
indexer and implement it in both languages together, not to port a Rust stub.

## 6. Findings for other rows

**`confirmTransaction` sends a different request than Rust does.** Rust's
`confirm_transaction` sends `getSignatureStatuses` with no config, so it reads
only the recent status cache; the port sends `searchTransactionHistory: true`.
A signature that has aged out of the cache therefore reads as unconfirmed in
Rust and confirmed here. The two agree on anything recent enough to be worth
confirming, which is why no existing test caught it. Recorded in the fixture and
pinned by a test that fails if either side moves. This belongs to whichever row
owns `confirmTransaction`, not to C03.

**The legacy message compiler exists twice.** `client/src/client.ts` has
`compileLegacyTransaction` and `wallet/src/internal.ts` has `compileTransaction`.
They were checked against each other rather than assumed: both apply
`checkedTransactionSize`, both order accounts the same way, and neither carries
a fix the other lacks. So this is duplication rather than the divergence class
[`remaining-work.md`](../remaining-work.md#working-rules-that-cost-something-to-learn)
warns about. It is that class waiting to happen, though, and the next fix to
either needs applying to both.

**Five wallet call sites still inline the build-sign-send sequence**
(`wallet/src/submit.ts:44-70`, `:330-338`, `deposit.ts:153-175`,
`registry.ts:461`, `:493`). They can now call `createAndSendTransaction`, which
is the consolidation Light performs with `buildAndSignTx`/`sendAndConfirmTx`.
Not done here: it is another package's, it is behaviourally neutral, and
`@zolana/wallet` has had four commits from other branches tonight. One
substantive difference to carry across when it is done: only
`createAssociatedTokenAccount` currently checks for unfilled signature slots;
the helper gives every site that check.

## Verification

`npm run build && npm run check:static` clean. `npm run test:unit` passes at
1952 tests over 113 files, one skipped, up from 1951 before this branch. The new
suite is `client/test/vectors/solana-rpc-reads-oracle.test.ts`, ten cases.

`cargo build -p xtask --bin solana-rpc-reads` and
`cargo run -p xtask --bin solana-rpc-reads -- --check` both clean. `xtask` gained
a `solana-signature` dependency, which the workspace already pins.

Not run: `cargo test -p zolana-client`, for the reason
[`stragglers.md`](stragglers.md#verification) records: the prover-backed
cucumber targets hang looking for a `zolana` CLI binary. Nothing on this branch
changes Rust behaviour; the only Rust added is a generator binary.
