# Four owner rulings nobody was acting on

Branch `port/rulings3`, worktree `zolana-ts-rulings3`. Three commits, one per
ruling, plus the ledger entries. Every row transition below is proposed here
rather than written into [`review-checklist.md`](../review-checklist.md), which
has a single writer.

The dispatch numbered its fourth item "record all four in
`authority-rulings.md`", which leaves the fourth ruling unnamed. Read as the
`input_utxo_hashes` reshape, which the dispatch states as a ruling of its own
inside item 1 and which is a shape rather than a deleted check. Four sections
are in the ledger.

## 1. T23, deleting the checks only TypeScript had

**Commit** `52c118fc`.

Verified at HEAD before touching anything. All three claims held, at drifted
lines: the constructor check at `transact.ts:519`, `applyP256Signature` at
`:564-580`, `input_utxo_hashes` at `spp_proof_inputs.rs:162-178`. The fourth
claim, that a previous worker had already reshaped `publicAmounts()`, also held;
it returns Rust's three field encodings and raises Rust's two asset errors, and
I left it alone.

Three changes:

- The constructor no longer calls `checkShape()`. Rust's constructor validates
  nothing and `check_shape` is a method the caller invokes.
- `signP256(keypair)` is new and carries Rust's rule, that the keypair's own
  curve is P256. `applyP256Signature(signature)` keeps only the length check
  that assigning Rust's public `p256_signature` field gets for free from the
  type system. The input-ownership check is gone, and with it
  `TRANSACTION_SIGNATURE_OWNER_MISMATCH`, which has no other producer.
- `inputUtxoHashes()` returns `InputUtxoContext[]`, Rust's type.
  `inputContexts()` is deleted; its four call sites in `client` now call
  `inputUtxoHashes()`.

The out-of-field Poseidon refusal named in the ruling is not a divergence.
`hashFields` in `internal.ts` screens against the modulus before calling the
hasher, but the WebAssembly hasher rejects the same inputs on its own, as
`light_poseidon` does under Rust. The screen decides which error surfaces, not
whether one does. No change; recorded in the ledger so the next reader does not
go looking.

**Tests changed, and why.** One case in `transaction/test/transfer.test.ts`
asserted the TypeScript-only behaviour, twice: a P256 signature by a key owning
none of the inputs, and one over inputs that are all Ed25519-owned, both
expecting `TRANSACTION_SIGNATURE_OWNER_MISMATCH`. It was not deleted. Both
assertions are inverted to Rust's behaviour, that the signature is taken, and
the rejection the case still proves is `signP256` called with an Ed25519
keypair. A new case constructs an unsupported shape, reads its message hash,
then calls `checkShape()` explicitly to get the rejection, which is what a Rust
caller can do and TypeScript could not; it also pins that `inputUtxoHashes()`
returns contexts indexed against the real inputs.

`rust-oracle.test.ts` drops the deleted error code from its expected list.

**Control edits, one per deleted check.** Re-adding the constructor
`checkShape()` fails the new shape case. Re-adding the input-ownership check in
`applyP256Signature` fails the accepted-signature case. Removing the curve check
from `signP256` fails the rejection case. Each was reverted after the failure.

**Row transition.** T23: adverse to closed, on the four `SppProofInputs`
divergences named in `transaction-independent-read.md`. The out-of-field
Poseidon residual the row records is closed as not-a-divergence.

## 2. `decrypt_transactions` named two different behaviours

**Commit** `cdedac39`.

Verified at HEAD: TypeScript's `decryptTransactions` mutated a caller-supplied
wallet and returned a `SyncReport`, Rust's `decrypt_transactions` builds a fresh
wallet and returns balances, and Rust's `Wallet::sync` and `sync_with_material`
had no TypeScript counterpart under any name.

- `syncWalletWithAuthority` is the old function renamed: it reads the
  authority's material once, then scans. Rust's `Wallet::sync`.
- `syncWalletWithMaterial` is new and takes material already in hand. Rust's
  `Wallet::sync_with_material`. It is the body both share; the async one now
  awaits the material and calls it.
- `decryptTransactions` is the port of Rust's free function: fresh wallet from
  the authority's identity, sync, return the balances, keep nothing.

Both scan functions are qualified rather than plain `syncWallet` because
`@zolana/wallet` already exports Rust's own `sync_wallet` under that name.

**Tests changed, and why.** No test asserted the wrong behaviour, so nothing
had to be corrected; three files follow the rename
(`wallet-sync.test.ts`, `wallet-viewing-key-history.test.ts`,
`zone-resolution.test.ts`) and `wallet/src/sync.ts` follows it at two call
sites. `module-surface.test.ts` is the exception and is the correction the
dispatch asked for: it listed `decrypt_transactions -> decryptTransactions`
under `RENAMES`, which certified the mismatch as intended. That entry is gone,
`decryptTransactions` now maps to Rust's function of the same name, and the two
scan functions are declared TypeScript-only.

New case in `wallet-sync.test.ts`: `decryptTransactions` reports
`decryptTransactionsBalance` from `wallet-sync-v1.json` and leaves the caller's
own wallet empty. That fixture field is Rust-generated and had no TypeScript
consumer before this commit, which is its own evidence the port was missing.

**Control edit.** Syncing an empty transaction list inside `decryptTransactions`
fails the new case on the balance.

**Row transition.** No row records this pair; it was found by the independent
read on `port/tx-close` and recorded in `transaction-independent-read.md`. If a
row is opened for it, it closes here.

## 3. T16, counterparty order during sync

**Commit** `666b48c2`.

**What Light Protocol does: nothing, because the question cannot arise there.**
Checked `js/stateless.js/src` at `b7936408b`. It has no shielded wallet sync at
all: no view tag, no counterparty scan, no decryption pass. Light's compressed
accounts are public state the RPC indexes by owner, so there is no set of
counterparty streams to walk and no order to choose. Their Rust SDK has no
parallel sync either; `rayon` appears only transitively in a lockfile.

Where Light does meet an ordering question it answers it the way this ruling
does. `rpc.ts:233`, `:1042` and `:1179` sort returned account pages by leaf
index rather than trusting arrival order, and their test RPC does the same. The
principle transfers even though the code does not: sort explicitly, do not
inherit an order from a container.

So the fallback applies. `CounterpartyCounters` now walks its counterparties in
pubkey-byte order, matching Rust's parallel sync
(`parallel.rs:242-243` and `:268-269`), and the counters it persists come back
in the same order. Rust's serial sync walks a `HashMap` (`sync.rs:868` and
`:893`) and so orders the decoded UTXOs by hash seed; between an order that is
stated and an order that is an artifact, a port can only be held to the stated
one.

**No oracle pins the undefined order**, which the dispatch asked me to check
either way. `counter_rows` in `xtask/src/ts_fixtures_transaction.rs:1927-1933`
sorts before emitting and says in its own comment that it does so because Rust
holds these in a hash map and the fixture has to be byte-reproducible. The sync
fixtures record `utxoCount`, `historyCount` and balances, never an ordered UTXO
list. The TypeScript test that compares counter rows sorts both sides before
comparing.

**Test.** New case in `wallet-viewing-key-history.test.ts`. Two counterparties,
generated and then labelled by which sorts first, each send the wallet a note on
the request stream and a second note on their shared stream. The request notes
fix discovery order as the reverse of sort order; the assertion is that the
shared-stream notes land sorted.

**Control edit.** Dropping the sort makes the walk follow discovery order and
the case fails on exactly the two amounts that swap.

**Row transition.** T16: closed, if a reconciler has not already closed it. This
is written here rather than into the checklist as instructed.

## For the Rust side

Two observations, neither actionable from this branch.

`xtask/src/ts_fixtures_transaction.rs:1330` asserts
`sequential.utxos == parallel.utxos`. That holds today only because the fixture
scenario is two proofless deposits with no counterparty shared streams. A
scenario with two counterparties that both hit would make the generator itself
flaky between runs, and the serial `HashMap` walk is the reason. Sorting the
serial walk in `sync.rs:868` would settle both that and the divergence T16
records, and would make Rust's two sync paths agree by construction rather than
by scenario.

`decrypt_transactions` carries a TODO saying it should move onto `Wallet`.
Ported as Rust stands. When Rust moves it, the TypeScript follows and the
qualified `syncWalletWith*` names can be revisited.

## What the rulings conflicted with

Only one thing, and it resolved. The obvious name for the renamed scan function
was `syncWallet`, and `@zolana/wallet` already exports a `syncWallet` that is
Rust's `sync_wallet` — a different function that fetches from the indexer before
scanning. Taking the plain name would have traded a collision inside one package
for a collision across two. Hence `syncWalletWithAuthority` and
`syncWalletWithMaterial`, which also read as the pair Rust has.

Worth stating plainly about T23, since it runs against this port's usual
direction: the ruling makes the SDK catch less. Every deleted check refused
something real. What none of them did was refuse it in Rust too, and a rule only
one language enforces is the rule a developer hits while porting working code.
Those failures now land at the prover, which cannot satisfy an unsupported
shape, or on chain, where a proof signed by a key the circuit does not bind does
not verify.

## Verification

From `sdk-libs/ts`, after `npm run build`: `npm run test:unit` (2035 passed, 1
skipped), `npm run check:static`, `npm run typecheck`. The Rust oracle was not
regenerated: nothing changed that it covers, and the one fixture field this
branch newly consumes, `decryptTransactionsBalance`, already existed.
