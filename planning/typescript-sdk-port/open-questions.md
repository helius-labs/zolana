# Open questions, and what Light Protocol does about each

Twenty-six questions this port has left undecided, collected in one place for
the first time, each with what Light Protocol does about it and a citation you
can check. Built 2026-07-26 on branch `port/open-questions` from `f4f4ee71`, by
reading the 34 files under `row-updates/`, the four register documents, and the
two ledgers, then reading Light at `b7936408b`.

Eleven need the owner and nothing else will move them; they are Part 1, and they
are the list that decides when this port finishes. Fifteen were answerable from
Light's source; five of those are implemented on this branch and the rest are
recorded with the smallest change that would settle them.

All eleven of Part 1 are now ruled, along with six from Parts 2 and 3, on
2026-07-25 and 2026-07-26. Each question's status line names its ruling and
links to the entry in [`authority-rulings.md`](authority-rulings.md) that
carries the evidence and the reasoning. The question text above each status line
is left as it was written, so a reader can see what the ruling was made against.

## How each answer is classified

The owner's instruction was to find what Light does and adopt it rather than
reason from first principles. Three things can happen when you go looking, and
each entry says which.

**Light answers it.** Their approach is adopted and, where the SDK can hold it,
implemented.

**Light solves it differently, because their architecture differs.** The entry
names the architectural difference and says whether it carries over. The
lookup-table study in [`versioned-transactions.md`](versioned-transactions.md)
is the model: Light names a tree and a queue per input so its account list
grows with input count, Zolana loads one tree at any shape, so Light's reason
to move to v0 is not Zolana's reason.

**Light never meets the problem.** Said plainly, with the search that shows the
absence rather than an assertion of it, and then the recommendation already
written in the row update is taken.

One rule constrains all three, and it caught two candidate fixes here: a change
that makes TypeScript refuse input Rust accepts is a new divergence, not a
closed question. Where Light's answer would require that, the entry says so and
stops.

---

# Part 1: the owner's list

Eleven questions. No amount of SDK work moves any of them. All eleven are ruled;
question 10 is ruled in part, and its status line says which part.

## 1. Owner-hash encoding includes y-parity in the specification and omits it everywhere else (G7-1)

`docs/spec.md:265-283` defines one `pk_field` carrying a `y_is_odd` layer and
puts it inside `owner_hash`; the circuit, the program, both Rust SDK crates and
both TypeScript packages use a parity-free form for owner identity and reserve
the parity-inclusive form for viewing keys, so nine implementations agree with
each other and disagree with the document
([`authority-rulings.md`](authority-rulings.md#open-owner-hash-encoding-g7-1)
lists all nine).

**Light:** never meets it. Light publishes no protocol specification that an
implementation could contradict: the repository root holds `README.md`,
`DOCS.md`, `INSTALL.md`, `SECURITY.md`, `CLAUDE.md` and `light-paper.md`, and
the paper is a design argument rather than a wire and hashing contract. The
Rust structs are the schema, and Photon and the SDK both read them, so there is
no third artifact to fall out of step. Zolana has a real specification, which is
worth more than Light's arrangement and is also why Zolana has this class of
question at all.

**Ruled** 2026-07-26: Option 1. Amend the specification to match the
implementations, and restate the collision argument at line 278 on the
parity-free form rather than delete it. No code moves and no key rotates.
[Ledger](authority-rulings.md#ruled-owner-hash-encoding-g7-1).

## 2. The specification states the confidential owner tag two ways that contradict each other (T23)

`docs/spec.md:884`, `:944` and `:959` all state a zero sentinel for a P256-owned
input while the confidential circuit branch constrains that input to carry
`p256SigningPkField` (`prover/server/circuits/spp_transaction/inputs.go:89-99`),
and the four implementations agree with the circuit.

**Light:** never meets it, for the reason in question 1, and additionally has one
ownership rail where Zolana has two.

**Ruled** 2026-07-26: amend the specification to the variant split, the zero
sentinel for the anonymous and zone-authority rails and the equality form for
the confidential one. Landed in `25b13fa2`; no verifying key was regenerated.
[Ledger](authority-rulings.md#ruled-confidential-owner-tag-t23).

## 3. The response context field is `slot` in the specification and `block_time` in all three implementations (C04, first half)

`docs/spec.md:1772-1786` declares `Context { slot: u64 }`; `sdk-libs/indexer-api`,
`sdk-libs/client` and the TypeScript port all declare a signed 64-bit
`block_time`, and Photon fills it from the maximum indexed block time.

**Light:** never meets it, same reason. Its `Rpc` has `getIndexerSlot`
(`js/stateless.js/src/rpc.ts:1692-1700`) as a plain method rather than a field on
a response wrapper, so there is nothing to disagree about.

**Ruled** 2026-07-26: amend the specification to `block_time: i64`, matching the
three implementations. The second half of C04, the integer domain, is question 12
and is settled. [Ledger](authority-rulings.md#ruled-the-u64-integer-domain-c04).

## 4. Three artifacts define the indexer schema and two of them are outside the SDK (X01)

`docs/spec.md` defines context, UTXO, transaction and output schemas that differ
from the ones Rust and Photon implement, and the SDK cannot align with all three;
`get_nullifier_queue_elements` compounds it by existing in Rust, in the port and
in Photon and appearing nowhere in the specification.

**Light:** never meets it, and the reason is structural rather than accidental.
Photon and the SDK read the same Rust structs, which is exactly Zolana's
arrangement minus the third document. So Light's arrangement is the state Zolana
reaches by amending the specification, not by changing code.

**Ruled** 2026-07-26: where Rust, the port and Photon already agree, that
agreement is authoritative and the specification is the stale artifact. The port
is correct as it stands, and `get_nullifier_queue_elements` needs a specification
entry rather than removal. Two smaller residues on this row were fixed by the
interface batch and are closed.
[Ledger](authority-rulings.md#ruled-indexer-api-schema-authority-x01).

## 5. A zone authority can move value out of a zone in the program and cannot in the specification

`docs/spec.md` states that value cannot leave a zone through a zone-authority
transition, while the program settles a zone-authority public leg through the
same path as an ordinary `transact` and the protocol's own builder carries a
`withdrawal` field for it
([`row-updates/rejection-validation.md`](row-updates/rejection-validation.md)).
The SDK guard that refused both directions has been removed, so the port now
matches the program.

**Light:** never meets it. Zones have no Light analogue, which
[`light-protocol-comparison.md`](light-protocol-comparison.md) already records
under differences rooted in the protocols.

**Ruled** 2026-07-26: amend the specification to match the program, on the same
principle as G7-1 and X01. No SDK code moves; the guard is already gone. The
`program-tests` scenario submitting a negative `public_sol_amount` with a real
proof is still worth having, as confirmation rather than as a precondition.
[Ledger](authority-rulings.md#q5-a-zone-authority-moving-value-out-of-a-zone).

## 6. The frozen-source gate fails on Rust SDK fixes that cannot change a fixture

`npm run fixtures:check` fails when any file under twelve canonical paths differs
from `BASELINE_SHA`, and those paths include `sdk-libs/keypair/src`,
`sdk-libs/transaction/src` and `sdk-libs/client/src/prover`, so every row closed
by fixing Rust reddens the gate; K12 already did, and the C08 ruling directs the
next worker at another frozen path.

**Light:** never meets it, and this was checked as a negative rather than assumed.
`BASELINE_SHA`, `frozen_sources` and `assert_frozen` return nothing anywhere in
that repository. Light does export test data from Rust, through
`xtask/src/export_photon_test_data.rs`, and pins nothing about the source files
that produced it. The mature lineage's answer to this class of drift is not a
source hash, which argues for narrowing the frozen set to files whose bytes feed
a fixture rather than scheduling work around the gate.

**Ruled** 2026-07-26: drop the source-hash gate entirely, as Light does. This
went further than the recommendation above, which was to narrow the frozen set.
The change is `assert_frozen_sources` and its constants in
`xtask/src/bin/ts-fixtures.rs`, which is outside the scope rule. Fixture drift is
then caught only by the fixtures' own regenerate-and-compare run.
[Ledger](authority-rulings.md#q6-the-frozen-source-gate).

## 7. Whether to take `@solana/kit`, and with it versioned transactions

Zolana depends on no Solana library and hand-writes the message compiler, the
wire serializer and the JSON-RPC client, which costs it address lookup tables,
`VersionedTransaction`, and interoperation with any wallet that speaks web3.js
types; kit was measured at 51.5 kB and passes the browser gate, and the real cost
is the boundary type.

**Light:** solves it differently, and the difference has been checked twice and
does not carry over. Light builds v0 messages and always has: `compileToV0Message`
first appears in `js/stateless.js/src` at `a6e67a04e` (2024-03-12) and
`new Transaction()` appears at no point in that directory's history, so there is
no migration and no recorded trigger. Its lookup tables are an append-only
address registry read by `getAllStateTreeInfos`
(`js/stateless.js/src/utils/get-state-tree-infos.ts:144-200`), never passed to
`compileToV0Message`, so they buy no size. And its kit dependency is an interop
shim: `js/token-interface/src/instructions/_plan.ts:1-24` builds legacy web3.js
instructions and converts them at the boundary, compiling no transactions with
kit and keeping web3.js as a peer dependency. "Light adopted kit, so should we"
is not an argument its code supports.

**Ruled** 2026-07-26: stay on legacy messages, and revisit when a second pool
tree ships. The signing path does not move either way, a v0 message being still
bytes, which is what makes the deferral cheap.
[Ledger](authority-rulings.md#q7-solanakit-and-versioned-transactions).

## 8. Whether the ciphertext format change is scheduled

Three of the ten supported shapes compile to transfers past the 1232-byte limit
today and a fourth joins them as a withdrawal; the already-specified ciphertext
format brings nine of the ten under the limit, and the recommendation against v0
rests on that change arriving.

**Light:** never meets it. Light's compressed accounts are public, so it has no
ciphertext in a transaction at all.

**Ruled** 2026-07-26: not scheduled, so plan as though it is not coming. The
conditional above fires and narrowing `SPP_SUPPORTED_SHAPES` is necessary work.
Question 7's answer no longer rests on this change arriving; it rests on the size
measurement. [Ledger](authority-rulings.md#q8-the-ciphertext-format-change).

## 9. Whether a second pool tree is planned, and when

The account arithmetic that makes versioned transactions unnecessary rests on
`TransactAccounts` loading exactly one tree
(`programs/shielded-pool/src/instructions/transact/account.rs:24-27`), and the
moment a spend can name two, a transfer acquires the shape of the problem Light
solved.

**Light:** solves it differently and this is the one place the difference cuts
toward Zolana later rather than now. Light's account list grows with input count
because it names a tree and a queue per input; Zolana's `InputUtxo` carries a
`tree_index: u8`, so five inputs add 38 bytes and no accounts.

**Ruled** 2026-07-26: no plan currently, so proceed on the one-tree assumption
and write it as an assumption with a named dependency rather than as a fact.
Question 7's answer rests on it. [Ledger](authority-rulings.md#q9-a-second-pool-tree).

## 10. Two Rust changes that must be ruled on before either language can move

T28's zone binding rules and S01's 1232-byte guard are separate rows and the same
shape of problem: the correct fix starts in Rust, and implementing it in
TypeScript alone would refuse input Rust accepts.

For T28, neither language validates the zone hash or the zone address at
construction, so they agree today; the three-clause rule in
[`row-updates/transaction-b.md`](row-updates/transaction-b.md) would refuse a
zero `zone_program_id`, refuse an explicit all-zero zone data hash, and refuse a
zone data hash at or above the BN254 modulus.

For S01, TypeScript enforces the 1232-byte instruction-data cap and Rust does
not, and adding it to Rust needs a fallible builder signature that moves
`xtask`, `forester` and four `sdk-tests` crates.

**Light:** splits on the clause. It answers the third T28 clause and declines the
first two, which is worth separating because the previous write-up treated them
together.

On the third clause, Light enforces the field range at the boundary where a
value arrives from outside: `BN254FromString` routes every base58 hash from the
indexer through `createBN254` (`js/stateless.js/src/rpc-interface.ts:296-299`),
and `enforceSize` throws at or above the field modulus
(`js/stateless.js/src/state/BN254.ts:35-40`). This corrects finding F8 in
[`light-protocol-comparison.md`](light-protocol-comparison.md), which reports
that nothing routes values through `createBN254`; one path does, and it is the
indexer decode path.

On the first two clauses, Light's practice is the opposite and the evidence is
already collected in
[`row-updates/merge-prefix.md`](row-updates/merge-prefix.md): where the program
enforces a caller-supplied byte, Light neither writes nor checks it, across four
independent decoders plus a clean negative.

For S01 there is a partial answer, in question 13.

**Partly ruled** 2026-07-26: an explicitly-passed zero at a zone binding is
normalized to absent rather than refused, which reshapes T28's first two clauses
and goes against the recommendation for the first. T28's third clause and S01 are
untouched; the third clause is safe on its own, relabels a deferred Poseidon
failure rather than refusing anything new, and could be taken alone in both
languages.
[Ledger](authority-rulings.md#q10-an-explicitly-passed-zero-at-a-zone-binding-t28).

## 11. Two program defects that need their own pull requests

PD-1, a padding dummy input's public nullifier column is unconstrained in the
circuit and the program inserts it anyway, so a chosen padding nullifier can
wedge the queue and freeze balances pool-wide. PD-2, `merge_transact` does not
bind its `user_record` to the owner whose UTXOs are merged.

**Light:** not applicable. These are Zolana circuit and program defects with
executed reproductions, and no SDK change reaches either.

**Ruled** 2026-07-26: each gets its own pull request against the program, tracked
outside this port, and neither blocks the port from landing. PD-2 has its branch
and PR #160, which is open rather than merged and whose commit is not an ancestor
of `main`. PD-1 has no branch. Both are outside `sdk-libs/**` by construction.
[Ledger](authority-rulings.md#q11-the-two-program-defects).

---

# Part 2: settled from Light's source, and implemented here

Five questions. Each fix is pinned by a test watched failing first.

## 12. Whether TypeScript should refuse indexer integers above the safe-integer bound (C04, second half)

Photon serializes `u64` and `i64` as bare JSON numbers, and the TypeScript
decoder refused any number outside the double-precision safe range
(`codec.ts:68-82`), so the port rejected a payload the Rust client accepts. The
specification is silent on the JSON encoding, so this could not be settled as a
conformance question, and four options had been recorded with no way to choose.

**Light answers it**, and it answers both halves, because Light meets this exact
problem with the same wire format.

At the transport, before parsing, it rewrites out-of-range numeric literals into
quoted strings so the digits survive `JSON.parse`
(`js/stateless.js/src/rpc.ts:291-302`, applied at `:346`). At the decoder,
`BNFromStringOrNumber` accepts a string and parses it base 10 unbounded, accepts
a number only when `Number.isSafeInteger` holds, and throws
`Unsafe integer. Precision loss` otherwise
(`js/stateless.js/src/rpc-interface.ts:316-328`). So the recorded option I2, a
lossless parse, is Light's answer, and option I4's rejection is kept as the
backstop for a body that reached the decoder another way.

**Implemented**, commit `876c5bf5`. `quoteUnsafeIntegers` runs before
`JSON.parse` in `@zolana/api`, and `wireInteger` in `@zolana/indexer-api` accepts
a canonical decimal string. This closes a divergence rather than opening one:
TypeScript now reads the domain Rust's serde reads.

Two defects in Light's implementation were not copied, and this was measured
rather than assumed. Light's rewrite is the regex `/(":\s*)(-?\d+)(\s*[},])/g`,
which requires a key and a colon immediately before the number, so
`{"seqs":[1152921504606846976,1]}` passes through unquoted and still loses
precision; and a string whose content contains `": ` followed by digits and a
comma is rewritten inside the quotes, turning `{"memo":"x\": 1152921504606846976,"}`
into text `JSON.parse` rejects. Both were reproduced against the exact regex. The
version here is a scanner that skips string literals, so it quotes array elements
and leaves string contents alone; the same six inputs were run against it.

Pinned by `reads a u64 above the safe-integer bound without losing precision`,
`does not rewrite a digit run inside a string payload` and
`leaves a safe integer, a quoted string, and a fractional number as they were
sent` in `api/test/transport.test.ts`, and by three cases in
`indexer-api/test/schema.test.ts` covering the string form, its non-canonical
rejections, and a number that had already lost precision.

## 13. Whether the transaction compiler should check the 1232-byte limit

Nothing in the SDK compares a compiled message against 1232, three of the ten
supported shapes exceed it, and the study that measured them recommended adding
a check without settling what the check should do to a caller.

**Light answers it**, and the shape of its answer is the part that matters,
because a hard refusal in Zolana's compiler would be the stricter-than-Rust
regression this project has reverted twice.

Light separates the two. Measurement is public: `MAX_TRANSACTION_SIZE` and
`estimateTransactionSize` are exported from the package root
(`js/compressed-token/src/index.ts:34-38`,
`js/compressed-token/src/v3/utils/estimate-tx-size.ts:4`, `:63`). The refusal is
`@internal` and reaches only the batches Light assembles itself, across four
modules: `v3/instructions/transfer-interface.ts:275`, `v3/instructions/unwrap.ts:276`,
`v3/instructions/approve-interface.ts:120` and `v3/actions/transfer-interface.ts:219`.
Its message names the reason it is allowed to be fatal: "This indicates a bug in
batch assembly."

The negative is clean and was checked. `buildTx` and `buildAndSignTx`, which
compile whatever instruction list a caller hands them, have no size check at all;
the only throw in either is about a duplicated signer
(`js/stateless.js/src/utils/send-and-confirm.ts:26-39`, `:123-144`).

Zolana's `compileLegacyTransaction` is the `buildTx` role, not the batch-assembly
role: an oversized transaction there is the caller's proof shape rather than a bug
in code Zolana wrote. So Light's answer, applied honestly, is measurement without
refusal.

**Implemented**, commit `0e26c397`. `MAX_TRANSACTION_SIZE` and `transactionSize`
are exported from `@zolana/client`. Zolana can measure exactly where Light
estimates, because it owns its serializer.

Pinned by five cases comparing `transactionSize` against the bytes `SolanaRpc`
actually submits, including 128 signatures where the compact-u16 count grows a
byte and a measurement assuming one byte would agree below and disagree above,
and by a sixth asserting that an oversized transaction is still submitted, which
fails if anyone later turns the measurement into a guard.

## 14. Five copies of `compactU16` and three hand-written message compilers

`compactU16` exists five times and the legacy message compiler three, and the
README already records what happened the last time duplicated arithmetic drifted.

**Light answers it**: it writes the encoder zero times. Searching its TypeScript
for `compactU16`, `encodeLength` and `shortvec` returns one function,
`compactU16Size` (`js/compressed-token/src/v3/utils/estimate-tx-size.ts:40-44`),
and that one counts bytes rather than emitting them. The emitting encoder is
never in Light's source; it arrives inside the web3.js serializer that
`compileToV0Message` feeds. So the only compact-u16 arithmetic Light hand-writes
is the one thing its dependency cannot do for it. Its whole transaction builder
is thirteen lines (`js/stateless.js/src/utils/send-and-confirm.ts:26-39`).

Zolana cannot take the dependency without settling question 7, but the count is
not a consequence of that: nothing required the same arithmetic to be written
five times inside one repository.

**Partly implemented**, commit `0e26c397`. The two copies finding F1 names by
line, `client/src/client.ts:735` and `client/src/solana-rpc.ts:627`, were
character-identical apart from one variable name and now read one function in
`client/src/wire.ts`.

**Not implemented:** the copies in `wallet/src/internal.ts:105` and
`test-kit/src/user-registry.ts:390`, and the three compilers. Collapsing those
means a shared home in `@zolana/interface`, which is the leaf both depend on, and
that adds to a published surface pinned by three allowlists. The smallest change
that settles it is two exports from `@zolana/interface` and their allowlist
entries; the cost is a permanent widening of the package that a program author or
an explorer takes for the codecs alone. Worth doing with question 22, since
merging the two packages moves the same surface.

## 15. Whether an SDK codec should enforce a byte the program enforces (I08, I09, I20, I21)

TypeScript refused a merge payload whose `encrypted_utxo` first byte was not `2`,
which the Rust decoder reads, because the prefix is not part of the serialized
layout and the shielded-pool program is what rejects it.

**Light answered it** before this pass, and the work is recorded in
[`row-updates/merge-prefix.md`](row-updates/merge-prefix.md) to the standard the
rest of this register tries to meet: four independent decoders that slice past a
program-enforced discriminator without comparing it, an indexer decoder that
validates nothing across 74 lines, a caller-supplied `mode` byte the program
constrains and Light neither writes nor checks, and a clean negative across two
whole directories. Both guards were removed and the answer was symmetric.

**Implemented** before this branch. Confirmed still in place here: the guards are
absent from `interface/src/codecs/index.ts`, and
`reads and rebuilds the non-canonical merge prefix Rust reads` pins both
directions.

Recorded because the register should be complete, and because the rule it
establishes is narrower than it looks. A codec follows the language it ports:
where Rust validates a discriminator, TypeScript does too, and
`transaction/src/serialization/codecs.ts` still raises
`TRANSACTION_BAD_DISCRIMINATOR` on both sides.

## 16. Whether the zone-authority prover should accept shapes it has no key for

`ZoneAuthorityProver::build` resolves against ten `SPP_SUPPORTED_SHAPES` while
four zone-authority verifying keys exist, so both SDKs will build a 2x3 request
the prover cannot serve and the caller learns at proving time.

**Light does not answer it, and this is the one entry where Light loses to a
higher authority.** `proverRequest` selects among three `circuitType` strings and
validates no shape at all before sending
(`js/stateless.js/src/rpc.ts:356-410`); nothing in `rpc.ts` refuses a request the
prover has no key for. Copying that would leave the defect in place.

The standing rule says Light outranks a reviewer's preference and does not
outrank the authority order, and here the specification decides:
`docs/spec.md`'s zone-authority section lists exactly four supported shapes, the
four square ones, and the keys on disk match it. So the SDKs are the diverging
side and narrowing them is conformance, not the port tightening past its
original.

**Not implemented here**, deliberately. The row update
[`row-updates/zone-authority-shape-narrowing.md`](row-updates/zone-authority-shape-narrowing.md)
assigns this to the client batch behind C08 and T23, it needs the matching change
in the Rust crate to avoid becoming a divergence, and both files are owned by a
worker running now. The smallest change is a four-element accepted set on each
side with a named error stating which shapes the rail supports, plus a shared
vector; the cost is breaking a caller passing a non-square shape, which the
standing pre-1.0 ruling permits.

---

# Part 3: settled from Light's source, waiting on something outside the SDK

Ten questions where Light's answer is established and adopting it needs a change
this branch cannot make.

## 17. Whether `ViewingKeyLike` should reach the call sites, given that it makes them async (K11)

`ViewingKeyLike` declares all fourteen operations and is proved satisfiable by an
async backend, but `transaction/src/wallet/sync.ts`,
`transaction/src/serialization/codecs.ts` and `wallet/src/sync.ts` still bind the
concrete `ViewingKey`, so no consumer can pass a backend even though one
typechecks; accepting it makes each call site `async`, because every method
returns `T | Promise<T>`.

**Light answers it, and the answer is to split by kind rather than decide once.**
Its capability interface for the compiled backend is synchronous:
`LightWasm` declares `blakeHash`, `poseidonHash`, `poseidonHashString` and
`poseidonHashBN`, all returning plain values
(`js/stateless.js/src/test-helpers/test-rpc/test-rpc.ts:70-75`), and it is passed
as an argument to the functions that need it rather than bound at module scope
(`test-rpc.ts:93`, `:146`, `js/stateless.js/src/rpc.ts:495`, `:524`). Signing is
the async one, and Light gets it from web3.js `Signer` rather than declaring its
own. So derivation stays synchronous and the propagating `async` never happens.

Applied here, that says `ViewingKeyLike` should return `T` rather than
`T | Promise<T>` for its derivation operations, which keeps the three call sites
synchronous and still admits a backend that holds key material in process.

**Not implemented.** Narrowing the return type is a change to a published
interface in `@zolana/keypair`, owned by the hashers batch, and it removes the
one capability the interface was added for: an HSM that answers over a wire
cannot satisfy a synchronous signature. The smallest change that settles it is a
sentence from the owner about whether an out-of-process viewing-key backend is a
supported deployment. If it is, the call sites go async and Light's arrangement
does not transfer; if it is not, the interface narrows and K11 closes without
touching them.

## 18. `ShieldedKeypair.fromEd25519` takes a different argument in each language

TypeScript's `fromEd25519(secret, account)` takes an account index where Rust's
`from_ed25519` takes a viewing key, so no TypeScript caller can pair a chosen
viewing key with a chosen signing secret.

**Light never meets it.** It has no shielded keypair, no viewing key and no
account-index derivation; ownership is a web3.js `Signer`.

**Not implemented.** The file is `sdk-libs/ts/keypair/`, owned by the hashers
batch, and fixing another batch's files mid-flight is how this project lost work
three times. The direction is not in doubt: Rust is the authority, so the
TypeScript signature widens. Cost is one overload and its allowlist entry.

## 19. Two Rust entry points disagree about waiting for the indexer

`sync_wallet` blocks waiting for the indexer and `sync_wallet_async` does not,
because one is built from `SyncWalletConfig::new()` and the other from
`::default()`, and no comment or document explains the split.

**Light answers it: always wait, one behaviour, no split.**
`confirmTransactionIndexed` polls `getIndexerSlot` until the indexer reaches the
transaction's slot or a timeout expires
(`js/stateless.js/src/rpc.ts:1671-1688`), and `confirmTx` calls it unconditionally
at the end of every confirmation (`send-and-confirm.ts:106-107`), so there is no
path through Light's SDK that returns before the indexer has caught up. The
timeout is 10 seconds against a local endpoint and 20 otherwise.

**Not implemented, and it should not be implemented from here.** The port
currently matches Rust and must keep matching Rust whichever way this goes;
changing TypeScript alone would create the divergence. Light's answer is evidence
that the blocking behaviour is the intended one and the `default()` construction
is the accident, which is what the owner needs to rule on. The generated fixture
already records both values.

## 20. The confirmation path cannot tell a rejected transaction from a dropped one (F2)

`confirmTransaction` returns `false` both for a transaction the runtime rejected
and for one that has not landed, so `#waitForSignature` keeps resubmitting and
reports `CLIENT_CONFIRMATION_TIMEOUT`, and `retryCause` classifies the decoded
program error as retryable.

**Light meets the problem and gets it wrong, so there is nothing to copy.** Its
confirmation never inspects `err`: `confirmTx` resolves as soon as
`confirmationStatus` matches the requested commitment
(`js/stateless.js/src/utils/send-and-confirm.ts:97-102`), so a transaction that
executed and failed returns a signature and `transfer()` reports success for a
transfer that did not happen. Zolana's behaviour is safe and merely uninformative;
Light's is unsafe. This is the one entry where the standing instruction to copy
Light would make the SDK worse, and it is recorded so nobody re-derives it.

**Not implemented.** The recommended path is written and is three local changes:
distinguish failed from not-yet, raise the program error instead of timing out,
and drop `CLIENT_RPC_PROGRAM_ERROR` from the retryable set. All three are in
`sdk-libs/ts/client/`, owned by the client batch and by a worker running now, and
the third is a deliberate divergence from Rust's `retry_cause` that should be
recorded as one rather than left to look like drift.

## 21. Whether `@zolana/interface` should carry the compiled Poseidon

`interface` pays the largest relative size cost of the five packages, 49.7x, for
two arity-2 calls, and standalone use of it for instruction building without any
cryptography is plausible.

**Light answers it: the package that builds instructions does not carry the
hasher.** `js/stateless.js` computes no Poseidon on any production path; the
`LightWasm` instance appears in `test-helpers` and is taken as a parameter by the
two `rpc.ts` functions that need it (`:495`, `:524`), and the consumer constructs
it once. So the hashing capability travels as an argument rather than as a
dependency of the layout code.

**Not implemented.** The
[`poseidon-wasm-and-packaging.md`](poseidon-wasm-and-packaging.md) ruling is
explicit that this must not be resolved inside its work packets, and equally
explicit that giving `interface` a hand-written copy is the one answer ruled out.
Light's answer points at the remaining option the ruling lists: remove
`interface`'s need to hash, by taking the two digests as arguments from the
caller that already has a hasher. The cost is two signature changes on a
published surface.

## 22. Whether `@zolana/api` and `@zolana/indexer-api` should be one package (F10)

They are the transport and the schema for the same server, both browser-safe,
each depending only on the other and on `@zolana/interface`, and nothing consumes
one without the other.

**Light answers it: one package.** `js/stateless.js` holds the RPC client, the
state types, the program layouts and the actions together, and Light ships three
published packages against Zolana's ten.

**Not implemented.** Merging them removes a package, a build step, a typecheck
step and six test configurations, and it touches two `exports` maps and every
cross-package import. It is also the natural moment to settle question 14, since
a shared home for the wire helpers is the same decision. This is safe work and
purely mechanical; it did not fit beside the behavioural changes on this branch.

Not everything in F10 falls the same way. Light puts `test-helpers` on its
published root surface, so a mock RPC and a TypeScript Merkle tree ship to every
production consumer; `@zolana/test-kit` as a separate package is the better call
and should stay.

## 23. Four base64 and base58 decoders that agree by coincidence

`@zolana/client`, `@zolana/indexer-api`, `@zolana/wallet` and `@zolana/interface`
each carry their own decoder, and `client/src/indexer.ts` imports `hashBytes`
from `@zolana/indexer-api` for hashes then uses its own local `decodeBase64` for
the payloads on the same six responses, so one response is validated by two
decoders that happen to agree character for character.

**Light answers it: one decoder, and it does not write it.** Light reaches for
`bs58.decode` and `Buffer.from(x, 'base64')` throughout, so the question of
keeping copies in step never arises.

**Not implemented.** `base64Bytes` now exists in `@zolana/indexer-api` and is the
inverse of `base64String`, so the end state is six imports in
`client/src/indexer.ts` and one deletion. `client` is owned by another row and by
a running worker, which is why the interface batch recorded it rather than doing
it. It is a one-line import now rather than a reimplementation.

## 24. The merkle-tree error codes have no mapping onto the Rust variants (M02 residual)

Eleven `MerkleTreeErrorCode` values face eight `ReferenceMerkleTreeError`
variants, and inventing a mapping would assert a correspondence nothing evidences.

**Light never meets it, and its own attempt is a warning rather than a model.**
`js/stateless.js/src/errors.ts` defines nine enums and nine `MetaError` subclasses
under a `// TODO: Clean up` on line 1, and not one of them is referenced anywhere
else in `js/src`; the real style is `throw new Error(...)`, twenty-three of them
in `rpc.ts` alone. So the mature lineage has no error taxonomy to copy, and
Zolana's is better in kind.

**Not implemented, and the recommendation is to close the row without a mapping.**
The row's behavioural half compares outcomes rather than error names, and it is
already satisfied by the replayed Rust traces. A mapping asserted without evidence
is worth less than the absence of one.

## 25. Rust classifies two malformed indexer bodies differently by accident

A 31-byte `output_slot` hash is decoded by the API layer and becomes a fatal
`ClientError::Indexer`, while a 32-byte `tx_viewing_pk` is length-checked in
`indexer.rs` and becomes a retryable `ClientError::Rpc`, so two malformed bodies
from the same response are classified by which layer happens to decode the field;
the port inherited the inconsistency by matching it.

**Light answers it: a malformed body is fatal, never retried.** Its RPC layer
validates through `superstruct` and throws on a structure mismatch, and neither
`rpcRequest` nor any caller in `rpc.ts` retries a parse failure; the only retry
loops in the SDK are the two that poll for a slot or a confirmation. So Light
never spends a retry schedule on a body that will not parse differently.

**Not implemented.** Making `fixed_bytes` and `decode_error` fatal in
`sdk-libs/client` would let TypeScript drop `CLIENT_INVALID_RPC_RESPONSE` from the
retryable set, which is the fix both languages want. It is a Rust semantics change
in the file PR #158 conflicts with, and the resolution order says current Rust
wins until someone rules otherwise. Cost is one enum arm and the paired tests that
already exist on both sides.

## 26. The npm scope, the publication owner, and the browser support matrix

The two repository-external choices the plan has carried from the start: which
scope to publish under and with whose registry access, and which browser versions
are supported.

**Light answers the shape of both, and the second answer is that it declines to
answer.** Its three packages publish under one organisation scope,
`@lightprotocol/stateless.js`, `@lightprotocol/compressed-token` and
`@lightprotocol/token-interface`, which is the arrangement `@zolana/*` already
assumes. Neither of the three declares `engines` or `browserslist`; this was
checked by reading all three manifests, not inferred from one. So a shipped SDK
with real users in this ecosystem publishes no browser matrix at all and lets the
consumer's bundler decide.

**Not implemented, and only half of it should be.** The scope default needs
registry access rather than a code change. On the matrix, Light's answer argues
for dropping the requirement rather than filling it in, but Zolana's browser gate
is a stronger property than Light holds and the packages already declare
`engines.node`, so publishing the Browserslist the gate implies is cheap and
keeps the claim honest. Recommend stating it and not gating on it.

---

## What was checked and found not to be an open question

Recorded so the next pass does not rediscover them.

The transaction account count. It was carried as a coming problem and it is not
one: a shielded transfer names three accounts at any supported shape against a
runtime ceiling of 128, and widening the proof shape consumes none of it.

The forester address-append builder. It reads as a coverage gap and it is a
correct omission, and Light landed in the same place for the same reason: it
decodes append, nullify and address-insert inputs so an indexer can read them,
and a search of `js/` for a matching builder returns nothing. The rule both
repositories arrive at is to decode any instruction that can appear in a
transaction and build only those whose inputs the SDK can produce for itself.

Whether the SDK falls behind Light on the prover client. It does not, and reading
it that way has cost time twice. Light's prover client is a fifty-line function
with no timeout, no retry, no job polling and no response cap
(`js/stateless.js/src/rpc.ts:356-410`).
