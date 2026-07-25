# PR #158 impact on the TypeScript SDK port

Read-only assessment of open PR #158, `feat(indexer): add shielded transaction
signature lookup` (branch `feat/photon-signature-lookup`, +990/-113), against
`ts-sdk-port` at `3ff5f26b`. No code, test, or fixture was changed.
`review-checklist.md` was read but not edited.

Everything under "Verified" was derived by reading the diff, the branch source,
or by running a read-only git command whose output is quoted. Everything under
"Inferred" is reasoning that was not mechanically checked.

## Bottom line

**#158 adds roughly one focused day of port work, not a re-plan.** The merge
conflict is one function; the new parity surface is one indexer method, three
wire types, two error variants, and one forced rename. Nothing in #158 touches
the protocol, the circuits, the tag derivation, or any fixture-frozen value.

**Recommendation: land #158 first, then port on top. Do not add the method to the
port in anticipation.**

The decisive fact is that both branches share the same parent. `git merge-base
ts-sdk-port origin/main` is `43fde8e4`, `origin/main`'s tip is `43fde8e4`, and
#158's `baseRefOid` is `43fde8e4`. #158 is five commits against a base that has
not moved. This branch is 206 commits against the same base, with 70 rows
`needs_fix`, 11 `needs_re_review`, and none verified. Asking #158 to rebase moves
a five-commit change over a 206-commit branch whose Rust client layer it directly
contradicts; the reverse moves a one-function conflict into a branch whose owners
already hold the context for that exact function.

The single risk in landing #158 first is that its `indexer_error` classifier is
the *worse* of the two designs on a point this port already spent three commits
fixing, and merging it naively would silently reintroduce the defect. That is an
argument for resolving the conflict deliberately, not for changing the order.

Cost, concretely:

| Work | Files | Rows |
| --- | --- | --- |
| Resolve the `indexer_error` conflict | `sdk-libs/client/src/indexer.rs` (1 hunk) | C04 |
| Reconcile the two retryability mechanisms | `indexer.rs`, `error.rs`, `retry.ts` | C01, C02, C04 |
| Rename the TS `IndexedShieldedTransaction` | 5 source files, 4 test files | C03, I-rows for `indexer-api` |
| Port the new method | `names.ts`, `types.ts`, `codec.ts`, `methods/index.ts`, `index.ts`, `api/src/index.ts`, `client/src/{indexer,rpc,index}.ts` | C03, C22, indexer-api rows |
| Rewrite `confirmPrivateTransaction` | `client/src/client.ts:471-520` | C21 |
| Two new error codes | `client/src/error.ts` | C02 |
| Regenerate three client fixtures | `errors-v1.json`, `lib.json`, `rpc-indexer-v1.json` | C01, C02, C22 |

## 1. Merge conflict surface

### Verified: exactly one textual conflict

`git merge-tree --write-tree HEAD refs/remotes/pr/158` (in-memory; the worktree
was not touched) reports:

```
Auto-merging sdk-libs/client/src/client.rs
Auto-merging sdk-libs/client/src/error.rs
Auto-merging sdk-libs/client/src/indexer.rs
CONFLICT (content): Merge conflict in sdk-libs/client/src/indexer.rs
Auto-merging sdk-libs/client/src/lib.rs
```

That is narrower than the file list suggests, because this branch never touches
three of the files #158 changes. Checking each baseline path against `43fde8e4`:

- `sdk-libs/indexer-api/src`: clean.
- `sdk-libs/zolana-api/src`: clean.
- `sdk-libs/client/src/rpc.rs`: clean.
- `services/photon/`: not modified on this branch.

Those four take #158's changes verbatim. This branch's Rust client work lives in
three commits, `3ba52785`, `6d757791`, and `30b58b9b`, and it is concentrated in
`error.rs` (+48/-24), `indexer.rs` (+269 net), and `retry.rs` (+170), which #158
does not touch at all.

### Verified: the one conflict is the semantic one

The conflict is lines 504-542 of the merged blob, and it is precisely the
collision the brief predicted. Both sides rewrote `indexer_error` from the same
one-line original, in incompatible directions:

This branch (`indexer.rs`, from `6d757791`) drops the API message entirely
because a response body can echo caller data, and returns a struct variant
carrying the method name and a retryable flag:

```rust
fn indexer_error(method: &'static str, error: zolana_api::ApiError) -> ClientError {
    let retryable = match error {
        zolana_api::ApiError::Request(error) => !error.is_decode() && !error.is_builder(),
        zolana_api::ApiError::Response { status, .. } => retryable_status(status.as_u16()),
        zolana_api::ApiError::JsonRpc { .. }
        | zolana_api::ApiError::InvalidRequest { .. }
        | zolana_api::ApiError::MissingResult(_) => false,
    };
    ClientError::Indexer { method, retryable }
}
```

#158 keeps the message (`let message = error.to_string()`) and encodes
retryability in the *choice of variant*, adding `IndexerUnavailable(String)` for
timeouts, connect failures, 429, 5xx, and JSON-RPC `-32603`, and mapping `-32601`
to `UnsupportedRpcMethod`.

These are not two spellings of one idea. They disagree on three separate points:

1. **Whether the API message reaches public error output.** C04 records that this
   branch stopped formatting `ApiError` into the message specifically so no
   response text escapes. #158 puts it back in both `Indexer(String)` and
   `IndexerUnavailable(String)`.
2. **Where retryability lives.** Branch: a `retryable: bool` field on one variant,
   read by `ClientError::retry_cause()`. #158: a separate variant, read by a new
   `should_retry()` override.
3. **Which failures are retryable.** #158 retries JSON-RPC `-32603` and a
   `-32601` becomes `UnsupportedRpcMethod`. This branch treats every `JsonRpc`,
   `InvalidRequest`, and `MissingResult` as fatal, and retries `408 | 425 | 429 |
   5xx`. #158 retries only `429 | 5xx`, so it drops `408` and `425`.

### Verified: three breakages that auto-merge hides

The three files git merged cleanly do not survive a compile, and the merged
`indexer.rs` outside the conflict region does not either.

**Merged `error.rs` carries both representations.** Line 190 has the branch's
`Indexer { method, retryable }`, line 196 has #158's `IndexerUnavailable(String)`,
line 207 has #158's `AmbiguousIndexedEvents`, and lines 216 and 221 keep the
branch's widening of `attempts` to `u64` in `IndexerNotCaughtUp` and
`PollTimedOut`. Git merged this because the two sides added text at different
offsets. The result is a type with two overlapping ways to say "the indexer is
temporarily unavailable" and one `retry_cause()` at line 242 that only understands
one of them.

**`should_retry` becomes a no-op against branch-produced errors.** #158 adds, at
merged lines 185 and 351:

```rust
fn should_retry(&self, error: &ClientError) -> bool {
    matches!(error, ClientError::IndexerUnavailable(_))
}
```

The base already declares `should_retry` on both traits with a `false` default
(`rpc.rs:258`, `rpc.rs:445`) and forwards it through `ZolanaClient`
(`client.rs:446`, `client.rs:660`), so #158 is overriding, not introducing. But
if the conflict is resolved in favour of this branch's `indexer_error`, nothing
ever constructs `IndexerUnavailable`, `should_retry` returns `false` for every
indexer failure, and the `Err(error) if indexer.should_retry(&error) => continue`
arms that #158 added to both `wait_for_indexed_transaction` bodies never fire.
The confirm path would then abandon the poll on the first transient failure. This
is the one merge outcome that compiles and is still wrong.

**#158's new indexer tests call the old signature.** Merged lines 1176-1207 hold
`classifies_transient_indexer_errors_for_retry` and
`classifies_non_transient_indexer_errors_without_retry`, which call
`indexer_error(zolana_api::ApiError::...)` with one argument and match
`ClientError::Indexer(_)` and `ClientError::IndexerUnavailable(_)`. Against this
branch's two-argument function and struct variant, all three fail to compile.
They sit outside the conflict markers, so a resolver who fixes only the marked
region will not see them.

*Inferred:* the clean resolution is to keep this branch's `indexer_error` shape
and fold #158's classification refinements into it. Add the `-32601` mapping to
`UnsupportedRpcMethod`, decide whether `-32603` should be retryable (it is a
genuine improvement; the branch currently treats all JSON-RPC as fatal), delete
`IndexerUnavailable`, and redefine `should_retry` as
`error.retry_cause().is_some()`. That keeps #158's behaviour, keeps the
message-redaction property C04 credits, and collapses the two mechanisms into
one. #158's two new tests then need rewriting against the struct variant.

### Verified: mechanical conflicts

Everything else on the Rust side is mechanical.

- `client.rs`: this branch changes one line, `fn fetch_spend_proofs` →
  `pub(crate) fn fetch_spend_proofs`. #158 changes the confirm path and the test
  module. Disjoint.
- `lib.rs`: this branch adds `RetryErrorCause` to the `pub use error::{..}` line;
  #158 adds two names to the `pub use rpc::{..}` block. Disjoint lines.
- `error.rs`: two additive hunks at different offsets. Textually mechanical; the
  semantic problem is described above.

## 2. New parity surface

### Verified: what #158 adds

**One JSON-RPC method.** `get_shielded_transactions_by_signature`, constant added
at `indexer-api/src/lib.rs:18`, method marker struct and `RpcMethod` impl at
`:39` and `:56`, registered in Photon at `rpc_server.rs` and `service.rs`.

**Three wire types** in `zolana-indexer-api`, all re-exported through
`zolana-api`:

- `GetShieldedTransactionsBySignatureRequest { tx_signature: SerializableSignature }`
- `IndexedShieldedTransaction { event_index: u16, transaction: ShieldedTransaction }`
- `GetShieldedTransactionsBySignatureResponse { context, transactions }`. Note
  the absent `next_cursor`: this endpoint does not paginate.

**Two client types** in `zolana-client::rpc`, mirroring those, plus two new trait
methods on `Rpc` and `AsyncRpc` with `unsupported(..)` defaults, plus the
`ZolanaClient` forwarders, plus the two names added to the crate root.

**Two error variants**: `IndexerUnavailable(String)` and
`AmbiguousIndexedEvents { signature: String, event_indices: Vec<u16> }`.

**One behaviour change to the confirm path.** `wait_for_indexed_transaction` and
its async twin stop calling `get_shielded_transactions_by_tags(tags, None,
Some(50), None)` and call the signature lookup instead, then run the result
through a new `select_indexed_transaction` that filters on signature *and* view
tag, returns `None` on no match, the single match when there is one, and
`AmbiguousIndexedEvents` when two or more events match.

**Photon `rings.yaml`**: a `/get_shielded_transactions_by_signature` path (+115
lines) and one component schema, `IndexedShieldedTransaction`, with `event_index`
as `integer / format: u-int16 / minimum: 0` and `transaction` as a `$ref` to the
existing `ShieldedTransaction`. No existing schema is modified.

### Verified: the port has none of it, and one name is already taken

The TypeScript `indexer-api` package already uses the name
`IndexedShieldedTransaction`, but for a *different type*. At
`indexer-api/src/types.ts:48` it is the port's name for Rust's
`ShieldedTransaction`, the flat record with `slot`, `txSignature`,
`outputSlots`, `messages`, `nullifiers`, `proofless`. It is a public export
(`indexer-api/src/index.ts:30`) and it is what `client/src/rpc.ts:11` imports and
what `EncryptedUtxoMatch.outputSlot` and
`GetShieldedTransactionsByTagsResponse.transactions` are typed against.

#158 introduces a Rust type with that exact name meaning the *wrapper*. Porting
#158 therefore forces the port to rename its existing type to
`ShieldedTransaction` before it can take #158's name, or to deliberately diverge
from Rust's naming on a public export. This is the largest single cost item and
it is pure mechanical churn: `types.ts:48,61`, `codec.ts:205,331,477`,
`index.ts:30`, `client/src/rpc.ts:11,34,47`, plus the four test files that name
the type.

*Inferred:* rename rather than diverge. The port's whole conformance argument
rests on name-for-name correspondence with Rust, and `client/lib.json` asserts
crate-root names literally.

### Cost per item

| Item | Where | Cost |
| --- | --- | --- |
| Method name constant | `indexer-api/src/names.ts` | 1 line |
| Request/response/wrapper types | `indexer-api/src/types.ts` | ~15 lines |
| Request + response codecs | `indexer-api/src/codec.ts` | ~40 lines; `checkedSignature` already exists (`codec.ts:25`), and the response reuses `indexedTransaction` at `:205` |
| Method descriptor | `indexer-api/src/methods/index.ts` | ~10 lines |
| Exports | `indexer-api/src/index.ts` | 4 lines |
| Rename of the existing type | 5 source + 4 test files | mechanical, wide |
| API client method | `api/src/index.ts`, following the `:88-93` pattern | ~8 lines |
| Indexer method | `client/src/indexer.ts`, following `:71` | ~25 lines |
| `Rpc` interface method | `client/src/rpc.ts:100-137` | ~6 lines |
| Two error codes + detail shapes + producer disposition | `client/src/error.ts:75-79`, `:160-176`, `:454-458` | ~20 lines, plus the C02 producer-disposition test |
| `selectIndexedTransaction` + confirm rewrite | `client/src/client.ts:471-520` | ~40 lines |
| Root exports | `client/src/index.ts` | 2 names |
| Test doubles | `e2e/support/doubles.ts` (4 sites today) | ~15 lines |

*Inferred:* the `rings.yaml` additions cost the port nothing directly. No
TypeScript source or test reads `rings.yaml`; the relationship is a manifest pin,
`photonSchemaRevision`, currently `43fde8e4`. The schema mirroring is enforced by
hand and by `indexer-api/test/schema.test.ts`, which asserts the five method
descriptors round-trip. That test gains a sixth case.

### Verified: one parity detail worth recording against C21

C21 currently faults the port because `confirmPrivateTransaction` "requires each
output view tag to reappear in the indexed record and sends no page limit, while
`wait_for_indexed_transaction` accepts a signature match at `limit = 50`". #158
resolves the page-limit half by deleting pagination from this path entirely, and
moves Rust toward the port on tag matching, though not all the way. `client.ts:503`
uses `tags.every(...)`; #158's `transaction_matches_tags` uses `.any(...)` over
outputs and messages. The port stays stricter than Rust, so the C21 finding
survives #158 in reduced form.

## 3. Fixture impact

### Verified: the baseline gate is already failing, and #158 does not change that

`ts-fixtures` hard-fails before generating anything if any path in
`BASELINE_SOURCE_PATHS` (`xtask/src/bin/ts-fixtures.rs:33-46`) differs from
`43fde8e4`. Checking all twelve against that revision today:

| Path | State |
| --- | --- |
| `sdk-libs/client/src/prover` | **drift** |
| `sdk-libs/keypair/src` | **drift** |
| `sdk-libs/transaction/src` | **drift** |
| `sdk-libs/transaction/tests` | **drift** |
| `sdk-libs/client/src/rpc.rs` | clean |
| `sdk-libs/indexer-api/src` | clean |
| `sdk-libs/zolana-api/src` | clean |
| the other five | clean |

Four paths already drift, so `assert_frozen_sources` already bails and
`fixtures:check` is already red. #158 would add three more drifted paths,
`client/src/rpc.rs`, `indexer-api/src`, and `zolana-api/src`, but the gate is a
single `bail!` on the first mismatch. **#158 does not make `fixtures:check`
worse. It is absorbed by the same regeneration.**

### Verified: which fixture contents actually change

Three fixtures are pinned separately, to `canonicalSourceRevisions.client` =
`30b58b9b`, and regenerated by `ts-fixtures --current-client`
(`ts-fixtures.rs:138-192`). Of the 58 fixtures, #158 changes exactly two of them,
and probably a third:

- **`client/errors-v1.json`** changes. It enumerates 58 `ClientError` variants
  exhaustively with sample details. #158 adds two, taking it to 60. This also
  forces two additions to `CANONICAL_CLIENT_ERROR_CODES` in `client/src/error.ts`
  and two new entries in the C02 producer-disposition test, which now derives the
  produced set by scanning for `new ClientError` sites.
- **`client/lib.json`** changes. It is a literal parse of `lib.rs`'s `pub mod`
  and `pub use` items, currently 7 modules and 89 names. #158 adds
  `GetShieldedTransactionsBySignatureResponse` and `IndexedShieldedTransaction`
  to the `pub use rpc::{..}` block, so the fixture gains two names and
  `crate-root-exports.test.ts` needs each carried, dispositioned, or deferred.
- **`client/rpc-indexer-v1.json`** is *inferred* to change. Its declared symbol set
  includes `wait_for_indexed_transaction_async`
  (`ts-fixtures.rs:2648`) and the packet report names `client/test/indexer-client.test.ts`
  against it. #158 rewrites that function. Whether the pinned *values* move
  depends on which vectors the fixture holds, which was not read exhaustively.

Two fixtures whose declared Rust source #158 touches do **not** change content:

- **`indexer-api/schema-v1.json`**: the declared source is
  `sdk-libs/client/src/rpc.rs`, but its content is `Context`, `MerkleProof`, and
  `NonInclusionProof` values (`ts-fixtures.rs:612-625`). #158 adds types to that
  file without touching those three. The fixture's *provenance* moves; its bytes
  do not.
- **`api/transport-v1.json`** and **`api/prover-request-v1.json`**: #158 adds two
  methods to `zolana-api` but changes no transport or prover behaviour.

*Inferred:* the net fixture cost of #158 is one `--current-client` regeneration
that this port already owes. `canonicalSourceRevisions.client` is `30b58b9b`,
which `git merge-base --is-ancestor 30b58b9b origin/main` confirms is *not* on
main. It is a branch-only commit. So the three client fixtures are already
pinned to a revision that only exists here, and they will be regenerated again
after the merge regardless of #158.

## 4. Does it change any open ruling?

**Your reading is correct. Verified, and it holds more strongly than stated.**

The ruling at issue is I07/I19 in `row-updates/interface-spec-conflicts.md:155-159`:
`spec.md:1450-1452` and `spec.md:1495-1498` make the deposit's discovery tag the
recipient's **signing** pubkey, consistent with the default-zone rule at
`spec.md:373`; both SDKs write the recipient's **viewing** pubkey x-coordinate
instead.

### Verified: #158 does not touch the tag derivation

The deposit tag is set at `sdk-libs/wallet/src/actions/deposit.rs:51`:

```rust
let view_tag = request.recipient.viewing_pubkey.x();
```

#158 changes seventeen files and none of them is in `sdk-libs/wallet`,
`sdk-libs/keypair`, `sdk-libs/transaction`, `program-libs/`, or `programs/`. It
adds no derivation and changes none. `transaction_matches_tags` only *compares*
tags that the caller already extracted.

### Verified: the confirm path cannot reach a deposit at all

This is stronger than "confirmation rather than discovery". #158's confirm path
reads its tags from `transact_output_view_tags_from_signature`, which walks the
confirmed instruction groups looking for a shielded-pool `TRANSACT` instruction
and, finding none, returns an error
(`sdk-libs/client/src/solana_rpc.rs:69-83`):

```rust
Err(ClientError::Rpc(
    "confirmed transaction has no shielded-pool TRANSACT instruction".into(),
))
```

A deposit is not a `TRANSACT`. `confirm_private_transaction` therefore cannot run
on a deposit transaction, and every caller in the tree confirms a transfer or a
withdrawal: `cli/src/wallet_cli/withdraw.rs:53`,
`cli/src/wallet_cli/transaction.rs:51` and `:139`,
`sdk-tests/client/examples/deposit_transfer_withdraw.rs:114` (the transfer) and
`:199` (the withdrawal), and the escrow, rfq, and swap tests. The deposit step in
that same example does not call it.

### Verified: deposit discovery runs through a different method, untouched

Deposit discovery reads `get_encrypted_utxos_by_tags`
(`sdk-libs/ts/wallet/src/sync.ts:215`). #158 does not modify
`services/photon/src/api/method/rings/get_encrypted_utxos_by_tags.rs`. That file
is not in the diff.

### Verified: the by-tags change is a refactor, not a semantic change

`get_shielded_transactions_by_tags.rs` is +42/-28, and reading it hunk by hunk,
every line is extraction. The body from `let rings_tx_ids = ...` onward moves into
a new `pub(super) async fn hydrate_shielded_transactions` so the signature lookup
can reuse it; the four `&tx` arguments become `tx`; the constructed value gains an
`IndexedShieldedTransaction` wrapper; and the by-tags caller strips it straight
back off:

```rust
let transactions = hydrate_shielded_transactions(&tx, matched_txs)
    .await?
    .into_iter()
    .map(|item| item.transaction)
    .collect();
```

`fetch_matching_rings_transactions`, the tag SQL, `validate_tags`, the cursor
handling, and `next_cursor_from_rows` are all unchanged, and
`GetShieldedTransactionsByTagsResponse` keeps its three fields. The only added
computation is `u16_from_i16(row.event_index, "event index")?`, whose result the
by-tags path discards. **The observable by-tags contract is byte-identical.**

*Inferred:* the one new failure mode is that a by-tags query now errors if a
stored `event_index` is negative, where before it was never read. That is a
database-invariant violation, not a reachable client path.

### Verdict

#158 is orthogonal to I07/I19. It neither strengthens nor weakens either option.
Option A2's cost estimate, a one-value change at `deposit.rs:51` and
`ts/wallet/src/deposit.ts:87` plus three fixture refreshes, is unaffected,
because #158 touches neither file and neither fixture. The protocol owner can
rule on the tag without reference to #158, and #158 can land without waiting for
the ruling.

## 5. Sequencing

### Land #158 first

The asymmetry is in the base, not the diff size. #158 is five commits against
`43fde8e4`, and `origin/main` is still at `43fde8e4`, so #158 can merge today
with no rebase at all. This branch is 206 commits against the same commit, and
its Rust client layer, three commits reworking `error.rs`, `indexer.rs`, and
`retry.rs`, is exactly what #158 collides with.

If #158 rebases onto this port: its author inherits a 206-commit branch, must
rewrite `indexer_error` against a struct variant they did not design, must
rewrite two of their own tests, must decide whether `retry_cause` or
`should_retry` is canonical, and must do all of it against a branch that is still
moving under them. The port's rows are 70 `needs_fix` and 11 `needs_re_review`
with none verified, so the base they rebase onto is not stable either.

If #158 lands first: this port takes one merge with one conflict hunk, resolved by
the people who wrote both `indexer_error` and the C04 finding that motivated it.
The three new-parity items are additive and independent, so they can be
sequenced into the existing rows rather than done as a batch.

### Do not add the method in anticipation

Three reasons, in order of weight.

**The port would be guessing at a shape that is still under review.** #158 has one
requested reviewer and no approval. Its error design is the weaker of the two on
a point this port already litigated: it puts the API response message back into
the error string, which is the exact property `6d757791` removed and C04 credits
as closed. If review changes that, and it should, an anticipatory port would
have to be redone.

**The name collision makes anticipation actively costly.** Porting #158 requires
renaming the port's public `IndexedShieldedTransaction`. Doing that rename before
#158 is final means either carrying a rename that #158 might not justify, or
doing it twice.

**There is nothing to gain by being early.** The new method has no caller in the
port other than `confirmPrivateTransaction`, which works today against
`getShieldedTransactionsByTags`. No port row is blocked on it. Adding it now
converts a clean future addition into present churn across nine source files
while 81 rows are still open.

### What to do now instead

Record the two forward-looking items so the merge is not a surprise:

- Note under C04 that the `indexer_error` design will need reconciliation, and
  that #158's `-32601` → `UnsupportedRpcMethod` mapping and its `-32603`
  retryability are improvements worth keeping when it happens.
- Note under C03 that `IndexedShieldedTransaction` will need renaming to
  `ShieldedTransaction`, because Rust is about to claim the name for a different
  type.

Neither requires a code change today.
