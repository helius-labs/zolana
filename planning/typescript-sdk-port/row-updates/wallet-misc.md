# Wallet, merkle-tree, and the stragglers

Ten adverse rows: the `W` family over `sdk-libs/ts/wallet`, the two `M` rows over
`sdk-libs/ts/merkle-tree`, and two known bugs that belonged to no row. Every
verdict below rests on a committed JSON oracle generated from the Rust crate,
because this branch has already produced a false parity claim from a
side-by-side reading and the checklist says so twice.

## Bottom line

| Row | Verdict | Evidence |
| --- | --- | --- |
| M01 | PARITY | `vectors/merkle-semantics-v1.json`, indexed scenarios |
| M02 | PARITY | `vectors/merkle-semantics-v1.json`, plain-tree scenarios |
| W04 | PARITY | `vectors/wallet-actions-v1.json`, 28 cases |

Three divergences turned up that no row had recorded, all found by replaying an
oracle rather than by reading:

1. **Zero is not out of the indexed range.** `IndexedMerkleTree.insert(0)` raised
   `INDEXED_MERKLE_TREE_INVALID_VALUE` where Rust raises
   `Indexed(ElementAlreadyExists)`. Zero is the tree's first element, so a
   duplicate is what it is. Fixed.
2. **`select_inputs` sums into a `u64`.** A wallet whose notes total past that
   ceiling makes Rust return `SelectedBalanceOverflow`; the port kept widening a
   bigint and built the spend. Fixed under a new
   `WALLET_SELECTED_BALANCE_OVERFLOW`.
3. **`bigIntToBytes` accepted what Rust refuses** (see the stragglers below).

## The evidence, and why it is shaped this way

Two new generators, both following `xtask/src/bin/poseidon-parity.rs`: write a
canonical JSON fixture, support `--check` so drift fails loudly, and commit the
output.

```bash
cargo run -p xtask --bin merkle-semantics   # sdk-libs/ts/vectors/merkle-semantics-v1.json
cargo run -p xtask --bin wallet-actions     # sdk-libs/ts/vectors/wallet-actions-v1.json
```

Both record *traces*, not end states, because that is what these rows ask about.
Atomicity, a first-fit selection loop, and a wrapping history index are all
properties of a sequence of calls; a fixture that captures one final root cannot
distinguish "the rejection left the tree alone" from "the rejection happened to
land on the same root". Each step carries the outcome of the call and the whole
observable state after it, so a divergence fails at the step that introduced it.

Rejections travel as the Rust `Debug` variant name. The two languages do not
share an error taxonomy, so each test holds an explicit variant-to-code table and
throws on an unmapped variant rather than passing quietly.

## M01: `IndexedMerkleTree`

`sdk-libs/ts/merkle-tree/test/vectors/merkle-semantics.test.ts` replays two
indexed traces: the default sentinel, and a custom sentinel of 100.

The sentinel closes the range from above, and closes it for both entry points.
The trace queries and appends the sentinel, the sentinel plus one, and twice the
sentinel; all six calls are `ValueOutsideIndexedRange`, the element count and the
root are unchanged after each, and the value one below the sentinel both proves
and appends. That is the M01 question answered, including the part the frozen
fixture could not reach: a *rejected* append leaves the tree provable from the
same root, because `append` restores the element list before returning the error.

**Rust moved for this row, and a later reader should know it.** The checklist
records the differential oracle finding Rust returning a proof at the sentinel
where TypeScript refused. Commit `4d9a39f1`, from the previous worker on this
branch, changed Rust instead of TypeScript, on the ground that Rust was
internally inconsistent rather than merely more permissive:
`get_non_inclusion_proof` returned a proof that `verify_non_inclusion_proof`, on
the same tree, rejected with `NonInclusionProofFailedHigherBoundViolated`. The
exclusion ranges tile `(0, highest_value)`, so a proof at the sentinel is not
representable, not merely unusual. I agree with the call and my oracle pins it,
but the parity here is parity with Rust as this branch leaves it, not with the
Rust the row was filed against. The corresponding bound in
`zolana_indexed_array` is a protocol library and was correctly moved to its own
branch (`88728091`).

## M02: `MerkleTree`

Three plain-tree traces.

**`get_next_index` carries no offset.** A tree built with
`rootHistoryStartOffset: 2` reports `nextIndex` 0, 1, 2, 3 across construction
and three appends, which is the appended-leaf count, unshifted. The offset appears only
in `historyRootIndex`, which is `(nextIndex - offset) % length` and *rejects*
while the offset runs ahead of the index. Neither `update` nor `insertLeaf`
advances `nextIndex`.

**`get_history_root_index_v2` is not always zero.** It counts root updates modulo
the history length and wraps: 0, 1, 2, 0, 1 over the same trace. An `update`
moves it because a recompute is a root update; `insertLeaf`, which recomputes
nothing, does not. The row's "always-zero semantics" is not what either language
does, and both agree on what they do instead.

**A rejected mutation changes nothing.** A height-2 tree takes four appends, then
a fifth that Rust refuses with `IntegerOverflow` and an `update` at index 9 that
it refuses with `LeafDoesNotExist(9)`. Root, leaf count, next index, root-history
length, and sequence number are byte-identical across the two refusals. Both
languages mutate a clone and adopt it only on success.

**A tree with no history configured rejects both accessors** rather than
answering with a default index: `RootHistoryArrayLenNotSet` in Rust,
`MERKLE_TREE_INVALID_HISTORY` in the port.

`4d9a39f1` also turned three `get_history_root_index` panics into rejections, so
the accessor's error arms in this fixture are likewise Rust-as-this-branch-leaves-it.

## W04: `create_withdrawal` and `create_split`

`sdk-libs/ts/wallet/test/vectors/wallet-actions.test.ts` replays 28 cases over
eight wallets. The fixture describes each wallet declaratively (amount, tree, and
whether the note is plain, zone-bound, or data-carrying) so the port
builds the same wallet rather than trusting a hash.

**The strictness regression was real.** Rust builds a zero-amount withdrawal:
`create_withdrawal` has no amount check, and `select_inputs` returns on the first
note because `available >= 0` holds for any note. The oracle records
`{"amount": "0", "outcome": {"arm": "ok", "value": {"inputCount": "1"}}}`. The
old `positiveAmount` refused it, so the SDK was refusing a transaction the chain
accepts. `d2ff553b` had already relaxed the guard to a `u64` ceiling; this is the
independent confirmation that row asked for, from the crate rather than from a
reading of it.

The same run pins the rest of the row's clauses:

| Question | Rust | Port |
| --- | --- | --- |
| Amount above the balance | `InsufficientBalance { requested: 24, available: 23 }` | `WALLET_INSUFFICIENT_BALANCE` |
| First-fit note count at 4, 12, 23 | 2, 3, 3 | same |
| Notes on two trees | `AmbiguousTree { tree_count: 2 }` | `WALLET_MULTIPLE_INPUT_TREES` |
| Split arity 0, 1, 9 | `SplitInvalidPartCount` | `WALLET_SPLIT_INVALID_PART_COUNT` |
| Split arity 2, 3, 4, 8 of `[3, 8, 12]` | 6, 4, 3, 1 per output | same |
| Named zone-bound note | `SplitInputZoneMismatch` | `WALLET_SPLIT_INPUT_ZONE_MISMATCH` |
| Named data-carrying note | `SplitInputHasData` | `WALLET_SPLIT_INPUT_HAS_DATA` |
| Named hash the wallet lacks | `InputUtxoUnavailable` | `WALLET_INPUT_UTXO_UNAVAILABLE` |

Two behaviours are worth naming because they are easy to get wrong and both
languages get them the same way. A zone-bound or data-carrying note is invisible
to auto-selection, so a wallet holding only one of those reports
`InsufficientBalance { requested: 1, available: 0 }` rather than the specific
refusal; the specific refusal is reachable only by naming the note. And a large
zone-bound note does not shadow a smaller plain one: the eligibility filter runs
before the largest-first pick.

`create_transfer` needs an RPC and is not in the fixture, but it shares the one
amount guard and the same `select_inputs`, and its unregistered path delegates to
`create_withdrawal` outright.

## The stragglers

**`test-kit` faucet port.** `startLocalStack` offset the RPC port but spawned
`solana-test-validator` without `--faucet-port`, so every clone's validator
grabbed the default 9900 and the second one to start failed. Both sidecar ports
now derive from the same offset through one `sidecarPorts` helper, which the
test-kit suite checks at offset 0 and at an offset. Commit `998df572`.

**`keypair` `bigIntToBytes`.** It truncated silently at the array width and read
a negative as two's complement, where the Rust `BigUint` conversion returns
`InvalidInputLength`. It now refuses both, matching the fix already made in
`merkle-tree/src/bytes.ts`, and the change is confined to `bytes.ts` because
another worker holds the keypair error surface. Commit `a4560f41`.
