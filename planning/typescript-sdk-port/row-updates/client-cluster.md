# C03, C04, C05 and C18 verified at HEAD

Branch `port/client-c`, verified at `c3ed4dac`. Four adverse rows in
`@zolana/client`, each re-derived from the Rust source and the TypeScript
mirroring it rather than from the earlier reports. Two of the four earlier
reports were right; the corrections to them are in the sections below.

| Row | Was | Now |
| --- | --- | --- |
| C03 `rpc.rs` | needs_fix / DIVERGENT | PARITY, one surface reduction recorded |
| C04 `indexer.rs` | needs_fix / PARTIAL | PARITY on the decoder; one ruling unmet in `@zolana/api` |
| C05 `solana_rpc.rs` | needs_fix / PARTIAL | PARITY, one decided divergence pinned |
| C18 `prover/zone_authority.rs` | needs_fix / DIVERGENT | PARITY |

**Worktree collision.** A second agent was committing to `port/client-c` in this
same worktree while this ran. It landed `c3ed4dac` on top of `3ab3f3dc`, and it
wrote `xtask/src/bin/solana-rpc-groups.rs` and its TypeScript replay from under
an in-flight edit of the same files. The combined state is coherent and green,
and the sections below verify it as it stands, but the branch is not safe for
two writers and the next dispatch should give each worker its own worktree.

## C03 `rpc.rs`: PARITY

### The eight stubs hold up

[`c03-rpc-surface.md`](c03-rpc-surface.md) claimed most reportedly-missing
methods were trait declarations defaulting to `unsupported(..)` with no
implementor and no caller. Re-derived rather than credited: every method body in
`sdk-libs/client/src/rpc.rs:127-331` is `Err(unsupported(..))` with exactly two
exceptions, `create_and_send_transaction` at `:222-233`, which reads a
blockhash, compiles and sends, and `should_retry` at `:258-260`, whose default
is the literal `false`.

Searching the whole tree for each of the eight named methods finds them only in
`rpc.rs` and in `client.rs`, where `ZolanaClient` forwards to another default:
`client.rs:361` returns `self.rpc.get_transaction_slot(..)`, and the pattern
repeats for `send_versioned_transaction_with_config`, `process_transaction`,
`process_transaction_with_context`, `process_versioned_transaction`,
`create_and_send_versioned_transaction`, `send_and_prove` and
`subscribe_to_shielded_transactions_by_tags`. No implementor outside the trait,
no caller. The claim holds.

`should_retry` likewise: `client.rs:446-447` is
`self.rpc.should_retry(error) || self.async_indexer.should_retry(error)`, and
neither concrete type overrides the `false` default, so it returns `false` for
every error in Rust. The port's `retryCause` and `isRetryable`
(`sdk-libs/ts/client/src/index.ts:61-63`) are the classification it was meant to
expose.

### The rest of the surface

The five plain reads are present on the transport:
`sdk-libs/ts/client/src/solana-rpc.ts:208` `getSlot`, `:215` `getBlockHeight`,
`:225` `getSignatureStatuses`, `:248` `getMinimumBalanceForRentExemption`, `:266`
`getHealth`. `createAndSendTransaction` ships as a free function and is pinned
against the Rust default body by the oracle
(`sdk-libs/ts/client/test/vectors/solana-rpc-reads-oracle.test.ts:237-282`).

Every type the Rust trait file declares has a TypeScript counterpart with the
same fields: `Context{block_time: i64}` (`rpc.rs:30-33`) as `RpcContext`
(`rpc.ts:21-23`), `MerkleContext`, `EncryptedUtxoMatch`, `MerkleProof`,
`NonInclusionProof`, `SpendProof`, and the four response structs. Nothing on the
Rust side is unaccounted for.

**One correction to the earlier report.** It says the five reads "are
deliberately not added to the `Rpc` interface". Two of them now are, as optional
members: `getProgramAccounts?` at `rpc.ts:102` and
`getMinimumBalanceForRentExemption?` at `:111`. Optional members do not oblige an
implementor, so the split the report argued for survives, but the sentence no
longer describes the file.

**One surface reduction, recorded not fixed.** Rust's `get_account` returns
`solana_account::Account`, which carries `executable` and `rent_epoch`;
`RpcAccount` (`rpc.ts:94-98`) carries `owner`, `data` and `lamports` only, and
`decodeAccount` (`solana-rpc.ts:547-558`) drops the rest. `rpc.get_account(a)?
.executable` is therefore expressible in Rust and not here. The only Rust
consumer of the field is `SolanaRpc::assert_executable`
(`sdk-libs/client/src/solana_rpc.rs:143-154`), which is carried as
`SolanaRpc.assertExecutable` (`solana-rpc.ts:319-332`) and reads `executable`
straight off the RPC envelope. No capability is lost; the field is. Widening
`RpcAccount` is a one-line change if the reconciler wants the row to be exact
rather than equivalent.

## C04 `indexer.rs`: PARITY on the decoder, one ruling unmet upstream

### The per-field split is intact

Checked field by field in `sdk-libs/ts/indexer-api/src/codec.ts`. The
string-or-number union, `unboundedWireInteger` at `:107-120`, is reached by
exactly the five fields the owner ruled and no others:

| Field | Site |
| --- | --- |
| `block_time` | `:209` |
| `slot` | `:249` (match), `:271` (transaction) |
| `root_seq` | `:306` (inclusion), `:333` (non-inclusion) |
| `seq` | `:341` |
| `start_seq` | `:448` |

Every other integer goes through the number-only `wireInteger` at `:89-94`:
`leaf_index` (`:217`, `:304`), `low_element_index` (`:329`),
`high_element_index` (`:331`), `tree_type` and `root_index` as `u16`
(`:285`, `:307`), and `limit` through `checkedPageLimit` (`:140-159`). The
writer side never emits a string at all: `toWireInteger` (`:170-189`) returns a
JSON number and refuses one that would not survive the round trip. No residue of
the global-union version remains in this package.

### The ruled refusal does not fire through `@zolana/api`

`quoteUnsafeIntegers` (`sdk-libs/ts/api/src/index.ts:358`, defined at
`:373-438`) rewrites every unsafe integer literal in a response body into a
quoted string before `JSON.parse`. For the five unbounded fields that turns a
value the ruling says to refuse into one the decoder accepts.

Measured rather than reasoned, by driving a `get_merkle_proofs` response through
`ZolanaIndexer`:

- `root_seq: 9007199254740995` as a bare JSON number is **accepted**, with the
  exact value preserved. The ruled `INDEXER_SCHEMA_INVALID_INTEGER` never fires.
- `leaf_index: 9007199254740995` as a bare JSON number is still refused, because
  the capped decoder rejects the string the quoting produced. Same outcome as
  the ruling wants, reached by a different route and reporting a string where
  the ruling reports a number.

Nothing is silently truncated, because the quoting reads the raw text and the
digits stay exact, but the behaviour is not the one ruled. `sdk-libs/ts/api`
is row A01's file and the checklist already assigns the quoting there, so this is
recorded rather than changed. **If the reconciler scores C04 against the ruling
end to end, it stays PARTIAL until A01 stops quoting the five unbounded fields.**
Scored against `indexer.rs` and its decoder alone, it is PARITY.

### `with_http_trace` and `api()`

The two methods the checklist held C04 open for, dispositioned with evidence
rather than ported.

`ZolanaIndexer::api()` (`sdk-libs/client/src/indexer.rs:148-150`, async at
`:179-181`) has **zero callers anywhere in the repository**. It exists because
`ZolanaIndexer::new(url)` builds the API internally and the accessor is the only
way back to it; the TypeScript constructor takes the API
(`sdk-libs/ts/client/src/indexer.ts:38`), so the caller already holds it.

`with_http_trace` (`indexer.rs:143-146`, `:174-177`) flips a flag that
`zolana-api`'s `post` reads to print the request and the response body to stdout
(`sdk-libs/zolana-api/src/lib.rs:248-256`). Its only callers are one localnet
integration test, at `program-tests/shielded-pool/tests/localnet_photon_e2e.rs`
lines 112 and 736. `@zolana/client` is browser-targeted and writes to no
console, and printing response bodies from inside the SDK is the hazard
[`keypair-error-redaction.md`](keypair-error-redaction.md) records. The
capability is the caller's `fetch` instead, which sees both bodies at both
points and lets the caller decide where they go. Pinned by
`sdk-libs/ts/client/test/indexer-http-trace.test.ts` so the disposition cannot
quietly stop being true.

## C05 `solana_rpc.rs`: PARITY

The grouping rules now have the Rust oracle
[`stragglers.md`](stragglers.md#c05-solana_rpcrs-against-solana-rpcts-partial)
recorded as missing. `xtask/src/bin/solana-rpc-groups.rs` points a real
`SolanaRpc` at a listener answering `getTransaction` with a canned body and
records whatever `fetch_confirmed_instruction_groups` makes of it, into
`sdk-libs/ts/vectors/solana-rpc-groups-v1.json`. Thirteen cases, replayed by
`sdk-libs/ts/client/test/vectors/solana-rpc-groups-oracle.test.ts`.

The cases cover what reading cannot settle: account indexes resolving past the
message keys into the lookup table with writable before readonly, an inner group
attaching by its `index` rather than positionally, stack height one on an outer
slot against the wire's height on an inner one, and the refusals: absent
metadata, absent inner instructions, an inner group past the last outer
instruction, program-id and account indexes out of bounds, a lookup-table index
with no table, a base64-encoded transaction, and `jsonParsed` messages and inner
instructions. The generator counts the requests it served and fails the run on a
second one, so a body the RPC client cannot deserialize is caught as a generator
bug instead of being recorded as a grouping refusal it is not.

Refusals are compared as accept/reject decisions rather than as messages. Rust
returns one `ClientError::Rpc(String)` for every malformed body
(`sdk-libs/client/src/solana_rpc.rs:285-428`) while the port names a structured
code per path; the decision is the portable part and is what a caller acts on.

`getConfirmedTransaction` retries every failure until the confirmation deadline
(`solana-rpc.ts:354-362`), matching `fetch_confirmed_transaction`'s
`Err(_) if started.elapsed() < self.confirmation_timeout` arm
(`solana_rpc.rs:210-212`). `sendTransaction` resubmits while it waits
(`solana-rpc.ts:290-297`), matching `send_and_confirm_transaction`.

**One divergence stays, and it is decided rather than open.**
`confirmTransaction` sends `searchTransactionHistory: true`
(`solana-rpc.ts:383`) where Rust's `confirm_transaction` sends the signatures
alone (`solana_rpc.rs:539-543`), so a signature aged out of the recent status
cache reads as unconfirmed in Rust and confirmed here. Recorded in the reads
oracle and pinned by
`solana-rpc-reads-oracle.test.ts:142-150`, which fails if either side moves.

## C18 zone prover rails: PARITY

### What existed

The shape narrowing was already done on both sides and the checklist had not
caught up. Rust `sdk-libs/client/src/prover/zone_authority.rs` pins
`SUPPORTED_SHAPES` to the four squares and returns
`ClientError::UnsupportedZoneAuthorityShape`; TypeScript
`sdk-libs/ts/client/src/prover/zone.ts:66-71` pins the same four and throws
`CLIENT_UNSUPPORTED_ZONE_AUTHORITY_SHAPE` at `:287-289`. Both refuse the six
non-square members of `SPP_SUPPORTED_SHAPES`.

All three rails were assembled: `assembleZone` (`zone.ts:196`),
`assembleZoneP256` (`:224`), `assembleZoneAuthority` (`:277`). The circuit names
reach the prover as `transfer-zone`, `transfer-p256-zone` and
`transfer-zone-authority` (`prover/client.ts:294-300`), and the request body key
order follows the Rust structs so the two serializers produce the same bytes.

The evidence is a Rust oracle, `sdk-libs/client/src/prover/ts_zone_oracle.rs`,
which emits every supported shape for both transfer rails, the four
zone-authority shapes, the six rejections taken from the client's own constant,
and a second-zone case proving the zone field reaches the public input. Replayed
by `sdk-libs/ts/client/test/vectors/zone-oracle.test.ts`.

### What it required to build

Two gaps, both closed on this branch.

`PreparedZoneAuthority` dropped the external data that Rust carries, so no
`SppProofInputs` could be rebuilt from a prepared value and the rail was
unreachable end to end, because `prepareZoneAuthority` threw on
`publicAmounts()`. `c3ed4dac` gives the prepared value its external data, derives
the public leg from it as Rust does, ports `ZoneAuthorityWitness` as
`assembleZoneAuthorityWitness`, and exports the rails from the client root where
the Rust crate root carries their prover structs.

The frozen `@zolana/client/prover` export set had not taken
`assembleZoneAuthorityWitness`, so the subpath surface test failed rather than
guarding the subpath. Fixed in `3ab3f3dc`.

`ZolanaClient` has no zone prove-and-send path, and neither does Rust's. The
zone rails are reached through the prover module in both languages, so that is
parity rather than a gap.

## Handoffs

- **A01 (`sdk-libs/ts/api`).** Stop quoting unsafe integers for the five
  unbounded fields, or ask the owner to amend the ruling to allow the transport
  to preserve them. Today the ruled precision-loss refusal is unreachable
  through the shipped stack. Evidence above.
- **Whoever owns the branch dispatch.** Two agents shared `port/client-c` and one
  worktree during this run. Give each worker its own worktree.
- **Optional, C03.** Widen `RpcAccount` with `executable` and `rentEpoch` if the
  row is to be exact rather than equivalent.

## Verification

From `sdk-libs/ts`, after `npm run build`:

- `npm run test:unit`: 2025 passed, 1 skipped, 120 files, 0 failed.
- `npm run lint`: clean.
- `npm run typecheck`: clean.

`cargo build -p xtask --bin solana-rpc-groups` and
`cargo run -p xtask --bin solana-rpc-groups -- --check` both clean, so the
grouping fixture is current against the Rust it was generated from.

Not run: `cargo test -p zolana-client`, for the reason
[`stragglers.md`](stragglers.md#verification) records. No Rust behaviour changed
on this branch; the only Rust added is a generator binary.
