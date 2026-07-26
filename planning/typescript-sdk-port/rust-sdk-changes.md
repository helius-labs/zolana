# Rust SDK changes made during the TypeScript port

The port was meant to be faithful in one direction: read Rust, write TypeScript.
Review found defects in the Rust SDK instead, so the Rust side moved too. This
document records what moved and why, so that a reader can answer two questions
without reading the branch history:

1. What in the Rust SDK is no longer what it was?
2. Which of those changes affect an existing Rust consumer?

Reconstructed from git history on `ts-sdk-port` against `origin/ts-sdk-port`,
restricted to paths under `sdk-libs/` plus the `xtask` fixture generators.

- HEAD read for this record: `c541ba753aefaf644541583a0d64a8faeeb59425`
- Rust SDK commits documented below: 12

**This record is behind the branch, and by a wide margin.** The same query run
on 2026-07-26 returns 48 commits touching the Rust SDK crates, so 36 are
undocumented here. Among them is `d3514b24`, which changed
`sdk-libs/client/src/prover/proof.rs` on two counts that rows `C08` and `T23`
name. Treat the table below as the entries someone has written up rather than
as the set of changes, and run the query in [refreshing this
record](#refreshing-this-record) before relying on the absence of an entry.

## Scope boundary

In scope: `sdk-libs/` in both languages. Either side may change where parity
requires it.

Out of scope: `programs/`, `program-libs/`, `prover/server/circuits/`, and the Go
prover. Those are the deployed protocol.

One violation occurred and was reverted. Commit `bc55a9b9` hardened the
`ExternalDataHash` length prefixes in
`program-libs/interface/src/instruction/instruction_data/transact.rs`, replacing
`as u16` truncation with a checked conversion. Commit `b416a64f` reverted it. The
guard cannot be reached, because a Solana transaction cannot carry 65536 bytes of
instruction data, and the file belongs to the program rather than the SDK.

The revert stands, but the sentence that used to follow it here, that row `T21`
is therefore blocked on protocol scope, was overtaken by the ruling of
2026-07-26 and is withdrawn. The program keeps truncating and the guard moves
into the two SDKs, which is where this branch may put it: TypeScript already
raises `TRANSACTION_TOO_MANY_OUTPUTS`, and the Rust SDK takes the matching one.
`T21` is ordinary in-scope work. See [the T21
ruling](authority-rulings.md#the-external-data-length-prefix-t21) for why the
loud disagreement was preferred over silent agreement.

Amending `docs/spec.md` is permitted where the amendment records behavior the
implementations already have. Five have landed on this branch, against the one
this section used to name:

| Commit | Amendment |
| --- | --- |
| `b9a5386f` | Defines the `DataRecord::Memo` tag `3` that both languages implement |
| `25b13fa2` | Names the two pubkey field encodings and adds the per-variant owner tag that row `T23` turned on |
| `8616af8b` | Completes the rail-separation argument |
| `b97b2a88` | Corrects the deposit instruction to the deployed program |
| `58b2be6a` | Describes protocol config updates as single-field |

Each records behaviour the implementations already had, which is the condition
the exception is granted under. [`authority-rulings.md`](authority-rulings.md)
holds the evidence each was made against.

## Summary

Cause abbreviations used below:

- **defect**: review found a genuine defect in the Rust SDK. The port was the
  occasion, not the cause.
- **parity**: Rust was not wrong, but it was underspecified or inconsistent, and
  the two languages could not agree until it moved.
- **evidence**: the change supports the fixture generator or test oracles.
- **reverted**: the change turned out to be unnecessary and was undone.

| Commit | Crate | What changed | Cause | Breaks a consumer | Rows |
| --- | --- | --- | --- | --- | --- |
| [`6882ca25`](#6882ca25-canonical-asset-and-zone-pairs) | `zolana-transaction` | Asset id `0` rejected; zone data requires a zone program id | defect | behavior | T11, T12 |
| [`7c697c2c`](#7c697c2c-serialization-reconstruction-is-checked) | `zolana-transaction` | `from_utxos` validates cardinality, owner, zone, position; merge keeps its zone; anonymous recipients keep bound data | defect, parity | compile, behavior | T04-T09 |
| [`3ba52785`](#3ba52785-retry-outcomes-become-structured) | `zolana-client` | Retry classification, structured poll cause, attempt counts widened, proof-input rename | defect, parity | compile | C01, C02 |
| [`aa9ad01a`](#aa9ad01a-current-client-fixture-mode) | `xtask` | `ts-fixtures --current-client` regenerates two client fixtures alone | evidence | no | C01, C02 |
| [`3d444a6c`](#3d444a6c-wallet-sync-becomes-atomic) | `zolana-transaction` | Sync stages before it applies; counters resume; zero window rejected; balance arithmetic checked; parallel path matches serial | defect | compile, behavior | T14, T15, T16 |
| [`6d757791`](#6d757791-indexer-failures-are-classified-and-redacted) | `zolana-client` | `ClientError::Indexer` reshaped to `{ method, retryable }`; lag reported only when observed; spend proofs bound to requested leaves and trees | defect, parity | compile | C04, C01, C02 |
| [`0a58a856`](#0a58a856-redacted-indexer-error-oracle) | `xtask` | Client error and RPC fixtures regenerated for the new indexer error | evidence | no | C04 |
| [`bc55a9b9`](#bc55a9b9-the-zero-owner-dummy-rule) | `zolana-transaction` | Noncanonical zero-owner input rejected; padding slots zeroed; address hash count checked; zone rule re-checked at hashing | defect | compile, behavior | T18, T19 |
| [`b416a64f`](#b416a64f-revert-of-the-interface-length-prefixes) | `zolana-interface` | Reverts the out-of-scope half of `bc55a9b9` | reverted | no | T21 |
| [`30b58b9b`](#30b58b9b-prover-job-handles-and-dummy-signer-slots) | `zolana-client` | Server-supplied job id validated; signer index kept per padded input slot | defect | no | C19, C10 |
| [`cda42f01`](#cda42f01-builder-rejections-get-their-own-names) | `zolana-transaction` | Split input openability, withdrawal target against asset, checked slot ordinal and slot count, zone-authority constructor | defect | compile, behavior | T22, T24, T25, T29 |
| [`68631870`](#68631870-crate-root-surface-fixture) | `xtask` | `client/lib.json` records the `zolana-client` crate-root modules and re-exports | evidence | no | C22, C01, C02 |

Eight of the twelve commits are defect-led. Three of those eight also carry a
parity change. Three are evidence-only, and one is the revert.

## Breaking changes for Rust consumers

Neither `ClientError` nor `TransactionError` is `#[non_exhaustive]`, so adding a
variant stops an exhaustive `match` from compiling. Both crates sit at version
`0.1.0` with no `publish = false`.

### zolana-client, error shape

The one to call out is in `6d757791`: **`ClientError::Indexer(String)` became
`ClientError::Indexer { method: &'static str, retryable: bool }`**. The API layer
already classifies a failure as transient or fatal, and the TypeScript side has
to read that classification, so it has to survive the error boundary rather than
being flattened into a message. The response text is dropped in the
same move: an HTTP body or a JSON-RPC message can echo caller data, and it was
reaching public error output. A caller that matched `ClientError::Indexer(text)`
or read the message for the reason now gets a method name and a flag instead.

Three more in `3ba52785`:

- `PollTimedOut { last_error: Option<String> }` became
  `PollTimedOut { last_cause: Option<RetryErrorCause> }`. The string was built
  with `error.to_string()` on whatever transient error arrived last, which put
  indexer response text into a public error.
- `attempts` widened from `u32` to `u64` on `PollTimedOut` and
  `IndexerNotCaughtUp`, because `num_retries.saturating_add(1)` reported
  `u32::MAX` attempts instead of `u32::MAX + 1` at the boundary.
- `WitnessInputCountMismatch` was renamed `ProofInputCountMismatch`, and its
  message now reads "assembled proof inputs". `CLAUDE.md` keeps circuit-internal
  vocabulary out of public SDK names.

`RetryErrorCause` is a new public type, re-exported from the crate root beside
`ClientError`, along with the new method `ClientError::retry_cause()` and
`IndexerPollConfig::attempts()`.

Four `ClientError` variants switched their field type from `solana_pubkey::Pubkey`
to `solana_address::Address` in the same commit: `MissingSplTokenAccount`,
`UserRegistryRecordNotFound`, `MergeDisabled`, and `MergeViewingKeyMismatch`.
`CLAUDE.md` records `Pubkey` as an alias of `Address`, so this compiles the same
for a consumer.

### zolana-transaction, new error variants

`7c697c2c` added nine: `InvalidOutputCount`, `OutputOwnerMismatch`,
`OutputAssetMismatch`, `OutputAmountMismatch`, `OutputBlindingMismatch`,
`OutputDataMismatch`, `OutputZoneMismatch`, `InvalidOutputPosition`, and
`UnknownAssetField`. The last one replaces a `Deserialize(String)` that formatted
"merge asset field has no matching asset" into text.

`3d444a6c` added `WalletBalanceOverflow` and `InvalidTagWindow`. `bc55a9b9` added
`NoncanonicalDummyInput` and `AddressHashCountMismatch`.

`cda42f01` added ten: `WithdrawalAssetMismatch`, `OutputSlotOverflow`,
`ExcessOutputSlots`, `MissingZoneAuthorityProgramId`,
`ZoneAuthorityInputZoneMismatch`, `ZoneAuthorityOutputZoneMismatch`,
`ZoneAuthorityWithdrawalNotAllowed`, `SplitInputIsDummy`,
`SplitInputOwnerMismatch`, and `SplitInputNullifierKeyMismatch`.

### zolana-transaction, input that used to be accepted

These compile unchanged and then fail at runtime where they previously succeeded:

- `AssetRegistry::insert` rejects asset id `0` (`6882ca25`).
- `SppProofInputUtxo` hashing rejects a zero-owner input carrying any other
  nonzero field (`bc55a9b9`).
- Wallet balance and spent-total arithmetic returns `WalletBalanceOverflow`
  instead of saturating (`3d444a6c`).
- `Wallet::sync` and `Wallet::sync_parallel` reject a zero tag window
  (`3d444a6c`).
- The seven `from_utxos` conversions reject a UTXO set they used to reinterpret
  (`7c697c2c`).
- `ConfidentialSplit::new` rejects a dummy, a foreign owner, and a foreign
  nullifier key; `ConfidentialTransfer::withdraw` rejects a target that does not
  match the asset; `PreparedTransfer::finalize` rejects a slot list longer than
  the output count (`cda42f01`).

One relaxation runs the other way: `AnonymousTransferRecipientPlaintext::into_utxo`
used to reject zone data and program data with `UnsupportedOutputData` and now
carries both through (`7c697c2c`).

## zolana-transaction

### `6882ca25`, canonical asset and zone pairs

Paths: `sdk-libs/transaction/src/utxo.rs`,
`sdk-libs/transaction/src/wallet/asset.rs`. Rows T11, T12. Cause: defect.

`AssetRegistry::insert` rejected only `asset_id == SOL_ASSET_ID`, so asset id `0`
was registrable. `docs/spec.md` assigns `1` to SOL and starts SPL registration at
`2`, which leaves `0` reserved. The guard became `asset_id <= SOL_ASSET_ID` and
reports `ReservedAssetId(0)`.

`ProofInputUtxo::with_zone` accepted a nonzero `zone_data_hash` with
`zone_program_id: None`, which commits to a zone policy that no program can
enforce. It now returns `MissingZoneProgramId`. `bc55a9b9` later moved the same
check into `hash()`, because the fields are public and a directly assembled value
bypassed the setter.

### `7c697c2c`, serialization reconstruction is checked

Paths: `sdk-libs/transaction/src/error.rs` and the six modules under
`sdk-libs/transaction/src/serialization/`. Rows T04 through T09. Cause: defect,
with one parity relaxation.

Each `from_utxos` conversion read `utxos.first()` and ignored the rest, and took
the owner from that first UTXO rather than from the `OwnerCx` the caller passed.
A caller could hand in a set the conversion silently reinterpreted, and the
encoded plaintext then described a different transaction than the one the caller
built. Three private helpers in `serialization/mod.rs` now carry the rule:
`single_utxo` for the one-output families, plus `validate_owner` and
`validate_zone`.

Applied per family:

- `Confidential`, `Merge`, `Proofless`, and `AnonymousRecipient` require exactly
  one UTXO with the passed owner and zone context. `Merge` also rejects a
  data-carrying UTXO.
- `Split` checks each output against the first for asset, amount, and data, and
  against the derived blinding for its position.
- `AnonymousSenderBundle` rejects a duplicate SOL or SPL slot and checks each
  blinding against `derive_blinding(seed, position)`.
- `PlaintextTransfer` rejects a duplicate position, requires position `0` to be
  non-SOL and position `1` to be SOL, and requires the recipient positions to run
  contiguously from `2`.

Two smaller repairs ride along. `Merge::to_utxos` hardcoded
`zone_program_id: None`, discarding the zone the decode context carried, and now
reads `cx.zone_program_id`. The "merge asset field has no matching asset" string
became the structured `UnknownAssetField([u8; 32])`.

The parity change: `AnonymousTransferRecipientPlaintext::into_utxo` rejected zone
data and UTXO data on an anonymous recipient. `docs/spec.md` allows both, and the
TypeScript port accepted them, so Rust was the stricter of the two without
authority for it.

### `3d444a6c`, wallet sync becomes atomic

Paths: `sdk-libs/transaction/src/error.rs`,
`sdk-libs/transaction/src/wallet/{parallel,state,sync}.rs`, and
`sdk-libs/transaction/tests/wallet_unified.rs`. Rows T14, T15, T16. Cause:
defect.

Five distinct defects, one commit:

1. **Partial mutation on failure.** `Wallet::sync` and `Wallet::sync_parallel`
   mutated the wallet as they scanned, so a failure part way through left a
   wallet holding some of a sync. Both now stage onto a clone and assign it back
   after the scan returns. `Wallet` and `ViewingKeyEntry` gained `Clone` for
   this. The regression test asserts that a rejected sync leaves `last_synced`,
   `utxos`, and `transactions` untouched.
2. **A zero tag window scanned nothing, quietly.** With `window == 0` the range
   `start..start` is empty, so the scan loop exited on its first pass and
   reported a clean sync. Both entry points and the four probe helpers now
   return `InvalidTagWindow`.
3. **Counters restarted at zero.** The tag probes began at `0` on each sync
   rather than at the stored counter, so a wallet rescanned its whole tag
   history. `probe_sender_stream`, `probe_recipient_stream`,
   `probe_presence_stream`, and `scan_stream` take a `start` argument, fed from
   `tx_count`, `request_count`, `known_senders[s]`, and `known_recipients[r]`.
4. **Saturating balance arithmetic.** `Wallet::balance`, the balances map, and
   `SyncCtx::spent_amounts` used `saturating_add`, so an overflowing total
   reported `u64::MAX` as a balance. Each uses `checked_add` and reports
   `WalletBalanceOverflow`; `spent_amounts` returns `Result`.
5. **The parallel path disagreed with the serial one.** It skipped
   `record_confidential_send`, and it probed sender and recipient keys in
   `HashMap` order, which is not stable between runs. It now records
   confidential sends and sorts both key lists by their bytes first.

### `bc55a9b9`, the zero-owner dummy rule

Paths: `sdk-libs/transaction/src/error.rs`,
`sdk-libs/transaction/src/instructions/types.rs`,
`sdk-libs/transaction/src/instructions/transact/{types,spp_proof_inputs}.rs`,
`sdk-libs/transaction/src/utxo.rs`, plus TypeScript and the transaction fixture
generator. Rows T18, T19. Cause: defect.

A zero owner is not a parseable key, so a zero-owner input can only stand for an
unused proof slot. `SppProofInputUtxo` accepted one carrying a custom asset,
amount, data, zone, data hash, zone data hash, or nullifier key, and hashed those
fields under an owner hash that no key reproduces. The TypeScript port had
already started rejecting that input, which left the port stricter than the
implementation it was ported from, and row T18 recorded the inversion.

`check_canonical_dummy()` is public on `SppProofInputUtxo` and is called from
`TryFrom<&SppProofInputUtxo> for ProofInputUtxo`, the single conversion that
`hash()` and `nullifier()` both pass through, and from
`SppProofInputs::input_utxo_hashes` and `message_hash`. It names the offending
field in `NoncanonicalDummyInput { field }`, and TypeScript raises the matching
code with the same field string.

Three related hash-construction gaps closed in the same commit:

- `PrivateTxHash::hash` accepted an `address_hashes` slice of a different length
  than `input_hashes` and hashed it as given, shifting the address chain. It now
  reports `AddressHashCountMismatch`.
- `EncryptedTransaction::hash` hashed padding slots by their contents, where
  `SppProofInputs::message_hash` and the circuit both contribute a zero hash.
  `InputUtxo::is_dummy()` was added for this.
- `ProofInputUtxo::hash` re-checks the nonzero-zone rule from `6882ca25`, which
  the public fields let a caller bypass.

Both languages pin the same two digests for a canonical dummy built with a
`[7u8; 31]` blinding, so a change to the rule in either language fails a test in
that language.

### `cda42f01`, builder rejections get their own names

Paths: `sdk-libs/transaction/src/error.rs`,
`sdk-libs/transaction/src/instructions/transact/{slots,split,transfer}.rs`,
`sdk-libs/transaction/src/instructions/zone_authority.rs`, plus TypeScript. Rows
T22, T24, T25, T29. Cause: defect.

Four builders folded distinct rejections into one code or skipped them, so a
caller could not tell which rule an input broke and the two ports disagreed on
which rejection fired:

- **Split (T24).** `ConfidentialSplit::new` checked the part count, the asset,
  the zone, the attached data, and the amount sum, but not whether the splitter
  could open the input. The circuit proves ownership from the nullifier secret
  behind `owner_hash`, so a dummy, a foreign owner, or a foreign nullifier key
  produces an unprovable transaction. Each is now its own code:
  `SplitInputIsDummy`, `SplitInputOwnerMismatch`, and
  `SplitInputNullifierKeyMismatch`.
- **Withdrawal target (T25).** `ConfidentialTransfer::withdraw` accepted a SOL
  asset routed at a token account and the reverse. The public leg is picked by
  the asset and the external account by the target, so a crossed pair debits one
  leg and credits an account the program does not read.
  `WithdrawalAssetMismatch` rejects it.
- **Slot ordinal and slot count (T22, T25).** `encrypt_transaction_data` and
  `encode_confidential_slots` cast the output position with `slot_index as u32`,
  and that ordinal keys AES-CTR through the HKDF `info` string, so a wrapped
  value reuses a key and nonce pair across two slots. `slot_ordinal` checks the
  conversion and reports `OutputSlotOverflow`. `PreparedTransfer::finalize` read
  slots by output position and dropped a longer list without a trace; it reports
  `ExcessOutputSlots`. The recipient position in `finalize` also moved from
  `RECIPIENT_POSITION_BASE + i as u8` to a checked add, because blindings are
  derived from a `u8` position and a wrapped one reuses an earlier slot's
  blinding.
- **Zone authority (T29).** `zone_authority.rs` held only
  `PreparedZoneAuthority` and `input_utxo_hashes` and checked no zone rule, so a
  default-zone spend and a withdrawal both passed. The new
  `PreparedZoneAuthority::new` requires a nonzero `zone_program_id`, requires
  each non-dummy input and output to carry exactly it with no default-zone
  exemption, and refuses a nonzero public SOL or SPL leg. Nothing authorizes this
  spend beyond nullifier-secret knowledge, so the zone rule is what keeps value
  inside the zone. Errors: `MissingZoneAuthorityProgramId`,
  `ZoneAuthorityInputZoneMismatch`, `ZoneAuthorityOutputZoneMismatch`, and
  `ZoneAuthorityWithdrawalNotAllowed`.

The merge part of row T27 was TypeScript-only: Rust already separated
`MergeInputZoneMismatch` from `MergeInputHasData`, and the TypeScript builder had
folded both into one code.

## zolana-client

### `3ba52785`, retry outcomes become structured

Paths: `sdk-libs/client/src/{error,indexer,lib,retry}.rs`,
`sdk-libs/client/src/prover/transact/witness.rs`, and two `xtask` generators.
Rows C01, C02. Cause: defect, plus parity on the naming and the cause type.

`IndexerPollConfig::poll_until` treated any error as transient: it recorded
`error.to_string()` and kept polling. A rejected request therefore consumed the
whole schedule before failing, and the reason reached the caller as free text.
The new `ClientError::retry_cause()` returns `Some(RetryErrorCause)` for `Rpc`,
`Indexer`, and `IndexerTimeout`, and `None` otherwise; `poll_until` returns a
`None` error immediately and keeps the structured cause for the rest.

`backoff()` started at `delay_ms` without consulting `max_delay_ms`, so a config
whose initial delay exceeded its cap produced an over-long first sleep. It now
starts at `delay_ms.min(max_delay_ms)`.

`attempts()` replaces `num_retries.saturating_add(1)` at its three call sites and
returns `u64`, which is exact at `u32::MAX`.

The renames and the `Pubkey` to `Address` switch are listed under [breaking
changes](#zolana-client-error-shape).

Tests were added by injecting the sleep function, so the schedule is asserted
without real time passing.

### `6d757791`, indexer failures are classified and redacted

Paths: `sdk-libs/client/src/{client,error,indexer,retry}.rs`. Row C04, plus the
Rust half of C01 and C02. Cause: defect, plus parity on the error shape.

Four changes:

1. **`indexer_error` stringified `ApiError`**, so an HTTP body or a JSON-RPC
   message reached public error text, and the caller could not tell a transport
   hiccup from a rejected request. It now classifies: a `Request` failure is
   retryable unless it is a decode or builder failure, a `Response` is retryable
   on 408, 425, 429, or a 5xx status, and a JSON-RPC error, an invalid request,
   or a missing result is fatal. The result is
   `ClientError::Indexer { method, retryable }`, and `retry_cause` consults the
   flag. This is the [breaking change](#zolana-client-error-shape).
2. **`wait_for_indexer` duplicated the retry loop** rather than using
   `poll_until`, and it propagated any request failure straight out. Both the
   blocking and the async form now run on `poll_until` and the new
   `poll_until_async`.
3. **An unreachable indexer was reported as a slow one.** The old loop seeded
   `latest = i64::MIN` and reported `IndexerNotCaughtUp` with that seed when the
   schedule ran out. A small `Lag` guard now counts responses, and it reports
   `IndexerNotCaughtUp` only when the response count reaches the attempt count,
   which means the indexer answered on each attempt and lagged. Otherwise the
   precise failure, usually `PollTimedOut` with its cause, is returned.
4. **`ZolanaIndexer::prove_transact` zipped spend proofs by position** without
   checking that a returned proof matched the leaf and tree it was requested
   for, and reported a short response as a formatted `Rpc` string. Its private
   `spend_proofs` helper was deleted, and `prove_transact` calls the
   `pub(crate)` `fetch_spend_proofs` in `client.rs`, which validates each proof
   against its request and reports `IncompleteInputProofs`. That leaves one
   checked spend-proof path in the crate instead of two.

### `30b58b9b`, prover job handles and dummy signer slots

Paths: `sdk-libs/client/src/prover/client.rs`,
`sdk-libs/client/src/prover/transact/witness.rs`. Rows C19, C10. Cause: defect.

`poll_async` interpolated the server-supplied `job_id` straight into
`{server}/prove/status?job_id={job_id}` in both the blocking and the async
client, so a handle containing a path or query character redirected the poll. The
new `checked_job_id` restricts it to `[A-Za-z0-9_-]{1,256}`, the same charset and
bound the TypeScript client applies, and reports `ProverServer` otherwise.

`assemble` collected signer indices for the real inputs into a compacted list and
then read that list by absolute input slot. The two line up only while each dummy
trails the real inputs; a dummy ahead of a real input shifted the later signers
and could mark a real P256 input as eddsa-signed. The list now holds one entry
per padded slot, with `None` for a dummy, and the dummy signer is the first real
entry found.

## Fixture generators in xtask

### `aa9ad01a`, current-client fixture mode

Path: `xtask/src/bin/ts-fixtures.rs`. Rows C01, C02. Cause: evidence.

Default-mode `ts-fixtures` calls `assert_frozen_sources`, which fails while any
canonical source differs from the frozen baseline `43fde8e4`. Thirteen
`sdk-libs/transaction` paths already differ and are still moving, so the client
fixtures could not be regenerated without waiting on unrelated work. That is
register issue G8-1.

`--current-client` regenerates `client/errors-v1.json` and
`client/rpc-indexer-v1.json` alone, stamping each with the last commit that
touched `sdk-libs/client/src`, and updates the two manifest hashes and
`canonicalSourceRevisions.client`. `--check` verifies the same pair. The
`--help` branch also stopped calling `process::exit(0)` from inside a fold and
returns instead.

### `0a58a856`, redacted indexer error oracle

Paths: `xtask/src/ts_fixtures_client.rs` and the two fixtures it writes. Row C04.
Cause: evidence.

`CLIENT_INDEXER` carried `{"reason": "indexer failed"}`. It now carries
`{"method": "get_merkle_proofs", "retryable": true}`, matching the reshaped
`ClientError::Indexer`, and both fixtures re-pin to `6d757791`.

`3ba52785` made the equivalent generator edits for `PollTimedOut.last_cause` and
the `ProofInputCountMismatch` rename in the same commit as the Rust change.

### `68631870`, crate-root surface fixture

Path: `xtask/src/bin/ts-fixtures.rs`. Rows C22, C01, C02. Cause: evidence.

The rest of this commit is TypeScript. The Rust-side part adds a
`client/lib.json` fixture that parses `sdk-libs/client/src/lib.rs` for its
`pub mod` declarations and the leaf names of its `pub use` trees, so a name
gained or lost at the `zolana-client` crate root fails a TypeScript vector test
unless it carries a disposition. The expected fixture count moved from 57 to 58,
and `--current-client` regenerates the new file beside the other two.

The parser reads Rust source as text rather than through `syn`: it strips line
comments, splits on `;`, and walks a `use` tree by brace depth. That holds for
the flat re-export list `lib.rs` has today.

## The out-of-scope change and its revert

### `b416a64f`, revert of the interface length prefixes

Path: `program-libs/interface/src/instruction/instruction_data/transact.rs`. Row
T21. Cause: reverted.

This is the change that was unnecessary, recorded as such rather than justified
after the fact.

`bc55a9b9` replaced the three `as u16` casts in the `ExternalDataHash` preimage
with a `length_prefix` helper returning `HasherError::IntegerOverflow` above
`0xffff`, and added a boundary test. Two problems. The file is in
`program-libs/`, which the shielded-pool program depends on and which the port
does not touch. And the guard cannot be reached: a Solana transaction cannot
carry 65536 bytes of instruction data, so no output count, data length, or
message count reaches the boundary.

`b416a64f` restored the casts and removed the helper, the comment, and the test.
Its prerequisite as written was misfiled in the first place: it named
`sdk-libs/transaction/src/instructions/transact/external_data.rs`, which contains
no unchecked `u16` cast, when the casts are in the interface preimage.

Row `T21` keeps its adverse verdict, and the reason has changed. It was recorded
here as blocked on protocol scope. The ruling of 2026-07-26 decided otherwise:
the program keeps truncating, both SDKs refuse the oversized input loudly, and
the work is a Rust SDK guard matching the TypeScript one plus a boundary vector
at `0xffff` against `0x10000`. That work is in scope and is step 5 of
[`remaining-work.md`](remaining-work.md). Do not read this section as a reason
to leave the row alone.

## Open defects in the Rust SDK that no commit has fixed

Review recorded these in the checklist session log. No commit addresses them; two
entries note a related half that a commit did close. Rows are given so the
finding can be read in full in the log.

### zolana-client

| Row | Path | Defect |
| --- | --- | --- |
| C21 | `src/client.rs` | `with_send_transaction_config` stores `send_config` and no path reads it, so a caller-supplied send config is dropped in silence. |
| C21 | `src/client.rs` | `wait_for_rpc_confirmation` and `wait_for_indexed_transaction` return `ClientError::Rpc(String)` for an unconfirmed signature and for an empty tag list. `MissingOutput` exists, `CLAUDE.md` asks for a named variant per failure, and TypeScript raises `CLIENT_MISSING_OUTPUT` and `CLIENT_CONFIRMATION_TIMEOUT`. |
| C05 | `src/solana_rpc.rs` | `transact_output_view_tags_from_instruction_groups` and `parse_pubkey` build public error text with `format!`, so RPC payload fragments reach `ClientError::Rpc` strings instead of structured details. |
| C05 | `src/solana_rpc.rs` | `wait_for_signature` and `fetch_confirmed_transaction` hard-code a 250 ms interval, and `AsyncSolanaRpc` hard-codes the 30-second `DEFAULT_CONFIRMATION_TIMEOUT`, ignoring the configurable `confirmation_timeout` that `SolanaRpc` already stores. |
| C19 | `src/prover/client.rs` | `send` builds the URL by string concatenation, so a base address with a trailing slash produces a double-slash path. The `job_id` half of this finding was closed by `30b58b9b`. |
| C08 | `src/prover/proof.rs` | `hex_to_be_32` swallows a hex parse failure with `unwrap_or_default()`, turning a malformed coordinate into zero, and truncates an over-long value rather than rejecting it. `proof_from_gnark_json` returns a bare `Option`, discarding which member failed. |
| C16 | `src/prover/merge.rs` | `MergeProver::common` documents that `tx_viewing_sk` must be below the BN254 modulus and does not check it, so an out-of-range scalar reaches the prover silently reduced. |
| C06, C16 | `src/prover/merge.rs` | `right_align` is a second 31-byte implementation of `field::right_align`, which has no caller. Keep one. |
| C04 | `src/indexer.rs` | `docs/spec.md` defines indexer `Context { slot: u64 }` while both languages expose `block_time: i64`. A spec-against-implementation difference rather than a code defect. |

### zolana-transaction

| Row | Path | Defect |
| --- | --- | --- |
| T23 | `src/instructions/transact/spp_proof_inputs.rs` | No canonical BN254 range validation. The rest of T23 is a specification conflict for the protocol owner about the confidential owner-tag variant, which is outside SDK scope. |
| T22 | `src/instructions/transact/slots.rs` | One ciphertext is produced per published output, where `docs/spec.md` fixes one sender-bundle ciphertext at the first output position and derives each recipient ordinal from the count of preceding data-bearing outputs. `cda42f01` closed the unchecked cast half of this row and left the layout question open. |

T24, T25, and T29 were listed here until `cda42f01` closed them. The Rust SDK
paths under `sdk-libs/` are clean at the HEAD above, so nothing in this section
is in flight in the worktree.

### zolana-wallet

| Row | Path | Defect |
| --- | --- | --- |
| W02, W09 | `src/lib.rs` | `actions/mod.rs` re-exports `deposit` while `lib.rs` omits it, so the crate root advertises `build_deposit_transaction` without the send path that uses it. |
| W04 | `src/actions/transaction.rs` | `create_transfer_with_recipient` resolves the spend tree before the registry lookup while TypeScript reverses the order. Defensible either way; pin it in one place. |
| W08 | `src/wallet_sync.rs` | `sync_wallet` and `sync_wallet_async` differ only in the default `wait_for_indexer`, which is easy to miss. State the intended default in one place. |

## Refreshing this record

The list above was derived, not transcribed. To find Rust SDK work that landed
after `c541ba75`:

```bash
git log --oneline --reverse --name-only origin/ts-sdk-port..HEAD \
-- 'sdk-libs/' 'xtask/' ':!sdk-libs/ts/'
```

Read each new commit, place it in the crate section it belongs to, and record its
cause with the four labels from the [summary](#summary). A commit that touches
`programs/`, `program-libs/`, `prover/server/circuits/`, or the Go prover is a
scope violation and belongs in [the out-of-scope
section](#the-out-of-scope-change-and-its-revert) with its revert.
