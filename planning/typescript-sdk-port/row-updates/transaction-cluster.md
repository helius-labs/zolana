# The `@zolana/transaction` adverse cluster, re-verified at HEAD

Worker on branch `port/tx-close`. Scope held to `sdk-libs/ts/` and this planning
directory; nothing in `programs/`, `program-libs/`, `prover/`, or the Rust SDK
crates was touched. `sdk-libs/ts/transaction/src/wallet/sync.ts` and
`.../serialization/codecs.ts` belong to another worker and were read but not
edited.

Every verdict below was re-derived from the Rust source and the TypeScript
mirroring it at the current HEAD. Where a row's recorded residual turned out to
be stale, that is said plainly rather than repeated, because several of these
residuals describe a state the tree left some commits ago.

## Summary

| Row | Was | Now | What moved |
| --- | --- | --- | --- |
| T12 | PARTIAL | **PARITY** | `AssetRegistry` narrowed to the Rust surface |
| T13 | DIVERGENT | **PARITY** | verified only; the rail check was already right |
| T14 | PARTIAL | **PARITY** | verified only; the recorded gaps are stale |
| T16 | DIVERGENT | **PARITY**, with a platform disposition | atomicity pinned |
| T17 | DIVERGENT | **PARITY** on exports; allowlists open | verified only |
| T21 | PARTIAL | **PARITY** at the SDK layer | Rust guard had landed; interface layer now pinned |
| T23 | DIVERGENT | **PARITY** | the public leg moved into `SppProofInputs` |
| T26 | PARTIAL | **PARITY** on exports; allowlists open | verified only |
| T28 | PARTIAL | **PARITY** | last clause closed, in the form parity allows |
| T29 | PARTIAL | **PARITY** | `prepareZoneAuthority` derives what Rust derives |
| T30 | PARTIAL | **PARITY** on exports; allowlists open | verified only |
| T31 | PARTIAL | **PARITY** | second constant duplication found and closed |
| S01 | DIVERGENT | **stays DIVERGENT** | verified; the residual is real, see below |

Four rows keep an open item. T17, T26, and T30 each carry a packaging-allowlist
clause that is a different kind of work from the export parity they also carry,
and that clause is untouched here. T21 keeps a layering note about which error
taxonomy the interface-level hash should use, which is a naming question with no
input on which the two layers disagree.

## T12, `wallet/asset.rs`: PARITY

The registry's behaviour already matched. Insert refuses in Rust's order:
reserved id, then duplicate id, then duplicate mint (`asset.rs:24-36` against
`asset.ts:17-39`), which matters for the one input that violates two rules at
once: re-inserting an existing pair reports the duplicate id in both. The two
extra TypeScript guards ahead of that order, the `bigint` range check and
`decodeAddress`, stand in for Rust's `u64` and `Address` types and cannot fire
for an input expressible in Rust. `resolve`, `asset_id`, and `address_for_field`
agree on values and on error variants, and the whole of it is pinned by the
`oracle.asset` vectors in `rust-oracle.test.ts:423-427` and
`transaction-vectors.test.ts:236-259`.

What did not match was the surface. Rust keeps the map private and exposes
`address_for_field` as a method; TypeScript published an `entries()` accessor
and a free `addressForAssetField`, both existing only so code outside the class
could reach the map. Folding the scan into the method removes both. `clone()`
stays: it stands for the Rust `Clone` derive, and `Wallet` holds its registry by
value in both languages (`state.ts:168`).

## T13, `wallet/authority.rs`: PARITY

The row is about the Rust fix that routed P256 signing through the single
signer. The TypeScript side needed no change and, on the evidence, never had the
defect.

Rust resolves the rail before signing: `signing_pubkey().as_p256()?` refuses a
non-P256 key with `KeypairError::InvalidSignatureType` (`pubkey.rs:128-135`).
TypeScript takes the same order through `publicKey().p256()`, which throws
`KEYPAIR_INVALID_SIGNATURE_TYPE` before any signature is produced
(`sdk-libs/ts/keypair/src/public-key.ts:150-153`). Same refusal, same category,
same point in the sequence.

The other half of the row, `ShieldedKeypair::solana_pubkey()` returning a
default address when derivation fails, has no TypeScript counterpart to diverge
from: `LocalWalletAuthority` is constructed with the Solana public key rather
than deriving one, so there is no failure path to swallow. Not porting a Rust
defect is the right outcome, and it is recorded here so nobody adds the method
later for symmetry.

## T14, `wallet/state.rs`: PARITY

The recorded residual is stale. `PrivateTransaction` carries all seven Rust
fields including `asset`, `amount`, and `counterpartyViewingPublicKey`
(`state.rs:45-53` against `state.ts:53-61`); `PrivateTransactionId` carries
`slot` (`state.ts:28-32`); and `PrivateTransactionStatus` is `"confirmed"` alone,
with no extra `pending` (`state.ts:51`).

`balance` and `balances` agree, including the overflow refusal. Rust
`checked_add`s each note and reports `WalletBalanceOverflow`; TypeScript sums in
`bigint` and checks the total. Amounts are non-negative, so the running sum is
monotonic and the total is its maximum: the two refuse exactly the same inputs.
Ordering, the `skipUtxos` behaviour, and the `UnknownMint` path off the registry
all match.

Two shapes stay deliberately different, both already dispositioned in
`module-surface.test.ts`: `Balances` is a newtype whose only method is a find by
mint, so `balances()` returns the array; and `_state()`/`_replace()` stand for
Rust's `pub(super)` accessors, which TypeScript has no visibility level for.

## T16, `wallet/parallel.rs`: PARITY, with the concurrency dispositioned

Rust's parallel path has exactly two public entry points, `sync_parallel` and
`sync_parallel_with_material` (`parallel.rs:99-126`). Its observable behaviour
beyond throughput is the staged clone: `*self = staged` runs only on success, so
a failed sync leaves a populated wallet untouched. TypeScript reaches the same
guarantee by a different route. `decryptTransactions` computes into locals and
calls `Wallet._replace` once at the end (`sync.ts:910-916`), and rayon has no
browser-safe counterpart, which is why the serial stand-in is the right shape
rather than a shortfall. That disposition is already recorded at
`module-surface.test.ts:166-167`.

The row asked for a serial-parallel equality assertion. One exists at
`wallet-sync.test.ts:322-330`, comparing report, UTXO set, and history against a
Rust fixture. What nobody had pinned is the atomicity, because every failure
case in the suite starts from an empty wallet, where a half-applied batch is
invisible. Added: a populated wallet, a batch refused for a zero tag window, and
an assertion that both entry points leave the UTXOs, the history, and
`lastSynced` exactly as they were.

The Rust-side clause, running the `parallel` feature in the normal gate command,
is a `cargo` change and stays open outside this scope.

## T17, T26, T30, the three aggregate rows: PARITY on exports

All three record a list of Rust names the TypeScript aggregate omits. Every
listed name is present at HEAD:

- **T17** (`./wallet`): `ApprovalRequest` (`wallet/index.ts:4`),
  `LocalWalletAuthority` (`:2`), `Filter` (`:25`), `ViewingKeyEntry` (`:32`),
  `SyncConfig` as `WalletSyncConfig` (`:19`), and all four `PrivateTransaction*`
  types (`:26-30`). `Balances` and `decrypt_transactions_with_config` are
  dispositioned with reasons (`module-surface.test.ts:88-91`), and the
  `decryptTransactionsWorkerEquivalent` alias the row wanted "recorded or
  removed" is recorded (`:166-167`).
- **T26** (`./transact`): `EncryptedTransaction`, `InputUtxo`, `OutputSlot`,
  `ShieldedTransaction` as `IndexedShieldedTransaction`, and
  `SppProofOutputUtxo` as `ProofOutputUtxo` are all exported
  (`transact/index.ts:17-31`).
- **T30** (`./instructions`): carried, with the input and output types reached
  through the same barrel.

This is not three separate spot checks. `module-surface.test.ts` reads the
Rust-generated `moduleSurfaces` oracle and asserts, for each of the five
aggregates, that every Rust name is either exported under its recorded
TypeScript spelling or dispositioned with a reason, and symmetrically that every
TypeScript export is accounted for. It also fails on a stale disposition in
either direction. So the omission clause of all three rows cannot silently
reopen.

**What stays open, identically for all three:** the packaging allowlists,
runtime, declaration, tarball, browser, named-consumer, and aggregate-fixture.
Those are `sdk-libs/ts/config` gates about what a published tarball exposes, not
about whether the barrel names match Rust, and none of them were touched here.
A reconciler may want to split that clause into its own row, since it is the
same work in three places and unrelated to the parity the rows otherwise track.

## T21, `external_data.rs`: PARITY at the SDK layer, one layering note open

An earlier draft of this file said the row's two halves were both Rust work.
That was wrong, and a re-read at HEAD corrects it: the Rust guard has landed.
`check_preimage_prefixes` refuses all four `u16` prefixes with
`TransactionError::TooManyOutputs` for the two counts and
`ExternalDataLengthOverflow { field, maximum, actual }` for the two data lengths
(`sdk-libs/transaction/src/instructions/transact/external_data.rs:159-184`), and
its own comment records the ruling that both SDKs refuse rather than reproduce
`program-libs/interface`'s truncation.

TypeScript matches it at the same layer. `transact.ts:252-280` wraps the
interface hash and runs the same checks first, raising
`TRANSACTION_TOO_MANY_OUTPUTS` and `TRANSACTION_INVALID_DATA_LENGTH`. The
boundary vector the row asked for also exists now and is cross-language: the
Rust oracle carries `maxOutputs` at `65535` with a computed digest against
`oneOutputPastMax` at `65536` refused, plus the same pair for messages, and
TypeScript replays all four (`transaction-parity-v1.json` `externalData.cases`,
replayed at `test/vectors/rust-oracle.test.ts:1704-1741`). Rows T21's accepted
`0xffff` and refused `0x10000` are therefore both pinned by execution, not by
reading.

What was genuinely missing, and is closed here, is the layer below. A caller
reaching `@zolana/interface`'s `externalDataHash` directly never passes through
`transact.ts`, so its refusal was unpinned: nothing failed if that function were
"simplified" to mirror `program-libs/interface`'s cast, which would put a hash
over a shortened preimage back into TypeScript with every suite still green.
`interface/test/interface.test.ts` now pins it, refusing each of the four
prefixes past `0xffff` with `INTERFACE_INVALID_INTEGER` naming the overflowing
prefix, including a second-output case so the index in the name is load-bearing,
and accepting the inclusive bound at `0xffff`.

One layering note stays open, and it is a naming question rather than a
behaviour gap. The interface layer reports the overflow as an integer-range
failure naming the field, while the SDK layer above it reports Rust's two named
variants. Both refuse the same inputs, and no input reaches the interface code
through the SDK without meeting the SDK's check first, so the taxonomies never
disagree on an outcome. Aligning them would mean either giving
`@zolana/interface` overflow variants its Rust counterpart does not have, since
`program-libs/interface` truncates and has no error to mirror, or routing every
caller through the SDK. Neither is this row's work, and the checklist's TypeScript
pointer for T21 aims at `interface/src/external-data-hash.ts` where the mirroring
code is `transact.ts`.

## T23, the public leg: PARITY

The recorded finding was right about the direction but understated the scope.
Rust's `public_amounts()` returns three field elements and enforces a protocol
rule while doing it (`spp_proof_inputs.rs:127-160`): the SPL asset is read off
the input and output notes, two distinct non-SOL mints are
`MultiplePublicSplAssets`, and none is `MissingPublicSplAsset`.

TypeScript returned `{ sol?: bigint; spl?: bigint }`: the two raw amounts, no
asset, no rule. The rule did exist, but in `@zolana/client`, as
`findPublicSplAsset` in `prover/assembly.ts`, with the field encoding done
separately at each of the two call sites. Two consequences, and the second is
the one that makes this a divergence rather than a layering preference. A caller
of `@zolana/transaction` alone, which is a published package whose public API
includes this method, got neither the encoding nor the refusal that the
equivalent Rust caller gets. And one protocol rule had two homes, which is the
defect T31 records in its own area.

`SppProofInputs.publicAmounts()` now returns `{ sol, spl, asset }` as `Bytes32`
and refuses through the same two error codes at the same point Rust does. The
client consumes the three fields; `findPublicSplAsset` is gone. That the
`prover-edge-cases` oracle still passes untouched is the evidence that the moved
computation produces the identical witness values, including the SOL-only cases
where the asset field must stay zero.

The confidential-tag half of this row was settled by ruling (`verify_first` and
`amend_both`) and is not relitigated here.

## T28, the last clause: PARITY

Two clauses were already settled, one of them by the ruling declining to take
it. The third, refusing a zone data hash at or above the BN254 modulus, is
closed here.

The refusal already happened, because `internal.ts` checks every input against
`BN254_MODULUS` before hashing, but it arrived as `TRANSACTION_KEYPAIR`, and
`TRANSACTION_POSEIDON` was declared in the code set and produced by nothing.
Rust reaches Poseidon two ways, and they report differently: through
`zolana_keypair`, which yields `TransactionError::Keypair`, and directly through
`light_poseidon` in `utxo.rs:12-18`, which yields `TransactionError::Poseidon`.
Only the UTXO commitment takes the second route. TypeScript now splits the same
way: `commitmentPoseidon` for the three commitment hashes, `poseidon` for
everything else, including the owner hash, which Rust routes through
`zolana_keypair::hash::owner_hash` (`utxo.rs:174`) and which therefore keeps the
keypair code.

[`t28-close.md`](t28-close.md) anticipated this clause being taken "at the
supplying call" rather than at hashing time. That form is declined, and the
reason is parity itself: Rust refuses at hash time, so moving the TypeScript
refusal to the constructor would make TypeScript reject at a point Rust accepts.
It would be the stricter-than-Rust failure this port has already been caught by
once. If the owner wants the earlier refusal it has to land in both languages,
and the Rust half is outside this worker's scope.

## T29, `zone_authority.rs`: PARITY

Three differences, of which two were real.

Not real: Rust calls `check_canonical_dummy()` on every input
(`zone_authority.rs:60`) and TypeScript does not. TypeScript's `ProofInputUtxo`
constructor runs the same check (`utxo.ts:247`) and its fields are readonly over
a defensive copy, so a value in hand cannot have gone non-canonical since. Rust
needs the recheck because its struct fields are public and mutable; its own
test mutates `inputs[0].utxo.asset` in place.

Real: `prepareZoneAuthority` took `publicAmounts` as a parameter and passed it
through unexamined, where Rust derives it from the external data and gets the
asset rule with it. And the prepared form did not carry the external data at
all, though the proof and the on-chain recomputation both need it. The builder
now takes the external data Rust takes and derives the shape and the amounts
through `SppProofInputs`, so the authority rail and the owner-signed rail cannot
drift apart on either.

Unrelated and still open: the rail accepts all ten SPP shapes while only four
zone-authority verifying keys exist, recorded in
[`zone-authority-shape-narrowing.md`](zone-authority-shape-narrowing.md) and
queued for the client worker. Nothing here changes it in either direction.

## T31, `lib.rs`: PARITY

The wire type prefixes were genuinely fixed before this branch: `TRANSFER`,
`SPLIT`, `MERGE`, and `TRANSFER_PLAINTEXT` are declared once, beside the reader
and writer that enforce them (`serialization/codecs.ts:30-33`), used there
(`:565`, `:695`, `:719`, `:1252`), and re-exported from the root (`index.ts:92`).
No `SPLIT_TYPE_PREFIX` and no bare literal survive.

A second instance of the same defect did survive, and is closed here. The root
declared `export const VIEW_TAG_LEN = 32` where Rust re-exports
`zolana_keypair::constants::VIEW_TAG_LEN` (`lib.rs:39`). The value had two homes
across two packages, and a change to the view tag length in the key material
would not have reached this root. It is now a renaming re-export of the keypair
constant, which keeps the Rust-facing spelling and leaves one declaration.

## S01, `smart-account-client/src/lib.rs`: stays DIVERGENT

Verified twice, by two workers reading independently and reaching the same
verdict, so the residual is real rather than an artifact of one reading.

On every input both languages accept, the bytes agree. The PDAs, the five create
instructions, and the execute fixture are pinned against the Rust source in
`sdk-libs/ts/smart-account-client/test/vectors.test.ts`, and the export surface is
pinned against every `pub const` and `pub fn` in `lib.rs` by `exports.test.ts`.

The row stays adverse because TypeScript refuses inputs Rust accepts, which is a
divergence in the same way laxness is. Rust's builders are infallible by
signature and carry no size or content checks, while TypeScript enforces the
1232-byte instruction and payload limits, rejects an empty signer set, a
threshold of zero or above the signer count, and duplicate signer keys on both
the create and execute paths. The two also part ways on one overflow: an inner
instruction whose data reaches `0x10000` is truncated by Rust's `as u16` cast and
refused by TypeScript. Where both refuse, at more than 255 compiled accounts,
outer signers, or inner instructions, Rust panics through `checked_u8` and
TypeScript throws a typed error, so the outcome agrees and the reported shape
does not.

Nothing here is closable from `sdk-libs/ts/` in a direction worth taking. The
mechanical fix is to delete the TypeScript guards, which would make the port
accept oversized payloads and silently truncate an oversized inner instruction,
the same trade the T21 ruling rejected for the external-data prefixes. The
alternative is a Rust change, giving those two builders fallible signatures and
stable error codes, which is outside this scope. The row needs an owner ruling
of the same kind T21 got, and the note in `authority-rulings.md` leaving the S01
size question open is still the current state.

Three claims on the row are stale and were not reproducible at HEAD. The
1232-byte enforcement exists (`instructions.ts:33`, `:192-203`, `:283-290`), the
exact execute fixture exists (`vectors.test.ts:106-143`), and the export surface
is pinned (`exports.test.ts:27-49`). A fourth, that Rust casts where TypeScript
rejects indexes above 255, describes a real difference in error mechanism but not
in policy: both refuse that input.

## Handoff to the `sync.ts` / `codecs.ts` worker

Nothing blocking. Two observations from reading those files:

1. `decryptTransactions` commits through a single `Wallet._replace` at
   `sync.ts:910`. The new atomicity test in `wallet-sync.test.ts` depends on that
   staying the shape; splitting the commit into incremental writes would make a
   failed sync half-apply, which is a behaviour change against Rust rather than a
   refactor.
2. `decryptTransactionsWorkerEquivalent` is dispositioned as a platform
   difference, not as owed work, on the reasoning in the T16 section above.

## Anything nobody has recorded

- **`TRANSACTION_POSEIDON` was declared and unreachable.** The Rust oracle has
  pinned `Poseidon -> TRANSACTION_POSEIDON` in its error table all along
  (`transaction-parity-v1.json:571-575`), so the code set and the oracle agreed
  while no code path produced it. An error code that the oracle pins but nothing
  raises is worth grepping for across the other packages; the variant table test
  compares names and displays, not reachability.
- **`public-exports.md` is behind the shipped root.** It declares neither
  `prepareZoneAuthority` nor `VIEW_TAG_LEN`, both of which the root exports, and
  nothing in `sdk-libs/ts/config` reads the manifest, so it cannot fail. Its
  `PublicAmounts` entry is updated here to the new shape, but the manifest is
  documentation that drifts silently, which is the property the T17/T26/T30
  allowlist clause exists to fix.
- **The client had a third copy of the field encoding.** `signedField` in
  `prover/assembly.ts` reduces a signed amount into the BN254 field, duplicating
  `signedToField` in `@zolana/transaction`. Its two public-amount call sites are
  gone now, but the function remains and other callers may use it. Worth checking
  whether it should become a re-export.
