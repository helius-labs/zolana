# Interface spec conflicts: I07, I19, I10, I22

Read-only investigation of the four `BLOCKED` interface rows, at HEAD
`676595b20e05588121f29f2fa3e96f7f38ac51da`. No code, test, fixture, or spec file
was changed. The four rows form two clusters: I07 and I19 on the deposit
instruction, I10 and I22 on the protocol-config update contract.

Headline for the protocol owner: **three of the four rows answer themselves.**
Three findings could be satisfied only by making the code match the spec, and in
all three cases that means redeploying `programs/shielded-pool`, which is out of
scope for this port: the deposit payload shape, the deposit account set, and the
protocol-config update granularity. No option in either cluster touches a
circuit, so **no verifying-key rotation and no proving-key rotation is at stake
anywhere in this document.** Deposit carries no proof and protocol config is
plain account state.

Exactly one live decision remains: which 32-byte value a deposit writes as the
output's discovery tag. That one is settable in the SDK alone.

## Method and confidence

Everything under "What each layer does" was read directly at the cited line.
Statements labelled *Inferred* are conclusions drawn from those readings and are
marked as such. No tests were run; no validator or indexer was started.

---

## Cluster A: the deposit instruction (I07, I19)

### I07 in one sentence

`program-libs/interface/src/instruction/instruction_data/deposit.rs` defines a
deposit payload of `view_tag`, `owner`, `blinding`, a single `amount`, optional
`utxo_data`, and optional `memo`, while `docs/spec.md:1449` defines a payload of
`owner`, `owner_hash`, `blinding`, a `public_sol_amount` / `public_spl_amount`
option pair, `data_hash`, and `utxo_data`, with no memo.

### I19 in one sentence

`program-libs/interface/src/instruction/builders/deposit.rs` builds a six-account
(SOL) or seven-account (SPL) instruction, while `docs/spec.md:1441` lists two
accounts, and the two documents disagree on the zone tag and on which key
supplies the discovery tag.

### What each layer does

**The program.** `programs/shielded-pool/src/instructions/deposit/` is the
authority, and it implements the interface layout, not the spec's.

- `processor.rs:39` deserializes `DepositIxData` with
  `wincode::deserialize_exact`, so a payload of the spec's shape is rejected
  outright rather than partially accepted.
- `processor.rs:40-42` requires `accounts.len() >= 3`; `process_zone_deposit`
  requires `>= 4` at `processor.rs:64-66`. The spec's two-account table cannot
  satisfy either.
- `account.rs:41-114` consumes, in order: `tree`, `depositor`, then
  `zone_config` when zone, then either three SOL accounts (`system_program`,
  `sol_interface`, `user_sol`) or four SPL accounts (`user_token`, `vault`,
  `registry`, `token_program`), then the program's own account, and rejects a
  non-empty tail at `account.rs:112-114`. The SOL / SPL branch is selected by
  remaining account count at `account.rs:62`, not by an option pair in
  instruction data.
- The asset is derived from the accounts, never from the payload:
  `account.rs:104` returns all-zero for SOL and `account.rs:171` reads the mint
  out of the `SplAssetRegistry` account for SPL.
- A single `amount` carries the value, and zero is rejected at
  `processor.rs:92-94`. There is no `public_sol_amount` / `public_spl_amount`
  pair and therefore no "exactly one is `Some`" check to implement.
- `owner` in the payload is the recipient `owner_hash`. `processor.rs:116` hashes
  it with the padded blinding into `owner_utxo_hash`. The recipient's signing
  pubkey never enters the instruction.
- **The program does not read `view_tag`.** It is deserialized at
  `processor.rs:39`, copied into `DepositParams` at `processor.rs:50`, and copied
  unchanged into the output slot the event carries at `deposit/event.rs:44`. No
  validation, no derivation check, no binding to any other field.
- The trailing program account is there because the program calls itself to write
  the event (`deposit/event.rs:60`, `emit_general_event`). The spec's own check 7
  (`spec.md:1483`) calls for that self-call but its account table omits the
  account the call needs.

**The interface crate.** `instruction_data/deposit.rs:19-40` declares
`DepositIxData` in the order `view_tag`, `owner`, `blinding`, `amount`,
`utxo_data`, `memo`, giving a 105-byte minimum; `ZoneDepositIxData` at
`:57-79` adds `zone_data_hash` and a `u16`-prefixed `zone_data` for a 139-byte
minimum. Tags come from `program-libs/event/src/tag.rs:4` (`DEPOSIT = 1`) and
`:18` (`ZONE_DEPOSIT = 15`). `builders/deposit.rs:50-67` builds
`[tree(w), depositor(w,s)]`, then for SOL `[default pubkey, sol_interface(w),
depositor(w)]` and for SPL `[user_token(w), vault(w), registry, token_program]`,
then the program account. The event type that carries the tag is
`program-libs/event/src/output_utxo.rs:11`, field name `view_tag`.

**The Rust SDK.** `sdk-libs/wallet/src/actions/deposit.rs:49-63` sets
`owner = recipient.owner_hash()`, a fresh `blinding`, and
`view_tag = request.recipient.viewing_pubkey.x()`. That value is the
`recipient_bootstrap_view_tag`: `sdk-libs/keypair/src/viewing_key.rs:237-239`
defines it as exactly `self.pubkey().x()`. The signing-pubkey tag the spec asks
for exists in the same crate as
`ShieldedAddress::confidential_view_tag()` (`sdk-libs/keypair/src/shielded.rs:29`,
resolving through `pubkey.rs:146-151`) and is simply not used by the deposit path.

**The TypeScript port.** `sdk-libs/ts/interface/src/codecs/index.ts:80-112`
encodes and decodes the interface field order byte for byte, including the
`u16`-prefixed byte vectors at `:72-78`.
`sdk-libs/ts/interface/src/instructions/index.ts:161-201` reproduces the Rust
builder's account list, including the zone-authority insertion at `:168-170` and
the trailing program account at `:185`. `sdk-libs/ts/wallet/src/deposit.ts:87`
sets `viewTag: params.recipient.viewingPublicKey.x()`, matching Rust exactly.
Tags agree: `sdk-libs/ts/interface/src/index.ts:112` and `:126`.

The two SDKs agree with each other and with the program on field order, byte
lengths, tag numbers, the account list, and the tag value they choose.

### What reads the tag

This is the question the row turns on, so it is worth stating end to end.

1. The program writes the caller's `view_tag` into the output slot unread
   (`deposit/event.rs:44`).
2. Photon persists it per output at
   `services/photon/src/ingester/persist/rings_transactions.rs:113` into the
   indexed `view_tag` column, indexed at
   `migration/migrations/rings/m20260616_000001_add_rings_tables.rs:253`.
3. `services/photon/src/api/method/rings/get_shielded_transactions_by_tags.rs:185`
   filters outputs by `po.view_tag IN (...)`, which is the only path by which a
   wallet finds a deposit.
4. Both wallets query with a tag set that already contains **both** candidate
   values. `sdk-libs/wallet/src/wallet_sync.rs:314` adds the signing-pubkey
   confidential tag and `:322` adds the bootstrap tag;
   `sdk-libs/ts/wallet/src/sync.ts:116` and `:119` do the same.
5. `program-tests/test-utils/src/test_validator_asserts/deposit.rs:53-54` waits
   for the indexed UTXO keyed on `data.view_tag`, so the assertion harness
   confirms discovery runs through this field.

So the tag is not decorative: it gates discovery. But the depositor picks its
value with no constraint from the program, and both SDKs already scan both
candidate values.

### Verdict

**The spec is wrong on the payload, the accounts, and the zone tag; the SDK
diverges from the spec on the discovery tag.**

Three findings are stale documentation with no implementation anywhere:

- The payload shape at `spec.md:1449-1467`. No component builds, encodes, or
  accepts it. The program would reject it.
- The account tables at `spec.md:1441-1444` (two accounts) and `spec.md:1622-1626`
  (three accounts). Both are strictly short of what `account.rs` consumes, and
  both omit the self-CPI program account the spec's own check 7 requires.
- `spec.md:1230` lists `zone_deposit` at Tag 1 while `spec.md:1243` and the
  section header at `spec.md:1616` both give Tag 15. Code uses 15. Line 1230 is
  a stale duplicate row inside a single table, contradicted twice in the same
  document.

One finding is a real, current disagreement: `spec.md:1450-1452` and
`spec.md:1495-1498` make the deposit's discovery tag the recipient's **signing**
pubkey, consistent with the default-zone rule at `spec.md:373` that "every output
is tagged by its owner pubkey". Both SDKs write the recipient's **viewing**
pubkey x-coordinate instead.

*Inferred:* the divergence is invisible inside this repository, because the
zolana wallets scan both tags. It becomes visible at the interoperability
boundary. A third-party wallet or indexer implemented to `spec.md:373` would scan
owner pubkeys only and would silently miss every deposit made by a zolana SDK
depositor. That is a discovery failure with no error surface, which is the worst
shape for this class of bug.

*Inferred:* the fix direction is unusually cheap. `ShieldedAddress` already
carries the signing pubkey and already exposes `confidential_view_tag()` in both
languages, so the depositor needs no new input. Because both sync paths already
query the signing tag unconditionally, switching the deposit tag needs no sync
change and loses no already-deposited UTXO: old deposits stay findable under the
bootstrap tag, which both wallets also still query.

### Options for I07 and I19

**Option A1: amend the spec to the implemented deposit, keep the viewing-key tag.**
Rewrite `spec.md`'s `DepositIxData` and `ZoneDepositIxData` to the interface field
order, replace both account tables with the account sets `account.rs` consumes,
delete the stale Tag 1 row at `spec.md:1230`, document the memo field, and record
that the discovery tag is the recipient's viewing pubkey x-coordinate with the
default-zone owner-pubkey rule at `spec.md:373` carrying an explicit deposit
exception. No program change. No circuit change. No key rotation. Releases both
rows to ordinary parity work.
*Consequence:* the default zone gains a second discovery rule that every external
integrator must learn, and a spec-conformant third-party wallet still needs the
extra tag in its scan set.

**Option A2: amend the spec to the implemented layout and accounts, and change
the two SDKs to tag deposits with the signing pubkey.**
Same spec amendment as A1 except the discovery tag, plus a one-value change at
`sdk-libs/wallet/src/actions/deposit.rs:51` and
`sdk-libs/ts/wallet/src/deposit.ts:87` from `viewing_pubkey.x()` to the
signing-pubkey confidential tag. No program change, no circuit change, no key
rotation, and no sync change, because both sync paths already query that tag.
*Consequence:* restores the single default-zone rule at `spec.md:373`, so an
integrator that reads only that rule interoperates. Costs a fixture refresh
wherever a deposit vector pins the tag, at least
`sdk-libs/ts/wallet/test/vectors/deposit-vector.test.ts:108`,
`sdk-libs/ts/wallet/test/wallet.test.ts:90`, and
`sdk-libs/wallet/src/actions/deposit.rs:302`. Deposits already on chain stay
discoverable under the old tag.

**Option A3: change the program to the spec.**
Requires a new payload struct, a new account layout, reinstating the
`public_sol_amount` / `public_spl_amount` pair, and adding the recipient signing
pubkey to instruction data. **This requires deploying `programs/shielded-pool`,
which the protocol owner has ruled out for this port.** It needs no verifying-key
rotation, since deposit is proofless, but the deployment alone settles it.
*Consequence:* not available. Recording it so the record shows the direction was
considered.

*Recommendation for the ruling:* A3 is closed by the deployment ban, so the
payload, account, and tag-number findings are spec amendments either way and need
no judgment call. The only judgment needed is A1 against A2, and it is narrow:
whether the deposit rail keeps its own discovery tag or rejoins the default-zone
owner-pubkey rule. A2 is the cheaper of the two to get wrong in the other
direction, because it needs no program change and no back-compatibility window.

---

## Cluster B: the protocol-config update contract (I10, I22)

### I10 in one sentence

`program-libs/interface/src/instruction/instruction_data/protocol_config.rs:21-29`
defines `UpdateProtocolConfigData` as a seven-variant enum that changes exactly
one field per instruction, while `docs/spec.md:1235` says the instruction
"rewrites every authority and flag".

### I22 in one sentence

`program-libs/interface/src/instruction/builders/protocol_config/mod.rs:51-74`
builds precisely that single-field instruction, so the builder row inherits I10's
conflict and has no independent finding.

### What each layer does

**The program.**
`programs/shielded-pool/src/instructions/protocol_config/update.rs:23-37` matches
on the enum and assigns exactly one field. Nothing else in `ProtocolConfig` is
written. Access control is at `update.rs:22` through
`load_and_validate_protocol_authority_mut`, which requires the caller to sign
(`protocol_config/loader.rs:76-78`) and to equal the stored `protocol_authority`
(`loader.rs:80-82`).

One property of the single-field form is worth recording: the
`ProtocolAuthority` variant additionally requires the **incoming** authority to
sign, at `update.rs:15-20`, rejecting the instruction unless the extra signer
matches the address being written.

Creation is the only full write. `protocol_config/create.rs:44-53` sets all seven
mutable fields, and `create.rs:23-25` requires the fee payer to equal the
`protocol_authority` it is about to write.

**The interface crate.** `state/protocol_config.rs:9-18` declares the account as
a discriminator plus four authorities plus three `u8` flags, size asserted at 132
bytes (`:77`). The seven update variants at
`instruction_data/protocol_config.rs:22-28` cover all seven mutable fields, so
every field the spec says a full rewrite touches is reachable one at a time.
`builders/protocol_config/mod.rs:58-72` builds
`[authority(s), protocol_config(w)]` and appends the incoming authority as a
third signer only for the `ProtocolAuthority` variant (`:62-67`).

**The Rust SDK, and the operator tool.** `xtask/src/update_protocol_config.rs:121-133`
collects one enum value per flag the operator passed and
`:239-245` builds one instruction per collected value, submitting them together.
*Inferred:* this is the deployed answer to multi-field updates. Several
single-field instructions in one transaction are atomic on Solana, so the
operator already achieves a full rewrite without a full-rewrite instruction.

**The TypeScript port.**
`sdk-libs/ts/interface/src/instructions/index.ts:283-326` mirrors the enum as a
seven-member discriminated union, writes variant indices 0 through 6 in the same
order as the Rust enum, and appends the incoming authority as a third signer for
`protocolAuthority` only (`:300`, `:324`). The account codec at
`sdk-libs/ts/interface/src/codecs/index.ts:662-686` reads the 132-byte account in
the state struct's field order. This matches Rust exactly.

### Can a partial update reach a state a full write could not?

This is the question the row said decides between a documentation gap and a live
defect. **No.**

Verified: no cross-field validation exists anywhere. `update.rs:23-37` performs a
bare assignment per variant. `create.rs:68-82` performs seven bare assignments.
Each authority gates a different instruction and each check reads only its own
field (`state/protocol_config.rs:40-62`); each flag is read only by its own
`allows_*` accessor (`:64-74`).

*Inferred:* with seven independent fields, no coupling, and one update variant per
field, the states reachable by a sequence of single-field updates are exactly the
full product of per-field values, which is the same set a full rewrite could
reach. There is no torn or half-migrated configuration, because there is nothing
for a configuration to be half-way through.

One asymmetry runs in the **opposite** direction from the question asked, and is
worth recording because it is easy to misread as supporting the defect reading.
The three flags are `u8`, and readers test non-zero (`state/protocol_config.rs:65`,
`:69`, `:73`). The update path writes `u8::from(bool)` at `update.rs:29`, `:32`,
and `:35`, so it can only ever produce `0` or `1`. Creation, by contrast, casts
raw instruction bytes with `bytemuck::try_from_bytes` at `create.rs:13-14` with no
range check, so **`create` can write a flag byte such as `7` that no `update` can
produce.** Behavior is unaffected, since every reader tests non-zero, and the
TypeScript decoder handles it correctly with `nonzeroBool`
(`codecs/index.ts:680-684`). It is a creation-side laxity, not an update defect,
and narrowing it would be a program change.

### Verdict

**The spec is wrong, and only loosely wrong.** It never defines an
`UpdateProtocolConfigData` payload at all, so there is no layout conflict to
resolve. The entire conflict is three prose statements that describe the
instruction's scope imprecisely: `spec.md:1235` ("rewrites every authority and
flag"), `spec.md:1151` ("rotates every authority"), and `spec.md:142` ("Rotate the
protocol config authority and the role authorities").

*Inferred:* read charitably, all three are true of the instruction's **reach**
(it can change any authority or flag) and false only about its **granularity**
(one per call). This is a documentation gap. Nothing is broken, no state is
unreachable, and the single-field form is strictly safer than a blind full
rewrite, because `update.rs:15-20` prevents rotating `protocol_authority` to an
address that cannot sign, which is the one irrecoverable mistake in this
instruction.

### Options for I10 and I22

**Option B1: amend the spec to the single-field contract.**
Restate `spec.md:1235` as a single-field update naming the seven addressable
fields, note that multi-field changes compose several instructions in one
transaction as `xtask/src/update_protocol_config.rs:239-245` does, and record the
incoming-authority co-signature requirement for the `ProtocolAuthority` variant.
Soften `spec.md:1151` and `spec.md:142` to match. No program change, no circuit
change, no key rotation. Releases I10, and I22 with it, to ordinary parity work.
*Consequence:* the spec gains one paragraph, and the safety property at
`update.rs:15-20` becomes documented rather than incidental. This is the option
the evidence points to.

**Option B2: B1 plus an SDK-level batch helper.**
Same amendment, plus a documented helper in the SDKs that takes a set of field
changes and returns the instruction list, mirroring what xtask already does
internally so external operators do not each rediscover it. No program change, no
key rotation.
*Consequence:* adds public SDK surface in two languages during a port whose goal
is parity, and adds a fixture obligation for the emitted instruction order.
Reasonable only if operator ergonomics is a goal for this release.

**Option B3: add a full-rewrite instruction or variant to the program.**
Would make `spec.md:1235` literally true. **This requires deploying
`programs/shielded-pool`, which the protocol owner has ruled out for this port.**
No verifying key or proving key is involved, so the deployment is the whole cost.
*Consequence:* not available. It would also need the incoming-authority
co-signature rule from `update.rs:15-20` carried across explicitly, or the full
rewrite would reintroduce the ability to brick governance by rotating
`protocol_authority` to an address nobody controls.

*Recommendation for the ruling:* B3 is closed by the deployment ban, and B1
against B2 is a scope question rather than a protocol question. I10 and I22 can
be released together on B1 alone.

---

## What this document does not decide

- It records no checklist edits. `review-checklist.md` was deliberately left
  untouched; the row transitions belong to the checklist owner.
- Two adjacent divergences surfaced during the deposit reading and belong to other
  rows, not to I07 or I19. `spec.md:1546-1552` types `tx_viewing_pk` and `salt` as
  `Option`, while `program-libs/event/src/lib.rs:27` and `:31` are fixed-size
  zeroed arrays; and `spec.md:1568-1576` names the output slot's tag field `owner`
  while `program-libs/event/src/output_utxo.rs:11` names it `view_tag`.
  `program-libs/event/src/proofless.rs:16` also carries a `memo` the spec's
  `ProoflessOutput` does not list. These live in the event crate and should be
  ruled on with whichever row owns it.
- The protocol-config field ordering difference between `spec.md:1150-1164`
  (flags interleaved after their authority) and
  `program-libs/interface/src/state/protocol_config.rs:9-18` (authorities first,
  then flags) affects the account layout, which is I31's file, not I10's.
