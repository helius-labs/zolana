# Ring State On One Primitive

Design document, 2026-10-06. Companion to
[ring-policy-design.md](ring-policy-design.md), which describes the ring as
built. This document describes the change.

## Abstract

A custom ring keeps provable state in four primitives: list entries, a key
registry with its own indexed Merkle tree, a spend record with its own
record kind, and rows inside the hash-pinned rule table. The key registry
and the spend record are list entries with different names: a namespace
PDA owner, an address derived from a domain and a member, a version, a
content commitment and a blinding. Each carries its own instruction,
circuit half, indexer projection, client reader and failure modes.

This change folds the key registry into the reserved `Escrow` list and the
spend record into a namespace-only `Spend` list. The entry primitive gains
two abilities it needs for that, a content opening in the circuit and an
entry update inside a transfer. Everything the program reads in plaintext,
the ring config, the policy config with its rule table and source map, the
co-signer, the delegate, the pause flag and the volume windows, stays in
PDAs. Rules stay one hash-pinned blob. The schema set stays sealed.

The document fixes the target shape, the transition per state kind, what
is removed, what it costs per transfer, the order of work, and the designs
considered and not taken.

## Terminology

| Term | Definition |
|---|---|
| Entry | One `(list, member)` fact as a zero-amount SPP data UTXO under the namespace PDA, see [the entry](ring-policy-design.md#the-entry-a-keyed-compressed-account). |
| Fact | One authenticated Present or Absent claim about an entry inside the policy circuit, one answer slot. |
| Content | The value an entry commits beside its member through `content_hash`. Unit content commits to zero. |
| Content opening | The circuit recomputing `content_hash` from witnessed fields of a Present fact and using those fields. |
| Entry update | A transfer that spends an entry at version `v` and emits the same address at `v + 1` as two slots of its own SPP transact. |
| Key registry | The indexed Merkle tree of height 40 holding `Poseidon(member, next, Poseidon(nullifier_pk, ciphertext_hash))` leaves, with `KeyRegistryRoot` and its 32-root history. Removed by this change. |
| Spend record | The namespace-owned data UTXO keyed by `SPEND_ADDRESS_DOMAIN` that carries a member's velocity counters commitment. Replaced by a `Spend` entry. |
| Rule-visible list | A list a rule may name, one of the eight ids the source map and the rule mask encode. |
| Namespace-only list | A list the circuit reads at a fixed id under the ring's own namespace, outside the source map and the rule mask. |

## State kinds and where they live

| State | Today | After |
|---|---|---|
| Allow, Block, Frozen, Approval | entry list, authority-written | unchanged |
| RingViewing, Recovery | entry list, member-written | unchanged |
| Reader | entry list and `ReadAccessRecord` PDA | one of the two, decided with the RPC |
| Registered nullifier keys | key registry tree, `register_key` circuit, `KeyRegistryRoot` | `Escrow` entry, content `Poseidon(nullifier_pk, ciphertext_hash)` |
| Velocity counters | spend record kind, `register_spend`, `getRingSpendRecord` | `Spend` entry, content `Poseidon(window, counters_commitment)` |
| Inline assets, velocity rows | rows in the rule table | unchanged, see [Asset](#asset-stays-open) |
| Rule table, source map | `PolicyConfig` PDA, hash-pinned | unchanged |
| Ring config, co-signer, delegate, pause, volume windows | PDAs | unchanged |

## The entry primitive, two extensions

Both extensions are needed by the two merges and by nothing else today.

**Content opening.** A fact currently binds `content_hash` into the entry
`data_hash` and never looks inside. A fact over a list whose rule needs the
value additionally witnesses the content fields and asserts
`content_hash = Poseidon(fields...)`. One Poseidon preimage per such fact.
The opening is only meaningful for Present facts, an Absent fact has no
content. The list decides the field list, the circuit has one opening per
content-bearing list it reads.

**Entry update.** The spend record already spends its predecessor and
emits its successor as the last input and the last output of the
transfer's SPP transact, with the namespace PDA raised as an owner signer
inside the program's CPI. That becomes the general shape. A transfer may
carry one entry update: exactly one input slot opens to an entry at
`(list, member)` version `v` and exactly one output slot opens to the same
address at `v + 1` with new content. Every other slot opens to a different
owner than the namespace. The circuit fixes the new content, the program
raises the PDA signature. `update_entry` remains the path for lists a
mutation instruction writes, the entry update is the path for lists a
transfer writes.

A list declares which path writes it. `check_mutator` refuses
`update_entry` on a list the transfer writes, and the circuit refuses an
entry update on any other list.

## Escrow absorbs the key registry

### Today

A member registers once. `register_key` carries a proof from
`KeyRegisterCircuit` that `nullifier_pk = Poseidon(secret)`, that the
secret is sealed to the auditor key under `CRING/nfk1`, and that inserting
`Poseidon(nullifier_pk, ciphertext_hash)` under the member into the indexed
tree moves `registry_old_root` to `registry_new_root`. The program checks
the transition against `KeyRegistryRoot` and advances the root history.

With `key_escrow` set, the policy circuit opens one registry leaf per UTXO
output whose owner is not the namespace (`key_escrow.go`), the audited
deposit circuit opens one per recipient, and both bind the root the program
reads from the history by an index the instruction carries. More than 32
registrations between proving and landing make a proof stale
(`StaleKeyRegistryRoot`). The `Escrow` list, id 8, is declared
member-written with unit content and has no reader or writer in any
component.

### After

```
  +== 1. Member: register =======================================+
  | 1.1 Seal nullifier secret to the auditor key                 |
  | 1.2 Prove nullifier_pk = Poseidon(secret) and the seal       |
  | 1.3 Send create_entry(Escrow, member, content_hash, proof)   |
  |     with the sealed envelope as a tagged message             |
  +==============================================================+
         |
         +---------------> +== 2. Ring program: create_entry ==================+
                           | 2.1 Writer check: signer owner tag == member      |
                           | 2.2 Verify the seal proof against the pinned      |
                           |     auditor key, bind content_hash                |
                           | 2.3 Require exactly one envelope message          |
                           | 2.4 CPI SPP: claim the address, insert version 0  |
                           +===================================================+

  +== 3. Any transfer with key_escrow set =======================+
  | 3.1 Per UTXO output not owned by the namespace: Present      |
  |     fact on (Escrow, output owner), content opened to        |
  |     (output nullifier_pk, ciphertext_hash)                   |
  | 3.2 Fact roots come from the transact's tree slots           |
  | 3.3 Revocation target per fact, as for every fact            |
  +==============================================================+
```

The `Escrow` entry has content `Poseidon(nullifier_pk, ciphertext_hash)`,
the value `RegisteredKey::hash` computes today. The envelope, ephemeral key
and ciphertext publish as one message tagged under the namespace in the
registration transaction, the auditor and the delegate recover the secret
from it exactly as from the registry entry today.

Registration, numbered:

1. The member derives `nullifier_pk` and seals the secret to the auditor
   key as today.
2. The member proves the seal with a reduced `KeySealCircuit`: the range
   checks, the curve check, `nullifier_pk = Poseidon(secret)`, the
   envelope, and `content_hash = Poseidon(nullifier_pk, ciphertext_hash)`.
   The public input chains `member`, `nullifier_pk`, the auditor and
   ephemeral key halves, `ciphertext_hash` and `content_hash`. The two
   registry roots, the low leaf, both height-40 paths and `new_index`
   leave the circuit.
3. The member sends `create_entry` for `Escrow` with the proof. The program
   runs the existing writer check, verifies the proof against the pinned
   auditor key, requires exactly one envelope message, and claims the
   address through SPP. A second registration is a double claim SPP
   refuses, which is the `AlreadyRegistered` check for free.

Transfer and deposit checks:

- The policy circuit replaces `OutputKeys [NOutputs]registry.KeyOpening`
  and `KeyRegistryRoot` with `EscrowFacts [NOutputs]ListFactWires`, fixed
  to list id 8, mode Present, member equal to the output owner hash, and
  content opened to `(output.nullifierPk, ctHash)`. The slots are separate
  from the rule answers, so `ANSWER_SLOTS` and `GUARANTEED_LOAD` do not
  move. Each escrow fact is enabled exactly when the output is a UTXO, the
  escrow flag is set and the owner is not the namespace. The namespace's
  own zero key stays bound by its owner hash as today.
- The public input drops `key_registry_root` and keeps `key_escrow`. Each
  escrow fact adds one revocation target and one packed tree index, in the
  same positions the rule facts use.
- The audited deposit circuit replaces its `Keys [MaxDeposits]KeyOpening`
  the same way and gains the tree slot chain. An audited deposit on an
  escrow ring therefore carries the policy tree accounts and one revocation
  target account per recipient. A deposit on a ring without escrow carries
  neither.
- The delegate rail is unchanged, it already requires `key_escrow = 1`.

Program:

- Removed: `create_key_registry_root`, `register_key`, `KeyRegistryRoot`,
  `RootTransition`, `StaleKeyRegistryRoot`, the registry root index in
  transact and audited deposit instruction data, `load_key_registry_root_mut`.
- Changed: `create_entry` verifies the seal proof when the list is `Escrow`
  and refuses the envelope message on any other list. `set_delegate` no
  longer requires an initialized registry. `check_mutator` refuses
  `update_entry` on `Escrow`, see [rotation](#rotation).

Indexer and clients:

- Photon drops `ring_projection/key_registry.rs` and the two registry
  endpoints. An escrowed key is read as the `Escrow` entry of the member,
  the envelope from the registration transaction's tagged message.
- The Rust `key_registry.rs` and `escrow.rs` and the TS `key-registry.ts`,
  `key-registry-tree.ts` and `key-escrow.ts` reduce to a seal, a
  `create_entry` builder and a fact opening over the existing entry
  lineage walk.
- `custom-rings/key-registry` is deleted.

### Rotation

The registry is append-only, one key per member for life. A member-written
entry is versioned, so a member could rotate its escrowed key with
`update_entry`. The delegate model needs the key that can spend a member's
notes, and every output checks its own nullifier key against the member's
current entry, so a rotation would only strand notes issued under the old
key if the delegate did not hold the old secret, which the auditor
envelope of the old version still gives it. Rotation is therefore safe but
not needed. The first version refuses `update_entry` on `Escrow` to keep
the append-only semantics and the one-registration invariant, and leaves
rotation as a later decision that costs one line.

### Staleness

The 32-root history and `StaleKeyRegistryRoot` go away. An escrow fact
reads any root in its tree's history like every fact, and a registration
between proving and landing changes a state root the proof did not use.
Only a revocation of the member's entry can invalidate the proof, and
revocation does not exist on an append-only list. The retry paths in
`RingTransferSubmission` and `RingTransactionSubmission` lose one trigger.

## Spend absorbs the spend record

### Today

The record is "the second record kind under the namespace PDA". Its
address is `spendAddress(namespace_owner_hash, sender, tree)` under
`SPEND_ADDRESS_DOMAIN`, its `data_hash` commits `(address, sender,
version, window, commitment)` under `SPEND_RECORD_DOMAIN`, and
`register_spend` claims the address at version zero. The transfer pins the
record as the last input and last output, publishes the successor's
opening in a message tagged `SHA256("zolana:spend-record:v1" || namespace)`
with the record in SPP's confidential output format, and the program
reconstructs the commitment from the message. Photon projects the latest
record per member and serves it through `getRingSpendRecord`.

### After

`Spend` is a namespace-only list at id 9. It is never named by a rule and
never sourced from a curator, so it needs no bit in the rule mask and no
slot in the source map, and the eight rule-visible lists stay as they are.
The entry address derivation and the circuit's list id range check already
admit any `u8`. The entry has member equal to the sender's owner hash and
content `Poseidon(window, counters_commitment)`.

Registration is `create_entry` on `Spend`. The program derives the content
from the clock and the zero counters, the member supplies nothing but the
signature. The existing writer check applies, the payer's owner tag is the
member.

The transfer carries the record as the general entry update:

1. The input slot opens to the `Spend` entry of the sender at the latest
   version, content opened to `(window, commitment)`.
2. The output slot opens to the same address at `version + 1`, content
   `Poseidon(window', commitment')` where the circuit fixes `window'` to
   the public `window_index` and `commitment'` to the successor counters.
3. `constrainVelocity` keeps its arithmetic unchanged, same window, caps,
   approval bit. Only `spendRecordFields.dataHash` and `assertRecord` are
   replaced by the entry `data_hash` and the entry update check.
4. The successor publishes through `ListEntry::to_output_data` as plaintext
   output data, the form registration already uses. The opening is public
   today, the confidential format and the tagged record message add
   nothing. The program checks the published bytes against the output
   commitment as it does for every entry.
5. The counters disclosure under the transaction viewing key stays, tagged
   as today, and the compressed policy variant that seals it is unchanged.

Removed: the spend address and record domains and layout in `spend.rs`,
`register_spend`, `getRingSpendRecord` and `ring_projection`'s record
projection, the record message tag, `spend-record-reader.ts`,
`register-spend.ts`, the record half of `velocity.rs` and `velocity.ts`.
`ReadSpendRecord::read_current` becomes the entry lineage read every list
already has, with the same out-of-sync detection through the nullifier PDA.

Kept: `SpendCounters`, `countersCommitment`, the disclosure hash, the
window arithmetic, `RingSpendRecordOutOfSync` renamed to the generic entry
error, and the one-sender rule for windowed transfers.

## Asset stays open

Inline assets and velocity rows could become an `Asset` list whose content
opens to `(cap, cosign_above, above_limit)`, making an asset allowed iff it
has an entry and moving the limits out of the table. That removes the two
table sections, three one-hot count arrays and the "exactly one unguarded
inline rule" builder rule.

It costs one fact per distinct output mint on every ring with an asset
rule, each fact one revocation target account, and the asset set would
move under the list's writer instead of with the rules under the upgrade
authority. The decision waits for the slot and account count per shape
after the two merges above land. Until then the table keeps its rows.

## What stays a PDA, and why

- **Ring config, co-signer, delegate, pause.** The program reads them
  without a proof at every transact. An entry can only be read through a
  fact, which costs a Merkle path pair and a revocation account per
  transfer to replace an account read.
- **Rule table and source map.** One hash-pinned blob under the upgrade
  authority. Per-rule entries would be sixteen facts per transfer, and the
  config authority must not be able to move rules, see
  [rejected designs](ring-policy-design.md#rejected-designs).
- **Volume windows.** Ring-wide deposit and withdrawal counters are
  updated by every public leg in the window. A UTXO counter is spent by
  each of them, so two deposits in one slot conflict on the same version.
  Shared counters stay plaintext program state.

## Per-transfer cost

| Transfer | Facts today | Facts after | Revocation accounts after |
|---|---|---|---|
| Policy ring, no escrow, no window | rule answers | unchanged | unchanged |
| Windowed member transfer | rule answers, record slots | rule answers, one entry update | unchanged |
| Escrow ring transfer | rule answers, 4 registry openings | rule answers, up to 4 escrow facts | rule targets + up to 4 |
| Audited deposit on an escrow ring | registry openings | one escrow fact per recipient | one per recipient, plus policy tree accounts |

A registry opening is one height-40 path. An escrow fact is one height-32
state path plus one height-40 nullifier path and the entry hashes, so the
policy circuit grows by about four state paths on escrow rings and the
deposit circuit by one state path per recipient. The account growth is the
figure to measure against the 64-address limit of a v1 transaction on the
widest shapes before the Escrow merge lands.

## Circuit and key changes

- `ListFactWires` gains optional content fields and an `opened` flag per
  list that needs them, the rule facts keep theirs disabled.
- `CustomRingPolicyCircuit` loses `KeyRegistryRoot` and `OutputKeys`, gains
  `EscrowFacts [NOutputs]`. `RecordWires` becomes the entry update pair.
- `CustomRingDepositCircuit` loses `KeyRegistryRoot` and `Keys`, gains
  escrow facts and tree slots.
- `KeyRegisterCircuit` becomes `KeySealCircuit` without the registry
  insertion. The `registry` Go package is deleted.
- `policy_public_input.rs` drops `key_registry_root`. Escrow facts append
  their revocation targets after the answer targets.
- Every custom ring proving key rotates: policy, compressed policy, delegate
  policy, deposit, and the seal key replacing `custom_ring_register_key`.
  The base audit key does not change. Rotation follows the published
  procedure, one lockfile, one vk regeneration, one S3 version folder.

## Order of work

1. **Escrow.** Circuits, program, indexer, SDKs, one key rotation. Measure
   the account count per shape on an escrow ring first.
2. **Spend.** Circuit entry update, program, indexer, SDKs. If it lands
   within the same rotation window as Escrow, one rotation covers both.
3. **Reader.** Pick the list or the PDA with the RPC owners.
4. **Asset.** Decide on the numbers from step 1.

Each step is its own PR. Program and circuit changes stay separate from
SDK cleanup where the PR size allows.

## Rejected designs

**Generic attestations.** One record kind `(issuer, schema, subject,
data[k], version, expiry)` for every ring state, rules naming
`(issuer, schema)`, config read in the circuit and exported as public
inputs. It removes the eight-list ceiling, the source map and twelve
instructions. It loses to three inputs: circuit meaning cannot live off
chain, so the "which field, which comparison" grammar moves into the rule
table instead of disappearing; every config read becomes a fact and an
account per transfer; and a compliance ring wants a closed, reviewable
feature set, which the sealed schema set is.

**Config in the tree.** Covered above. One fact and one account per
transfer forever to replace two account reads.

**Per-rule entries.** Sixteen facts per transfer.

**A ninth rule-visible list for Spend.** Would need a wider rule mask and
source map and a new row encoding. Spend is read at a fixed id under the
ring's own namespace, which needs neither.

**Keeping the registry tree and only renaming.** Buys nothing. The cost of
the registry is the second tree, its history, its insertion circuit and its
projection, not its name.

## Open questions

- The exact account count per shape on an escrow ring, with the widest
  spend and four escrow facts.
- Whether the audited deposit circuit should share the policy circuit's
  tree slot gadget or take a single tree for its escrow facts.
- Whether `Reader` lives in the list or the PDA. The ring RPC reads the
  `ReadAccessRecord` PDA today (`sdk-libs/ts/src/ring/reader.ts`), the
  list has no reader.

## Acceptance criteria

- `custom-rings/key-registry`, the `registry` Go package, `KeyRegistryRoot`,
  `create_key_registry_root`, `register_key`, `StaleKeyRegistryRoot` and the
  Photon registry projection and endpoints are gone.
- A member registers through `create_entry` on `Escrow`, a second
  registration fails at the address claim, and an escrow ring transfer and
  audited deposit prove every output key against `Escrow` entries.
- A delegate move recovers a member's secret from the registration
  message and spends the member's notes.
- `register_spend`, `getRingSpendRecord`, the record domains and the record
  message tag are gone, a windowed transfer updates the `Spend` entry, the
  cap and approval tests in `velocity_test.go` and `program/tests/policy/velocity.rs`
  pass unchanged in their assertions.
- `ANSWER_SLOTS` and `GUARANTEED_LOAD` are unchanged.
- `vk_fingerprint`, `vk_proving_key_lock` and the TS proving key table pin
  the rotated keys.
