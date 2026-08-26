# Ring policy and records

The policy system mediates between a ring operator who sets transfer rules and
a participant who proves compliance without revealing the transfer. Hold it as
one idea, membership checks move out of program code and into the transfer
proof.

The naive ring stores its lists in accounts and checks the recipient in the
processor. That design's flaw is exposure. The program reads the recipient in
clear and the ring loses anonymity. Instead the ring pins one hash of its
rules, and the transfer proof shows the rules hold against lists in SPP's own
trees.

## The model

Six terms carry the whole design.

- The **rule table** is the compiled `Policy`, a fixed array of at most
  `MAX_RULES` rules built into the ring program.
- A **member** (`Member`) is a field element naming who or what a rule checks.
  Zero is the circuit padding value, never a member.
- A **kind** (`RecordKind`) is a `u8` naming one list. Zero is reserved for
  inline assets.
- A **record** (`Record`) states one `(kind, member)` fact. It lives as a
  zero-amount data UTXO in the SPP state tree.
- The **holder** (`Holder`) of a kind is the party that may mutate its list,
  the ring authority or the member.
- The **pool** is the transfer proof's set of record checks, one slot per
  distinct `(kind, member, mode)` triple the rules name.

A blocklist ring runs through every section below. Its table holds one rule,
`Rule::forbid(Subject::OutputOwner, RecordKind::Block)`. The authority records
Mallory under `Block`. A transfer to Mallory has no witness, its pool slot
cannot show the live record absent. A transfer to Bob proves absence, no
record under his pair exists. After the authority clears Mallory, a transfer
to her proves absence through the cleared record.

## The rule table

`Rule { subject, mode, source, guard }` lives in
`program-libs/ring-policy/src/policy.rs`. A rule checks `OutputOwner`,
`Sender`, or `Asset` for `Present` or `Absent` in one list. The source is a
record kind or an inline asset set. An `AboveAmount` guard passes transfers
below the threshold without a membership check.

`PolicyBuilder::build` runs in const context and panics at compile time on a
table the circuit cannot enforce. Duplicate rules, guarded sender rules, and
zero-valued inline assets fail the build, never a transaction.

`Policy::hash` chains the table domain, `POLICY_VERSION`, the records owner
hash, the rule count, every `Rule::encoded()`, and the inline assets. The
count closes the variable-length preimage. The owner hash ties the table to
one ring's records.

The ring's table is the `POLICY` const in
`custom-rings/interface/src/policy.rs`. Cargo features add rows through
`rule_if`, a build without features compiles an empty table.

`create_policy` pins the table hash into the `PolicyConfig` account together
with the records tree. Only the upgrade authority may sign it, the table is
part of the deployed program. Every transact and record mutation recomputes
`POLICY.hash` and refuses a mismatch, a changed table fails closed.

## Records

Records are standard SPP UTXOs, the derivations are in
[spec.md](spec.md#utxo-hash). `program-libs/ring-policy/src/record.rs` fixes
their shape.

`RecordsOwner::new` derives the owner hash from the ring's `policy_records`
PDA with a zero nullifier secret. Anyone computes record nullifiers, the
record set stays publicly auditable. Spending still requires the PDA's CPI
signature.

`record_seed(kind, member)` gives every pair one deterministic address.
Creating a record claims the address, and the nullifier tree admits each
address once. One lineage per pair, for the life of the tree.

The record version doubles as the UTXO blinding. A member cleared and
recorded again never repeats a `utxo_hash` or a nullifier.

A mutation is a one-input one-output SPP transact built over
`mutation_private_tx_hash`. `create_record` claims the address and inserts the
version-zero UTXO. `update_record` spends the live UTXO and inserts the next
version at the same address. There is no delete, removal is an update to
`Cleared`. Absence therefore has two provable shapes, an address never claimed
or a live record in `Cleared`.

Records publish their bytes in plaintext through `Record::to_output_data`.
Discovery re-derives `data_hash` from the published bytes and compares it with
the on-chain leaf before trusting them.

## Mutation authorization

`RecordKind::holder()` is the single authorization axis. The match is
exhaustive, a new kind does not compile until it declares its holder.
`RingViewing`, `Recovery`, and `Escrow` are member-held, the member signs
their own mutations. Every other kind is authority-held. `check_mutator` in
the ring program enforces the matching signer on every mutation.

## Proving compliance

The wallet builds the pool in `build_pool`
(`custom-rings/sdk/src/witness.rs`), one slot per distinct triple, unused
slots disabled and zero-filled. Presence is an inclusion proof of the record's
`utxo_hash` in the state tree plus a non-inclusion proof of its nullifier.
Absence is a non-inclusion proof of the pair's address, or the same two
proofs over the cleared record.

The public input chains the audit statement with `policy_hash`, `state_root`,
and `nullifier_root` (`custom-rings/interface/src/public_input.rs`). The
program resolves both roots from the history indices in the instruction data
and verifies one proof.

One circuit serves every ring. A rules-free ring proves a zero-length table
with every pool slot disabled. Proof size, account list, and verification cost
do not vary with the table, a transfer reveals none of the checks it passed.

## Adding a list

A new list is one trait impl. The sealed `List` trait in
`program-libs/ring-policy/src/list.rs` fixes the kind, its `Payload` type, and
the holder. Its module doc walks the four steps. The keying, the record shape,
the membership proofs, and the circuit are reused unchanged.

## Pitfalls

- `PolicyConfig.records_tree` must equal the transfer's input tree. The
  transact refuses roots from any other tree.
- A rules-free ring still needs `create_policy`. The transact path loads the
  policy config unconditionally.
- A ring-owned record tree looks equivalent to reusing SPP's trees. It fails
  on maintenance, nothing rolls its roots forward or drains its nullifier
  queue. Records as SPP UTXOs inherit the forester, the root history, and the
  indexer.

## Limits

- A table holds at most `MAX_RULES` rules and `MAX_INLINE_ASSETS` inline
  assets. A transfer proves at most `POLICY_POOL_SLOTS` distinct triples,
  above that the witness build refuses.
- The builder rejects `ExitDestination` rules, no layer enforces exit
  destinations.
- Sender rules take no amount guard, a transfer has no single sender amount.
- A ring keeps its rule table for life. An upgrade with a different table
  fails closed on every transact, a new table means a new ring.

## The cycle

1. The operator deploys the ring program with its compiled table.
2. `create_policy` pins `policy_hash` and the records tree, signed by the
   upgrade authority.
3. Each list's holder creates and updates records through SPP transacts.
4. The wallet reads the policy config and the records, then builds the pool
   witness.
5. The prover produces one proof over the audit statement and the table
   statement.
6. The ring program recomputes the table hash, resolves the roots, verifies
   the proof, and CPIs into SPP.
