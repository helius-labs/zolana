# Ring policy and entries

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

Seven terms carry the whole design.

- The **rule table** is the compiled `RuleTable`, a fixed array of at most
  `MAX_RULES` rules built into the ring program.
- A **member** (`Member`) is a field element naming who or what a rule checks.
  Zero is the circuit padding value, never a member.
- A **list** (`ListId`) is a `u8` naming one list. Zero is reserved for
  inline assets.
- A **entry** (`ListEntry`) states one `(list, member)` fact. It lives as a
  zero-amount data UTXO in the SPP state tree.
- The **writer** (`Writer`) of a list is the party that may mutate its list,
  the ring authority or the member.
- The **answers** is the transfer proof's set of entry checks, one slot per
  distinct `(list, member, mode)` triple the rules name.
- The **source map** binds each referenced list to the entries owner serving
  it, the ring's own entries or a curator ring's.

A blocklist ring runs through every section below. Its table holds one rule,
`Rule::forbid(Subject::OutputOwner, ListId::Block)`. The authority entries
Mallory under `Block`. A transfer to Mallory has no witness, its answers slot
cannot show the live entry absent. A transfer to Bob proves absence, no
entry under his pair exists. After the authority clears Mallory, a transfer
to her proves absence through the cleared entry.

## The rule table

`Rule { subject, mode, source, guard }` lives in
`program-libs/ring-policy/src/policy.rs`. A rule checks `OutputOwner`,
`Sender`, or `Asset` for `Present` or `Absent` in one list. The source is a
list or an inline asset set. An `AboveAmount` guard passes transfers
below the threshold without a membership check.

`RuleTableBuilder::build` runs in const context and panics at compile time on a
table the circuit cannot enforce. Duplicate rules, guarded sender rules, and
zero-valued inline assets fail the build, never a transaction.

`RuleTable::hash` chains the table domain, `POLICY_VERSION`, the eight source
slots, the rule count, every `Rule::encoded()`, and the inline assets. The
count closes the variable-length preimage. The source map ties the table to
the entries serving each list.

The ring's table is the `RULES` const in
`custom-rings/interface/src/policy.rs`. Cargo features add rows through
`rule_if`, a build without features compiles an empty table.

`create_policy` pins the table hash into the `PolicyConfig` account together
with the source map and the entries tree. Only the upgrade authority may sign
it, the table is part of the deployed program. Every transact and entry
mutation recomputes `RULES.hash` and refuses a mismatch, a changed table
fails closed.

## Entries

Entries are standard SPP UTXOs, the derivations are in
[spec.md](spec.md#utxo-hash). `program-libs/ring-policy/src/entry.rs` fixes
their shape.

`ListNamespace::new` derives the owner hash from the ring's `policy_records`
PDA with a zero nullifier secret. Anyone computes entry nullifiers, the
entry set stays publicly auditable. Spending still requires the PDA's CPI
signature.

`record_seed(list, member)` gives every pair one deterministic address.
Creating an entry claims the address, and the nullifier tree admits each
address once. One lineage per pair, for the life of the tree.

The entry version doubles as the UTXO blinding. A member cleared and
recorded again never repeats a `utxo_hash` or a nullifier.

A mutation is a one-input one-output SPP transact built over
`mutation_private_tx_hash`. `create_entry` claims the address and inserts the
version-zero UTXO. `update_entry` spends the live UTXO and inserts the next
version at the same address. There is no delete, removal is an update to
`Cleared`. Absence therefore has two provable shapes, an address never claimed
or a live entry in `Cleared`.

Entries publish their bytes in plaintext through `ListEntry::to_output_data`.
Discovery re-derives `data_hash` from the published bytes and compares it with
the on-chain leaf before trusting them.

## Mutation authorization

`ListId::writer()` is the single authorization axis. The match is
exhaustive, a new list does not compile until it declares its writer.
`RingViewing`, `Recovery`, and `Escrow` are member-held, the member signs
their own mutations. Every other list is authority-held. `check_mutator` in
the ring program enforces the matching signer on every mutation.

## Sources

`create_policy` declares each referenced list's source and stores the map in
`PolicyConfig.sources`. A curator entry copies the curator's resolved owner
for the list, a curator of a curator collapses at copy time. `RuleTable::hash`
binds all eight slots and the circuit resolves every answer's owner from
the committed map. One curated list serves every subscriber from one write.

`set_policy_source` lets the ring authority re-point one list. The instruction
first checks the deployed table still reproduces the stored hash from the
stored map. A rebuilt table stays fail closed, only `create_policy` pins a
table. All sources live in one entries tree, the transfer's input tree.

Mutations of a curator sourced list fail on the subscriber with
`ForeignRecordSource`, the list is mutated on its curator ring. Members enroll
member held lists at the curator directly, every subscriber sees the entry.

## Proving compliance

The wallet builds the answers in `answer_rules`
(`custom-rings/sdk/src/witness.rs`), one slot per distinct triple, unused
slots disabled and zero-filled. Presence is an inclusion proof of the entry's
`utxo_hash` in the state tree plus a non-inclusion proof of its nullifier.
Absence is a non-inclusion proof of the pair's address, or the same two
proofs over the cleared entry.

The public input chains the audit statement with `policy_hash`, `state_root`,
and `nullifier_root` (`custom-rings/interface/src/public_input.rs`). The
program resolves both roots from the history indices in the instruction data
and verifies one proof.

One circuit serves every ring. A rules-free ring proves a zero-length table
with every answers slot disabled. Proof size, account list, and verification cost
do not vary with the table, a transfer reveals none of the checks it passed.

## Adding a list

A new list is one trait impl. The sealed `ListSchema` trait in `program-libs/ring-policy/src/schema.rs` fixes the list, its `EntryContent` type, and
the writer. Its module doc walks the four steps. The keying, the entry shape,
the membership proofs, and the circuit are reused unchanged.

## Pitfalls

- `PolicyConfig.entries_tree` must equal the transfer's input tree. The
  transact refuses roots from any other tree.
- A rules-free ring still needs `create_policy`. The transact path loads the
  policy config unconditionally.
- A ring-owned entry tree looks equivalent to reusing SPP's trees. It fails
  on maintenance, nothing rolls its roots forward or drains its nullifier
  queue. Entries as SPP UTXOs inherit the forester, the root history, and the
  indexer.
- A curator on another entries tree is refused at `create_policy`. The proof
  runs against one root pair, every source shares the transfer's tree.
- A subscriber trusts its curator wholly. A curator mutation takes effect on
  every subscriber at the next transfer, with no per-ring review step.

## Limits

- A table holds at most `MAX_RULES` rules and `MAX_INLINE_ASSETS` inline
  assets. A transfer proves at most `ANSWER_SLOTS` distinct triples,
  above that the witness build refuses.
- The builder rejects `ExitDestination` rules, no layer enforces exit
  destinations.
- Sender rules take no amount guard, a transfer has no single sender amount.
- A ring keeps its rule table for life. An upgrade with a different table
  fails closed on every transact, a new table means a new ring.

## The cycle

1. The operator deploys the ring program with its compiled table.
2. `create_policy` pins `policy_hash`, the source map, and the entries tree,
   signed by the upgrade authority.
3. Each list's writer creates and updates entries through SPP transacts on
   the ring the source map names.
4. The wallet reads the policy config and the entries, then builds the answers
   witness.
5. The prover produces one proof over the audit statement and the table
   statement.
6. The ring program recomputes the table hash, resolves the roots, verifies
   the proof, and CPIs into SPP.
