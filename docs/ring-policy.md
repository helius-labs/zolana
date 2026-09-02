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
- A **list** (`ListId`) is a `u8` naming one of the eight lists. Zero is
  reserved for inline assets.
- An **entry** (`ListEntry`) states one `(list, member)` fact. It lives as a
  zero-amount data UTXO in the SPP state tree.
- The **writer** (`Writer`) of a list is the party that may mutate its list,
  the ring authority or the member.
- The **answers** array is the transfer proof's set of entry checks, one
  slot per distinct `(list, member, mode)` triple the rules name.
- The **source map** binds each referenced list to the namespace serving
  it, the ring's own or a curator ring's.

A blocklist ring runs through every section below. Its table holds one rule,
`Rule::forbid(Subject::OutputOwner, ListId::Block)`. The authority lists
Mallory under `Block`. A transfer to Mallory has no witness, its answer slot
cannot show the live entry absent. A transfer to Bob proves absence, no
entry under his pair exists. After the authority clears Mallory, a transfer
to her proves absence through the cleared entry.

## The rule table

`Rule { subject, mode, source, guard }` lives in
`program-libs/ring-policy/src/rule_table.rs`. A rule checks `OutputOwner`,
`Sender`, or `Asset` for `Present` or `Absent` in one list. The source is a
list, a group of lists, or an inline asset set. A group is a disjunction over
its lists, `require_any` passes a subject present in at least one list (a union
allowlist) and `forbid_all` refuses a subject only when present in every list
(an intersection blocklist). Several separate rules stay a conjunction, absence
from every listed block list or presence in every listed allow list. An
`AboveAmount` guard exempts a subject from the
membership check when the total that subject receives in the transaction stays
at or below the threshold. The exemption aggregates every output to the same
recipient, so splitting a payment across slots does not escape it. It is
per-transaction and does not bound a total across transactions.

`RuleTableBuilder::build` runs in const context and panics at compile time on a
table the circuit cannot enforce. Duplicate rules, guarded sender rules, and
zero-valued inline assets fail the build, never a transaction.

`RuleTable::hash` chains the table domain, `POLICY_VERSION`, the eight source
slots, the rule count, every `Rule::encoded()`, and the inline assets. The
count closes the variable-length preimage. The source map ties the table to
the entries serving each list.

The ring's table is the `RULES` const in
`custom-rings/interface/src/rules.rs`. Cargo features add rows through
`rule_if`, a build without features compiles an empty table.

`create_policy` pins the table hash into the `PolicyConfig` account together
with the source map and the entries tree. Only the upgrade authority may sign
it, the table is part of the deployed program. Every transact and entry
mutation recomputes `RULES.hash` and refuses a mismatch, a changed table
fails closed. `init_spp_ring_config` registers a policy ring with SPP only
after `create_policy`, it loads the policy config as its last account.

## Entries

Entries are standard SPP UTXOs, the derivations are in
[spec.md](spec.md#utxo-hash). `program-libs/ring-policy/src/entry.rs` fixes
their shape.

`ListNamespace::new` derives the owner hash from the ring's `policy_records`
PDA with a zero nullifier secret. Anyone computes entry nullifiers, the
entry set stays publicly auditable. Spending still requires the PDA's CPI
signature.

`entry_seed(list_id, member)` gives every pair one deterministic address.
Creating an entry claims the address, and the nullifier tree admits each
address once. One lineage per pair, for the life of the tree.

The entry version doubles as the UTXO blinding. A member cleared and
recorded again never repeats a `utxo_hash` or a nullifier.

A mutation is a one-input one-output SPP transact built over
`mutation_private_tx_hash`. `create_entry` claims the address and inserts the
version-zero UTXO. `update_entry` spends the live UTXO and inserts the next
version at the same address. There is no delete, removal is an update to
`Cleared`. Absence therefore has two provable shapes, an address never claimed
or a live entry in `Cleared`. `create_entry` and `update_entry` refuse a
content commitment the list's schema does not recover (`InvalidEntryContent`).
Every current list carries unit content and commits to zero.

Entries publish their bytes in plaintext through `ListEntry::to_output_data`.
Discovery re-derives `data_hash` from the published bytes and compares it with
the on-chain leaf before trusting them.

## Mutation authorization

`ListId::writer()` is the single authorization axis. The match is
exhaustive, a new list does not compile until it declares its writer.
`RingViewing`, `Recovery`, and `Escrow` are member-written, the member signs
their own mutations. Every other list is authority-written. `check_mutator` in
the ring program enforces the matching signer on every mutation. The
mutation's payer signs as the SPP payer, funds the forester fee and is bound
in the proof, so it is fixed at proof time. The transaction fee payer may be
any other signer. A member of a member-written list is the Solana key whose
owner tag hashes to the member. The ring admits the eddsa rail only, a P-256
identity can be listed by the authority but cannot transact in the ring or
self-manage a member-written list.

## Sources

`create_policy` declares each referenced list's source and stores the map in
`PolicyConfig.sources`. A curator slot copies the curator's resolved owner
for the list, a curator of a curator collapses at copy time. `RuleTable::hash`
binds all eight slots and the circuit resolves every answer's owner from
the committed map. One curated list serves every subscriber from one write.

`set_policy_source` lets the ring authority re-point one list. The instruction
first checks the deployed table still reproduces the stored hash from the
stored map. A rebuilt table stays fail closed, only `create_policy` pins a
table. All sources live in one entries tree.

Mutations of a curator sourced list fail on the subscriber with
`ForeignSource`, the list is mutated on its curator ring. Members enroll
member-written lists at the curator directly, every subscriber sees the entry.

## Proving compliance

The wallet builds the answers in `CustomRingWitnessInput::build`
(`custom-rings/sdk/src/witness.rs`), one slot per distinct triple, unused
slots disabled and zero-filled. It fixes every entry before the first proof
read and takes the state root and the nullifier root from the proof responses
against the pinned entries tree, `PolicyRootMismatch` when a response mixes
roots. Presence is an inclusion proof of the entry's `utxo_hash` in the state
tree plus a non-inclusion proof of its nullifier. Absence is a non-inclusion
proof of the pair's address, or the same two proofs over the cleared entry.

The public input chains the audit statement with `policy_hash`, `state_root`,
and `nullifier_root` (`custom-rings/interface/src/public_input.rs`). The
program resolves both roots from the history indices in the instruction data
and verifies one proof.

A ring is one of two tiers, pinned by the config `has_policy` flag that transact
dispatches on. A policy ring proves the folded audit-and-policy statement above.
An audit-only ring proves the eight-element audit statement alone against a
lighter circuit and verifying key, with no policy accounts. Within the policy
circuit an empty table proves a zero-length table with every answer slot
disabled, and proof size, account list, and verification cost do not vary with
the table, a transfer reveals none of the checks it passed.

## Adding a list

The eight `ListId` values fill the circuit's source width, a ninth is a circuit
and encoding change. `Allow`, `Block` and `Frozen` back the released rules, the
other five are writable and read by no rule. The sealed `ListSchema` trait in
`program-libs/ring-policy/src/schema.rs` fixes a list and its `EntryContent`
type, its module doc walks the four steps. The keying, the entry shape, the
membership proofs, and the circuit are reused unchanged.

## Pitfalls

- Photon learns a tree from the first transaction it indexes in it, so an
  entries tree serves no membership proof before its first transact lands.
  An entry claim into a fresh tree fails at the indexer until a deposit or
  transfer has reached the tree.
- The transact reads its roots from a dedicated entries-tree account, its
  address checked equal to `PolicyConfig.entries_tree`, and refuses roots from
  any other tree. The SPP money input and output trees are independent and may
  be any registered tree. A paused entries tree stops every policy transact,
  money in other trees included.
- A policy ring pins `create_policy` and the transact path loads its policy
  config, an audit-only ring pins none and takes the audit path.
- A ring-owned entry tree looks equivalent to reusing SPP's trees. It fails
  on maintenance, nothing rolls its roots forward or drains its nullifier
  queue. Entries as SPP UTXOs inherit the forester, the root history, and the
  indexer.
- A curator on another entries tree is refused at `create_policy`. The proof
  runs against one root pair, every source shares the transfer's tree.
- A subscriber trusts its curator wholly. A curator mutation reaches every
  subscriber on the same schedule as the ring's own entries, with no per-ring
  review step.
- The moment a mutation takes effect depends on the tree its effect lives in.
  A new state leaf, an `Allow` entry or a `Cleared` version, is provable at
  the next transfer, transact appends the leaf synchronously. An effect that
  lives in the nullifier tree, a `Block` address claim or the retirement of an
  `Allow` entry, is enforced on chain only after the forester appends the zkp
  batch holding it and the window has dropped every earlier root,
  `NULLIFIER_ROOT_WINDOW` rotations later. Indexer-backed clients are refused
  at once, photon serves no non-inclusion proof for a queued leaf and the SDK
  refuses a contradicting live entry. No slot or clock bound exists.

## Limits

- A table holds at most `MAX_RULES` rules and `MAX_INLINE_ASSETS` inline
  assets. A transfer proves at most `ANSWER_SLOTS` distinct triples,
  above that the witness build refuses.
- The builder rejects `ExitDestination` rules, no layer enforces exit
  destinations.
- Sender rules take no amount guard, a transfer has no single sender amount.
- An owner amount guard needs a single unguarded inline asset rule and reads
  in that asset's base units. An asset guard reads in its own asset's units.
- The builder asserts a spend from one key at `POLICY_OUTPUT_SLOTS` distinct
  recipients fits `ANSWER_SLOTS`. A shape past `POLICY_INPUT_SLOTS` inputs or
  `POLICY_OUTPUT_SLOTS` outputs, or a spend whose answers exceed
  `ANSWER_SLOTS`, is refused at witness build with `PolicyShapeUnsupported`.
  A padded change slot pushes the transact past the packet limit, `prove`
  refuses it with `PaddedChange`.
- The entries tree is pinned at `create_policy` for the life of the ring, like
  the table and the tier. The cli default pins the SPP default tree. A full
  entries tree ends list changes, transfers in other trees still prove against
  its roots. Another tree means a new ring.
- A ring keeps its rule table for life. An upgrade with a different table
  fails closed on every transact, a new table means a new ring.
- The tier is fixed at `create_config` and immutable. A ring cannot move
  between audit-only and policy after init.
- The program reads a config account of another size as uninitialized, the
  SDK refuses it.

## The cycle

1. The operator deploys the ring program with its compiled table.
2. `create_policy` pins `policy_hash`, the source map, and the entries tree,
   signed by the upgrade authority.
3. `init_spp_ring_config` registers the ring with SPP under its `ring_auth`
   PDA, refused before step 2.
4. Each list's writer creates and updates entries through SPP transacts on
   the ring the source map names.
5. The wallet reads the policy config and the entries, then builds the answers
   witness.
6. The prover produces one proof over the audit statement and the table
   statement.
7. The ring program recomputes the table hash, resolves the roots, verifies
   the proof, and CPIs into SPP.

## Diagrams

- [`diagrams/ring-policy-classes.mmd`](diagrams/ring-policy-classes.mmd), the
  type relationships by domain.
- [`diagrams/ring-policy-domains.mmd`](diagrams/ring-policy-domains.mmd),
  what lives where and the hash and proof bridges between the layers.
- [`diagrams/ring-policy-ofac-setup.mmd`](diagrams/ring-policy-ofac-setup.mmd),
  a subscriber pins a curator's blocklist at `create_policy`.
- [`diagrams/ring-policy-ofac-example.mmd`](diagrams/ring-policy-ofac-example.mmd),
  the enforcement cycle, baseline, ban, refusal, clear, source switch.
