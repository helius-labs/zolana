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

- The **rule table** (`RuleTable`) holds at most `MAX_RULES` rules and
  `MAX_INLINE_ASSETS` inline assets. It is data, written from `ring.toml`
  into the ring's policy config and pinned there by hash.
- A **member** (`Member`) is a field element naming who or what a rule checks,
  an owner tag or a mint. The tag hashes as the UTXO's owner proof input, the
  mint as its asset field. Zero is the circuit padding value, never a member.
- A **list** (`ListId`) is a `u8` naming one of the eight lists. Zero is
  reserved for inline assets. One list holds owner and asset members side by
  side, an owner rule looks up the output owners and an asset rule the output
  mints.
- An **entry** (`ListEntry`) states one `(list, member)` fact. It lives as a
  zero-amount data UTXO in the SPP state tree.
- The **writer** (`Writer`) of a list is the party that may mutate its list,
  the ring authority or the member.
- The **answers** array is the transfer proof's set of entry checks, one
  slot per distinct `(list, member, mode)` triple the rules need.
- The **source map** binds each referenced list to the namespace serving
  it, the ring's own or a curator ring's.

A blocklist ring runs through every section below, the `own-blocklist`
example. Its table holds one rule,
`Rule::forbid(Subject::OutputOwner, ListId::Block)`. The authority lists
Mallory under `Block`. A transfer to Mallory has no witness, its answer slot
cannot show the live entry absent. A transfer to Bob proves absence, no
entry under his pair exists. After the authority clears Mallory, a transfer
to her proves absence through the cleared entry.

## The rule table

`Rule { subject, source, guard }` lives in
`program-libs/ring-policy/src/rule_table.rs`. A rule screens every live
`OutputOwner`, `Sender`, or `Asset` of a transfer. Its source is
`RuleSource::Lists { present, absent }`, two sets of lists, or
`RuleSource::InlineAssets`. A list rule holds for a subject when any list in
`present` carries a live `Active` entry for it, or any list in `absent`
carries none. `require` and `forbid` name one list. `require_any` passes a
subject present in at least one list (a union allowlist) and `forbid_all`
refuses a subject only when present in every list (an intersection
blocklist). `any_of` mixes both sets, `any_of(OutputOwner, {Approval},
{Block})` admits an approved owner and every unblocked one. Separate rules
stay a conjunction.

An `Asset` rule takes either source. With lists it looks up each output's
mint in the named lists. The mints are entries the config authority or a
curator writes, a change is one mutation and no re-pin. An inline asset rule
(`allow_only_assets`) compares each output asset with the members the table
carries and needs no entry. It holds at most `MAX_INLINE_ASSETS` mints, they
move only with the rows under the upgrade authority. The inline form fits an
asset set that must move only with the rules, and an owner amount guard needs
it. The list form fits a set the config authority or a curator maintains.

An `AboveAmount` guard exempts a subject from the membership check when the
total that subject receives in the transaction stays at or below the
threshold. The exemption sums every output with the same subject value, owner
or mint, a payment split across slots does not escape it. It is per-transaction
and does not bound a total across transactions.

`RuleTableBuilder::try_build` refuses a table the circuit cannot enforce and
names the reason (`RuleTableError`). Two rules with the same signature,
subject plus both list sets, a guarded sender rule, a zero threshold, an
owner guard without exactly one unguarded inline asset rule, and a table past
the answer budget below are refused. The cli refuses such a table at `new`,
`init` and `policy set` naming the row. The program refuses it at
`create_policy` and `set_policy_rules` with `InvalidPolicyRules` and logs the
reason.

`Rule::encoded` packs a rule into one row of 32 bytes. Byte 31 is the
subject, byte 30 the primary mode, byte 29 the list mask of that mode (bit
`i` names list `i + 1`, zero marks the inline source), byte 28 the guard tag,
bytes 20 to 27 the threshold big-endian, and byte 19 the alternative mask,
the lists satisfying the rule in the opposite mode. Bytes 0 to 18 stay zero.
The form is canonical. A rule with a present set is `Present` primary and
carries its absent set in byte 19, a rule with absent lists only is `Absent`
primary with byte 19 zero. `Rule::decode` refuses every other row, the
stored rows are exactly what `encoded` emits. The circuit range-checks the
components and re-derives the row by weighted sum (`ruleShift` in
`prover/server/circuits/custom_ring/transfer/constants.go`).

`EncodedRuleTable::hash` chains `POLICY_TABLE_DOMAIN`, `POLICY_VERSION`, the
eight source slots, the rule count, every row, and the inline assets. The
count closes the variable-length preimage. The source map ties the table to
the entries serving each list. `POLICY_VERSION` moves with any change of the
row encoding.

## The answer budget

A rule costs one answer per live instance of its subject, one per sender key
for a sender rule and one per output for an owner or asset rule. An inline
rule costs none. A group of lists is one rule and costs one answer, the
witness takes the first alternative the entries satisfy. Two rules asking
the same `(list, member, mode)` share one slot. `try_build` asserts every
table answers `GUARANTEED_LOAD`, one sender key at `POLICY_OUTPUT_SLOTS`
outputs, within `ANSWER_SLOTS`. A spend from several keys can need more,
`CustomRingWitnessInput::build` refuses it with `PolicyShapeUnsupported`.

## Rules as data

`ring.toml` carries the table in its `[policy]` table
(`custom-rings/cli/src/policy/grammar.rs`). `entries_tree` names the tree
every entry lives in, the SPP default tree when absent.
`[policy.sources.<cluster>]` names a curator ring per list and per cluster,
a list left out reads the ring's own entries. Each `[[policy.rules]]` row has
a `subject` (`output-owner`, `sender` or `asset`), exactly one of `require`,
`forbid`, `any` or `assets`, and an optional `above`. `any` lists
alternatives, each a `require` or a `forbid`. Only an authority-written list
takes a name in a rule. The rows compile in order through
`RuleTableBuilder`. One released binary serves every ring.

`create_policy` carries the rows, the inline assets and the source specs
(`PolicyTableIxData`) and is signed by the upgrade authority. It binds each
referenced list to its namespace, stores the rows in `PolicyConfig.rules`
(`EncodedRuleTable`) beside the map, pins `policy_hash` over both, and writes
`generation` one with the current slot in `generation_slot`. `set_policy_rules`
replaces the rows and the map under the same authority. `set_policy_source`
re-points one list under the config authority. Both re-hash the stored rows
over the new map, count one more generation and record the slot. `transact`
verifies against the stored hash from then on, a proof built against the old
table fails with `ProofVerificationFailed` and its note stays unspent.
`init_spp_ring_config` registers a policy ring with SPP only after
`create_policy`, it loads the policy config as its last account.

An auditor reconstructs the table history from the transaction history of
the policy config PDA. Every `create_policy`, `set_policy_rules` and
`set_policy_source` is one signed transaction on that account, `generation`
counts them and `generation_slot` names the slot of the last one.

The circuit binds the pinned hash through the public input. The rows enter
the witness as their fields, the proof packs each row again, reproduces
`policy_hash` from the rows and the map, and the program feeds the stored
hash into the public input chain.

## Roles

The **upgrade authority** deploys the binary, pins the table at
`create_policy` and replaces it with `set_policy_rules`. The **config
authority** writes the authority-written lists, re-points sources, grants
readers and pauses the ring. A **curator** is a ring whose lists other rings
read, it writes its own entries and nothing on its subscribers. The
**operator** answers `zolana-ring new` and holds the ring directory, one key
serves both authorities unless `ring.toml` splits them.

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
for the list, a curator of a curator collapses at copy time.
`EncodedRuleTable::hash` binds all eight slots and the circuit resolves every
answer's owner from the committed map. One curated list serves every
subscriber from one write.

`set_policy_source` lets the ring authority re-point one list the stored
table references, to the ring's own entries or to a curator policy config
pinned to the same entries tree. It rewrites the hash over the stored rows,
the rows themselves move only under the upgrade authority. All sources live
in one entries tree.

Mutations of a curator sourced list fail on the subscriber with
`ForeignSource`, the list is mutated on its curator ring. Members enroll
member-written lists at the curator directly, every subscriber sees the entry.

## Proving compliance

The wallet reads the policy config and trusts its rows only after they
reproduce the pinned hash (`policy_config_table`). It builds the answers in
`CustomRingWitnessInput::build` (`custom-rings/sdk/src/witness.rs`), one slot
per distinct triple, unused slots disabled and zero-filled. For each rule and
each live subject it takes the first alternative the entries satisfy and
refuses with `PolicyRuleUnsatisfied` when none does, before any proof
request. It walks every entry lineage by its nullifier chain before the
first proof read and takes the state root and the nullifier root from the
proof responses against the pinned entries tree, `PolicyRootMismatch` when a
response mixes roots. Presence is an inclusion proof of the entry's
`utxo_hash` in the state tree plus a non-inclusion proof of its nullifier.
Absence is a non-inclusion proof of the pair's address, or the same two
proofs over the cleared entry.

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
and encoding change. A rule names any authority-written list, `Allow`,
`Block`, `Frozen`, `Reader` and `Approval`. The member-written lists are
writable and read by no rule, the `ring.toml` grammar refuses their names.
The sealed `ListSchema` trait in `program-libs/ring-policy/src/schema.rs`
fixes a list and its `EntryContent` type, its module doc walks the four
steps. The keying, the entry shape, the membership proofs, and the circuit
are reused unchanged.

## The cli

`zolana-ring new` asks, in order, for the ring name, the service URLs of both
clusters, the target and the tier. A policy ring then names its entries tree,
picks the lists its rules read, picks a source per list and adds rules one
at a time. Each rule compiles as soon as it is added, a refused row is
dropped with its reason. `finish` compiles the table with its sources, a
source no rule reads is offered for removal. The wizard prints the
`ring.toml` it will write and asks before writing. `--silent` takes every
default. `--policy-from <file>` takes the `[policy]` table of a `ring.toml`
or of a file holding only that table, checks it on both clusters, and skips
the tier and policy questions.

The source question offers `own entries`, the curators of the catalogue
serving the list from their own entries in the ring's tree, and `another
curator` by program id. The catalogue is the bundled
`custom-rings/cli/catalogue.toml`, one table per cluster where curators
register by pull request, merged with every ring registered with SPP on the
target that pins a policy. `--catalogue <path or URL>` (`RING_CATALOGUE`)
replaces the bundled file.

`init` compiles `[policy]` for the target and checks each curator, deployed,
with a policy, serving the list from its own entries, in the ring's tree.
It pins the table with `create_policy`. A table whose curator accounts push
the transaction past one legacy packet is pinned over the ring's own sources,
each curated list is then pointed with `set_policy_source`. `init` reads the
chain back and refuses to register a ring whose pinned policy differs from
`ring.toml` (`PolicyDrift`).

`policy show` prints the pinned rows, hash, generation with its slot, tree
and sources. `policy check` compares `ring.toml` with the chain, rows and
hash, then the tree, then every source, and exits non-zero on a difference.
`policy set` prints the rows added and removed and replaces the table under
the upgrade authority, `--yes` skips the confirmation. A changed
`entries_tree` is refused, the tree is fixed at `init`.

`list add|clear|show <list>` names the member with `--owner <tag>` or
`--asset <mint>`, exactly one, and `sol` is the native token. `add` and
`clear` mutate the ring's own entries, a list a curator serves is refused
with `SharedList`. `show` reads the entry from the source the list points
at. `list set-source <list> --curator
<program id or catalogue name>` or `--own` re-points a list after the same
curator check. `status` prints the recorded answers and the chain, the
pinned table included. `transact` deposits twice, enrols the sender and the
recipient in `Allow` when the table references `Allow` and the ring serves
it, then transfers once.

The worked examples in `custom-rings/examples/` each hold one `ring.toml`
the cli loads and re-renders.

- [`audit-only`](../custom-rings/examples/audit-only/ring.toml) has no
  policy table, the ring proves the audit statement alone.
- [`empty-policy`](../custom-rings/examples/empty-policy/ring.toml) pins an
  empty table. Every transfer passes and the table can grow with `policy
  set`.
- [`own-blocklist`](../custom-rings/examples/own-blocklist/ring.toml)
  forbids every output owner on the ring's own `Block` list.
- [`token-blocklist`](../custom-rings/examples/token-blocklist/ring.toml)
  forbids every output mint on the ring's own `Block` list.
- [`curated-blocklist-approval-exception`](../custom-rings/examples/curated-blocklist-approval-exception/ring.toml)
  reads `Block` from a curator named per cluster and admits an owner on its
  own `Approval` list.
- [`allowlist`](../custom-rings/examples/allowlist/ring.toml) is a closed
  ring, the sender and every output owner on `Allow`, a frozen sender
  refused, entries in a named tree.
- [`asset-allowlist-owner-threshold`](../custom-rings/examples/asset-allowlist-owner-threshold/ring.toml)
  admits one mint inline and demands `Allow` from an owner receiving more
  than the threshold.

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
- A re-pin takes effect at once. A proof built against the old table fails
  at verification, a transfer in flight across `policy set` or `list
  set-source` is rebuilt from the new config.
- A full table pinned with its curator accounts can exceed one legacy packet
  at `create_policy` (`TransactionTooLarge`). `init` pins it over the ring's
  own sources and points each curated list afterwards. `set_policy_rules`
  carries fewer accounts and fits the same table.
- The answer budget is guaranteed for one sender key at the output width. A
  spend from several keys against a table near `ANSWER_SLOTS` is refused at
  witness build, split it by key.
- A rule cannot name a member-written list. `RingViewing`, `Recovery` and
  `Escrow` are enrolled by their members and read by no rule.
- Curated sources are per cluster. `[policy.sources.localnet]` and
  `[policy.sources.devnet]` name different curators, the catalogue is per
  cluster too, and a catalogue name resolves only on the cluster that lists
  it.

## Limits

- A table holds at most `MAX_RULES` rules and `MAX_INLINE_ASSETS` inline
  assets over `MAX_SOURCES` source slots. A transfer proves at most
  `ANSWER_SLOTS` distinct triples, above that the witness build refuses.
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
  the tier. `ring.toml` without `entries_tree` pins the SPP default tree.
  `set_policy_rules` keeps the stored tree. A full entries tree ends list
  changes, transfers in other trees still prove against its roots. Another
  tree means a new ring.
- The table moves only under the upgrade authority. `generation` is a `u32`
  counter, a write at its ceiling fails with `PolicyGenerationOverflow`.
- The tier is fixed at `create_config` and immutable. A ring cannot move
  between audit-only and policy after init, `init` refuses a `ring.toml`
  whose tier differs from the chain (`TierDrift`).
- The program reads a config account of another size as uninitialized, the
  SDK refuses it.

## The cycle

1. The operator answers `zolana-ring new` and deploys the released ring
   program.
2. `create_policy` stores the rows and the source map, pins `policy_hash` and
   the entries tree at generation one, signed by the upgrade authority.
3. `init_spp_ring_config` registers the ring with SPP under its `ring_auth`
   PDA, refused before step 2.
4. Each list's writer creates and updates entries through SPP transacts on
   the ring the source map names.
5. The wallet reads the policy config, checks the rows against the hash,
   reads the entries and builds the answers witness.
6. The prover produces one proof over the audit statement and the table
   statement.
7. The ring program reads the pinned hash, resolves the roots, verifies the
   proof, and CPIs into SPP.
8. `set_policy_rules` or `set_policy_source` re-pins the hash at the next
   generation, a proof in flight over the old hash fails.
