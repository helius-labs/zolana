# Ring policy and entries

The ring pins a rule table and proves compliance over the same private
transaction that SPP settles. List answers stay private. The auditor can
decrypt the transfer. Windowed spend records expose the sender's identity
and record history without exposing its counters.

## The model

Seven terms carry the whole design.

- The **rule table** (`RuleTable`) holds at most `MAX_RULES` rules and
  `MAX_INLINE_ASSETS` inline asset-limit pairs. It is data, written from `ring.toml`
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
  slot per distinct `(list, member, mode)` triple the rules need, the circuit
  names them list facts.
- The **source map** binds each referenced list to the namespace serving
  it, the ring's own or a curator ring's.

A blocklist ring runs through every section below, the `own-blocklist`
example. Its table holds one rule,
`Rule::forbid(Subject::OutputOwner, ListId::Block)`. The authority lists
Mallory under `Block`. Once all accepted nullifier roots contain that claim,
a transfer to Mallory cannot prove her absent. A transfer to Bob proves absence, no
entry under his pair exists. After the authority clears Mallory, a transfer
to her proves absence through the cleared entry.

## The rule table

`Rule { subject, source, guard }` lives in
`custom-rings/policy/src/rule_table.rs`. A rule screens every live
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

`AboveAmountByAsset` puts several thresholds on one output-owner rule. The
table pairs each inline mint with its limit. Outputs are grouped by owner and
mint, and the owner needs the rule's list answer if any group exceeds its
limit. A mint absent from the map is refused. This remains one rule, so it
does not add an answer per configured mint.

```toml
[[policy.rules]]
subject = "output-owner"
require = "allow"
limits = [
  { asset = "11111111111111111111111111111111", above = 1000000000 },
  { asset = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", above = 1000000 },
]
```

`RuleTableBuilder::try_build` refuses a table the circuit cannot enforce and
names the reason (`RuleTableError`). Two rules with the same signature,
subject plus both list sets, a guarded sender rule, a zero threshold, an
owner guard without exactly one unguarded inline asset rule, and a table past
the answer budget below are refused. The cli refuses such a table at `new`,
`init` and `policy set` naming the row. The program refuses it at
`create_policy` and `set_policy_rules` with `InvalidPolicyRules`.

`Rule::encoded` packs a rule into one row of 32 bytes. Byte 31 is the
subject, byte 30 the primary mode, byte 29 the list mask of that mode (bit
`i` names list `i + 1`, zero marks the inline source), byte 28 the guard tag,
bytes 20 to 27 the threshold big-endian, and byte 19 the alternative mask,
the lists satisfying the rule in the opposite mode. Bytes 0 to 18 stay zero.
The form is canonical. A rule with a present set is `Present` primary and
carries its absent set in byte 19, a rule with absent lists only is `Absent`
primary with byte 19 zero. `Rule::decode` refuses every other row, the
stored rows are exactly what `encoded` emits. The circuit range-checks the
components and re-derives the row by weighted sum (`ruleWeights` in
`prover/server/circuits/custom_ring/policy/constants.go`).

A velocity table bounds a sender's outflow per mint and puts a single
transfer above a threshold under dual control. It is `window_slots` and up
to `MAX_VELOCITY_ASSETS` rows of `VelocityRow { asset, cap, cosign_above }`,
a zero cap leaves the mint uncapped and a zero threshold disables the co-sign
demand. A zero window caps each transfer alone with no record, a nonzero
window carries the counters across it. A window without rows is refused, a
row names a nonzero mint once and carries at least one bound. The rows pin
with the rules and move only under the upgrade authority.

```toml
[policy.velocity]
window_slots = 216000
rows = [
  { asset = "11111111111111111111111111111111", cap = 5000000000, cosign_above = 1000000000 },
]
```

Dropping `window_slots` caps each transfer on its own with no record.

```toml
[policy.velocity]
rows = [
  { asset = "11111111111111111111111111111111", cap = 5000000000, cosign_above = 1000000000 },
]
```

`EncodedRuleTable::hash` chains `POLICY_TABLE_DOMAIN`, `POLICY_VERSION`, the
eight source slots, the rule, inline and velocity counts, every row, the
inline asset-limit pairs, the window length and every velocity row as mint,
cap and threshold. The counts close the variable-length preimage. The source
map ties the table to the entries serving each list. `POLICY_VERSION` moves
with any change of the row encoding.

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
(`PolicyTableIxData`), is signed by the upgrade authority and refuses an
audit-only ring, the tier is fixed at `create_config`. It binds each
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
`create_policy`, replaces it with `set_policy_rules` and sets the delegate
once. The **auditor** decrypts transfers and registered nullifier keys but
cannot authorize an ownership transfer or withdrawal. The **permanent
delegate** signs moves between members over the authority rail and cannot
withdraw. Its dedicated policy key keeps ordinary rules and
exempts velocity. Scoped co-signing still applies. It spends a member's notes
with the member's nullifier key, escrowed to the ring auditor in the key
registry. The current delegate workflow needs both the auditor secret for
recovery and the configured delegate's Solana signature for authorization,
see the custom-rings [README](../custom-rings/README.md#controls). The **config
authority** writes the authority-written lists, re-points sources, grants
readers, sets or clears the co-signer and the spend windows, and pauses the
ring. The **co-signer**
signs beside the sender on the operations its scope names and on every
transfer the velocity statement marks for approval. A **member** of a windowed velocity ring registers its own spend record
once and spends it with every transfer. A **curator** is a ring whose lists other rings
read, it writes its own entries and nothing on its subscribers. The
**operator** answers `zolana-ring new` and holds the ring directory, one key
serves both authorities unless `ring.toml` splits them.

## Entries

Entries are standard SPP UTXOs, the derivations are in
[spec.md](spec.md#utxo-hash). `custom-rings/policy/src/entry.rs` fixes
their shape.

`ListNamespace::new` derives the owner hash from the ring's `policy_records`
PDA with a zero nullifier secret. Anyone computes entry nullifiers, the
entry set stays publicly auditable. Spending still requires the PDA's CPI
signature.

`entry_seed(list_id, member)` gives every pair one deterministic address.
Creating an entry claims the address, and the nullifier tree admits each
address once. One lineage per pair, for the life of the tree.

Every entry leaf and address hashes under the entries tree id the policy
config pins. The entry's blinding is the SPP output blinding of the transact
that wrote it, derived from the spent nullifier and published in the record,
so a reader rebuilds the leaf from the record alone. A member cleared and
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

## Spend records

A windowed velocity ring keeps a spend record per member, a per-transfer cap
ring keeps none. A spend record is the second record kind under the namespace PDA, a
zero-amount SOL data note in the entries tree keyed by the member's identity
through `SPEND_ADDRESS_DOMAIN`, so no list instruction reaches it. Its
public opening is `member || version || window || counters_commitment ||
blinding`, `SpendRecord::data_hash` binds it to its derived address and the
program checks every published record against the leaf it names. The
counters, `SpendCounters { salt, assets, spent }`, stay behind
`HashChain(salt, (asset, spent) x 8)`, each counter bound to its mint
independent of its table position.

`register_spend` claims the member's address at version zero under the
current window with the zero counters, the payer's Solana key is the member
and the program derives every field except the blinding. From then on only the member's
own transfer writes the record. The transfer carries the record as the last
input and the last output of its SPP transact, the namespace PDA raised as
one more owner signer inside the program's CPI, and the policy circuit pins
the two slots at the sender's address, the input at the latest version, the
output at version plus one, every other opening a different owner. Money
inputs open to one identity, that identity is the record's member.

For each row the circuit charges `outflow = inputs of the mint - change the
sender keeps inside the ring`, payments, exits and withdrawals alike, and
writes `spent' = (record.window == window ? spent : 0) + outflow` into the
successor under a fresh salt, `spent' <= cap` where the cap is nonzero. The
program derives `window = slot / window_slots` and binds it into the public
input beside the ring id, the namespace owner and the approval bit, the bit
the circuit sets when any `outflow > cosign_above`. The program then demands
the configured co-signer, `ApprovalWithoutCoSigner` when the ring has none.
A record from a future window is refused, an expired one is consumed from
its published commitment alone.

Registration publishes the opening as plaintext output data. A transfer
uses SPP's standard confidential output format for the record, publishing
the opening in one message tagged
`SHA256("zolana:spend-record:v1" || namespace)`. The program reconstructs the
last output's commitment from that message. Missing or duplicate messages
are refused. The carrier is a zero-amount note the namespace PDA owns.

The successor's counters follow in a message under the
transaction viewing key, tagged with the namespace, before the auditor
message. The sender derives that key from the transfer's first nullifier and
recovers the counters for its next transfer, the auditor recovers it from
the audit ciphertext and reports the record with its counters, or without
them when no message opens to the commitment. `ReadSpendRecord::read_current`
authenticates the record against the shared head root. `RegisterSpend`
proves both the SPP claim and insertion into the indexed head map. Then
`CustomRingTransfer::prove` reads the record, the slot and the counters
before it stages the slots, refusing `SpendRecordMissing`,
`SpendCountersUnknown` and `VelocityCapExceeded` before any prover round.

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

The public input chains the eight audit elements with `policy_hash`,
`state_root`, `nullifier_root`, `entries_tree_id`, `ring_id`,
`namespace_owner_hash`, `window_index` and `approval_required`, sixteen in
all (`custom-rings/interface/src/policy_public_input.rs`). Windowed member
transfers append the old and new shared head roots, eighteen elements,
and use the compressed policy key. The program resolves the list state and
nullifier roots from history indices. The old head root must equal the
head-map account's current root. One ring proof binds both checks.

A ring is one of two tiers, pinned by the config `has_policy` flag that transact
dispatches on. A policy ring proves the combined audit-and-policy statement above.
An audit-only ring proves the eight-element audit statement alone against a
lighter circuit and verifying key, with no policy accounts. Within the policy
circuit an empty table creates no list obligations. The client disables unused
answer slots. The account list and key distinguish windowed velocity from
ordinary policy. Individual list answers stay private.

## Adding a list

The eight `ListId` values fill the circuit's source width, a ninth is a circuit
and encoding change. A rule names any authority-written list, `Allow`,
`Block`, `Frozen`, `Reader` and `Approval`. The member-written lists are
writable and read by no rule, the `ring.toml` grammar refuses their names.
The sealed `ListSchema` trait in `custom-rings/policy/src/schema.rs`
fixes a list and its `EntryContent` type, its module doc walks the four
steps. The keying, the entry shape, the membership proofs, and the circuit
are reused unchanged.

## The cli

`zolana-ring new` asks, in order, for the ring name, the service URLs of both
clusters and the target. It then offers common policy options and an advanced
rule builder. Finishing without an option creates an audit-only ring, any
option creates a policy ring, and `configure policy later` creates one with an
empty table. The options build list rules. A velocity table comes from
`--policy-from` or a hand-written `ring.toml`. Co-signing is configured
separately in `ring.toml`'s `[cosigner]` table. A policy uses the SPP default entries tree without asking and
writes that address explicitly to `ring.toml`. Each option compiles as one
unit when added. After `finish`, the wizard derives the lists the rules read
and asks for those sources only. The wizard prints the `ring.toml` it will
write and asks before writing. `--silent` takes every default. `--policy-from
<file>` takes the `[policy]` table of a `ring.toml` or of a file holding only
that table, checks it on both clusters, and skips the policy option questions.

The source question offers `own entries`, the curators of the catalogue
serving the list from their own entries in the ring's tree, and `another
curator` by program id. The catalogue is the bundled
`custom-rings/cli/catalogue.toml`, one table per cluster where curators
register by pull request, merged with every ring registered with SPP on the
target that pins a policy. `--catalogue <path or URL>` (`RING_CATALOGUE`)
replaces the bundled file.

`init` compiles `[policy]` for the target and checks each curator, deployed,
with a policy, serving the list from its own entries, in the ring's tree.
It pins the table with `create_policy`. The SDK refuses a `create_policy`
transaction past the signed V1 size (`TransactionTooLarge`). `init` reads the
chain back and refuses to register a ring whose pinned policy differs from
`ring.toml` (`PolicyDrift`).

`policy show` prints the pinned rows, hash, generation with its slot, tree
and sources. `policy check` compares `ring.toml` with the chain, rows and
hash, then the tree, then every source, and exits non-zero on a difference.
`policy set` prints the rows added and removed and replaces the table under
the upgrade authority, `--yes` skips the confirmation. A changed
`entries_tree` is refused, the tree is fixed at `init`.

`spend register` claims the sender's spend record on a windowed velocity ring and
`spend show` prints its live version, window and commitment. `transact` and
`transfer` register the sender before its first transfer and refuse a
transfer the proof marks for approval unless `--cosigner-keypair` is given.

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
- [`velocity-window`](../custom-rings/examples/velocity-window/ring.toml)
  caps each sender's SOL outflow per window and demands the co-signer above
  a threshold.
- [`transfer-cap`](../custom-rings/examples/transfer-cap/ring.toml) caps each
  transfer's SOL outflow on its own with no window and no record.

## Pitfalls

- Photon learns a tree from the first transaction it indexes in it, so an
  entries tree serves no membership proof before its first transact lands.
  An entry claim into a fresh tree fails at the indexer until a deposit or
  transfer has reached the tree.
- The transact reads its roots from a dedicated entries-tree account, its
  address checked equal to `PolicyConfig.entries_tree`, and refuses roots from
  any other tree. Non-windowed money transfers may use other registered trees.
  Windowed member transfers require both money trees to be the entries tree.
  A paused entries tree stops every policy transact,
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
- A changed policy hash takes effect at once. In-flight proofs over the old
  hash must be rebuilt. An identical re-pin advances `generation` and keeps
  the proof statement.
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
- A scalar owner amount guard needs a single unguarded inline asset rule and
  reads in that asset's base units. A per-asset owner guard supports up to
  `MAX_INLINE_ASSETS` mint-limit pairs and refuses any other mint.
- The builder asserts a spend from one key at `POLICY_OUTPUT_SLOTS` distinct
  recipients fits `ANSWER_SLOTS`. A shape past `POLICY_INPUT_SLOTS` inputs or
  `POLICY_OUTPUT_SLOTS` outputs, or a spend whose answers exceed
  `ANSWER_SLOTS`, is refused at witness build with `PolicyShapeUnsupported`.
  `prove` requires compact change and refuses padded change with `PaddedChange`.
- The entries tree is pinned at `create_policy` for the life of the ring, like
  the tier. The grammar accepts a missing `entries_tree` as the SPP default;
  the cli writes the effective address explicitly.
  `set_policy_rules` keeps the stored tree. A full entries tree ends list
  changes. Non-windowed transfers in other trees can still prove against its
  roots. Windowed transfers also need space for the successor record. Another
  entries tree means a new ring.
- The table moves only under the upgrade authority. `generation` is a `u32`
  counter, a write at its ceiling fails with `PolicyGenerationOverflow`.
- The tier is fixed at `create_config` and immutable. A ring cannot move
  between audit-only and policy after init, `init` refuses a `ring.toml`
  whose tier differs from the chain (`TierDrift`).
- The program and SDK reject a config account with an incompatible layout.
- A velocity ring, per transfer or windowed, takes no deposit leg on a
  member transfer. Delegation is exempt from velocity caps and counters.
  Ordinary rules and transfer-scoped co-signing apply to it. A windowed ring keeps
  every note of a transfer in its entries tree and needs a registered record
  before a member's first transfer, a per-transfer cap ring keeps neither and
  each transfer stands alone against its cap. Windows are fixed, a boundary
  admits up to twice the cap. A member spends only its own notes in one
  transfer. The record publishes the member's identity and lineage.
- Windowed members share one 42-byte head-map account.
  Photon supplies proofs for its exact root. A concurrent update makes a
  proof stale and requires rebuilding. One input and one output carry the
  record, leaving four money inputs and three outputs. See
  [compressed history](ring-policy-design.md#compressed-history).

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
8. `set_policy_rules` or `set_policy_source` advances the generation. A changed
   hash invalidates proofs over the prior policy.
