# Ring policy and member registry

A custom ring proves its rules against the same private transaction that SPP settles. Its proof also encrypts the committed note fields to the auditor. Users keep their spending keys. The auditor key alone cannot spend.

## The model

Rules and membership are separate data.

```text
PolicyConfig                  MemberRegistryRoot
  rules and thresholds          32 accepted Merkle roots
  own or curator source                    ↑
             ↓                             |
  subjects in the transfer → authenticated registry records
```

`PolicyConfig` is a 1,596-byte PDA. It stores sixteen packed rules, eight list sources, eight mint-specific amount guards and eight outflow rows. It also stores the policy hash, address-tree binding and update generation.

`MemberRegistryRoot` is a 1,035-byte PDA. It stores the last 32 roots, their cursor and the next leaf index. Photon reconstructs the height-20 tree from confirmed registry instructions. A leaf holds:

```text
[member | next member | 64-bit list bitmap | escrow commitment]
```

A member identifies an owner or a mint. Their derivations are distinct. Zero is reserved for the sentinel and circuit padding. Current policies use eight list IDs. One record holds every list bit for that member. The encrypted recovery key travels in registration data and is indexed with the record.

A present record proves the requested member's bits. An absent record proves that the requested member lies strictly between its predecessor and the next member. Both need an authenticated Merkle path. Photon supplies these paths. Clients check them against the requested on-chain root before proving.

This replaces versioned SPP list notes. Membership no longer needs note inclusion, revocation proofs or list-entry lineage. List updates do not spend SPP notes. Transfers read the registry without changing it.

## Rules

Every rule applies to each live instance of its subject. Supported subjects are `sender`, `output-owner` and `asset`. Separate rules are joined with AND. Alternatives inside one rule are joined with OR.

| Form | Meaning |
|---|---|
| `require = "allow"` | The subject has the Allow bit. |
| `forbid = "block"` | The subject has no Block bit. |
| `any = [{ require = "approval" }, { forbid = "block" }]` | Approval or absence from Block is enough. |

Owner and asset rules use the same registry mechanism. The old `assets = [...]` inline allowlist is rejected. To screen mints, use an asset rule and write mint memberships to its list. That list can contain more than eight mints.

```toml
[[policy.rules]]
subject = "asset"
require = "allow"

[[policy.rules]]
subject = "output-owner"
require = "allow"

[[policy.rules]]
subject = "sender"
forbid = "frozen"
```

An `above` guard waives a rule when the subject's received amount is at or below the threshold. The proof sums matching outputs, so splitting a payment across slots cannot evade it. Amounts use base units. Sender rules cannot have amount guards. A scalar owner guard sums that owner's outputs and rejects mixed-mint transfers. Use per-asset guards for payments in several mints.

A per-asset owner guard groups outputs by owner and mint. It requires the owner's list condition if any group exceeds its configured threshold. An unconfigured mint is rejected because the proof has no threshold for it. All such rules share one threshold map with up to eight rows.

```toml
[[policy.rules]]
subject = "output-owner"
require = "allow"
limits = [
  { asset = "11111111111111111111111111111111", above = 1000000000 },
  { asset = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", above = 1000000 },
]
```

These eight rows define amount semantics. They are not a second membership list. Their historical wire names are `inline_assets` and `inline_limits`. Changing a screening decision changes a registry bit. Changing a threshold changes the policy table.

The [rule decoder](../custom-rings/policy/src/rule_table.rs) validates the canonical 32-byte row encoding. It rejects duplicate rule signatures, invalid masks, unsupported subjects, nonzero padding and malformed guards. The CLI validates before submission. The program repeats validation when the table is written.

## Outflow limits

Outflow is the sender's input value minus change kept by that sender inside the ring. Payments, withdrawals and exits count. A limited transfer must have one sender.

```toml
[policy]
limits = [
  { asset = "11111111111111111111111111111111", cap = 5000000000, cosign_above = 1000000000 },
]
```

A zero `cap` disables the cap. A zero `cosign_above` disables that approval threshold. At least one must be nonzero. Each mint appears once. The circuit derives the approval bit, and the program requires the configured co-signer when it is set.

Limits apply to one transfer. There is no rolling counter. A cap of 100 permits two separate transfers of 60. Delegate moves remain exempt from outflow limits. They still need the delegate's signature, escrow, ordinary policy rules and any transfer-scoped co-signer.

## Sources and updates

Each source slot stores a list ID and a registry address. Zero means this ring's registry. A nonzero address names a curator's registry root account. One policy can use one distinct curator. It reads that registry directly. Sources do not recursively follow another policy's source map.

```toml
[policy.sources.devnet]
block = "<curator program ID>"
```

Several rings can use the same curator. The curator's list writes affect them without copying records or replacing their rules. Curators are configured per cluster.

The upgrade authority creates or replaces the rule table. The config authority writes authority lists and can change the source of a referenced list. Policy writes validate the table, recompute its hash and increment the generation. A changed table or source invalidates proofs for the old policy. An identical re-pin increments generation without changing the proof statement.

Membership changes publish a new root. Older roots remain accepted until they leave the 32-root history. A cleared Allow bit or a newly set Block bit therefore does not promise immediate revocation. This is different from changing the policy table.

The address-tree binding stays fixed for the ring. It remains part of the policy statement. It no longer stores list-entry addresses. Registry capacity is determined by the separate member tree.

## Mutation authorization and escrow

`Allow`, `Block`, `Frozen`, `Reader` and `Approval` are authority-written lists. `RingViewing`, `Recovery` and `Escrow` are member-written. The policy grammar permits only authority-written lists in rules. Setting the member-written Escrow bit does not register a nullifier key.

`UpdateMembers` proves a batch of record changes. Each changed bit requires its list's writer. Even an unchanged record needs the authority or matching member to sign. An unsigned no-op cannot advance the registry or rotate its root history. The program checks that every escrow commitment is unchanged before verifying the proof. This applies even when the member or authority signs.

`RegisterKey` proves encryption of the member's nullifier key to the configured auditor. It can insert an absent record or fill the empty escrow commitment of an existing record. It preserves all list bits. Photon projects registration using the stored authenticated list bits. Redundant list fields in registration data cannot replace them. A registered key is final. List writes cannot establish, replace or clear it.

Registry mode requires the output owner's escrow commitment. The auditor can recover notes using the registered key. A delegate is a separate authority and must sign a move. Anonymous mode does not support delegation. The reference ring rejects public legs on the delegate path. SPP’s authority rail alone allows withdrawals, so each ring must enforce that restriction itself.

## Proving compliance

The SDK reads the table and authenticates member records for each subject. The proof opens the transaction's notes, applies every enabled rule, checks outflow and escrow, then encrypts auditor disclosure from those same fields.

The optimized proofs take 78 public fields. The program builds these from its own policy account, accepted registry roots and resolved SPP tree accounts. The prover cannot replace the policy table through instruction data. The proof remains 192 bytes.

General registry proofs accept scattered records. Shared-path proofs save constraints when every queried record in a registry lies in one aligned block of eight leaves. Absence uses the predecessor's index. The own and curator registries can use different blocks. Both paths enforce the same policy.

The ring verifies its proof before calling SPP. SPP independently checks the settlement proof and changes the note and nullifier trees. Audit-only rings omit the policy proof obligations but still require auditor disclosure. Ordinary recipient ciphertext remains wallet-side.

See [proof costs](../custom-rings/proof-costs.md) for supported capacities and [the audit map](../custom-rings/audit-readiness.md) for constraint attacks and integration coverage. A supported shape must still fit 4,096 transaction bytes and 64 accounts. No rule is waived to make it fit.

## The CLI

`zolana-ring new --policy-from <file>` imports and validates a policy. `init` creates the registry and pins the table before registering the ring with SPP. The tier is fixed at config creation. An audit-only ring cannot later become a policy ring.

`policy show` prints the stored rules and generation. `policy check` compares them with `ring.toml`. `policy set` replaces the table under the upgrade authority. `list set-source <list> --curator <program ID>` selects a curator, and `--own` returns to this ring's registry.

`list add|clear|show <list>` accepts one of `--owner <tag>` or `--asset <mint>`. Use `sol` for the native mint. List writes update this ring's registry. Curated lists must be edited at their source. `transact` and `transfer` require `--cosigner-keypair` when approval is needed.

The [worked examples](../custom-rings/examples) cover audit-only, empty policy, blocklists, curator approval exceptions, allowlists, per-mint owner thresholds and outflow limits. The CLI tests parse and render every example. Old list notes and P-256 auditor configs need migration before deploying this protocol.
