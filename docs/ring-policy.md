# Ring policy

A [policy ring](../custom-rings/README.md#rings-and-rails) keeps its rule table
in its member registry account, and the program hashes the table at every
policy write. Each policy proof binds that hash. The rules read the
[member records](../custom-rings/docs/member-records.md) of the transfer's
subjects, and the proof opens those records privately. The table hash and the
policy statement are in [Policy proof](spec.md#policy-proof).

## Rules

A rule names a subject, a present set of lists and an absent set of lists. A
rule holds for a subject that is on any list of its present set, or off any
list of its absent set. A transfer meets the rules when every rule holds.
Separate rules therefore join with AND, and the lists inside one rule join with
OR.

A rule applies to every live instance of its subject:

- `sender` is the one owner who spends. It is the owner signer of a
  confidential transfer, the hidden owner of an anonymous transfer, and the
  source member of a delegate move.
- `output-owner` is the owner of each output note, including the sender's
  change and every output that leaves the ring.
- `asset` is the asset of each output note.

An absent member reads as on no list, so it fails a `require` and passes a
`forbid`. One `ring.toml` row is one rule:

```toml
[[policy.rules]]
subject = "output-owner"
require = "allow"

[[policy.rules]]
subject = "sender"
forbid = "frozen"

[[policy.rules]]
subject = "output-owner"
any = [{ require = "approval" }, { forbid = "block" }]
```

`require` puts one list in the present set and `forbid` one list in the
absent set. `any` takes several alternatives of both forms, and the rule holds
when one alternative holds. An asset rule screens mints through the same
lists.

A rule reads only the authority lists. See
[Members and lists](../custom-rings/docs/member-records.md#members-and-lists).
A table with a rule over `ring-viewing`, `recovery` or `escrow` is refused
when it is written, because the members write those lists themselves.

## Amount guards

An `above` guard waives a rule while the amount stays at or below the
threshold. An output-owner rule sums each owner's outputs, and an asset rule
sums each asset's outputs. Splitting a payment across slots therefore does not
evade the guard. A sender rule takes no guard. An output-owner rule with
`above` requires every output of the transfer to carry one mint.

An output-owner rule with `limits` groups the outputs by owner and mint. It
applies the rule to a group above its mint's threshold, and it refuses an
output in a mint without a threshold. Every rule with `limits` in a table
shares one threshold map.

```toml
[[policy.rules]]
subject = "output-owner"
require = "allow"
limits = [
  { asset = "11111111111111111111111111111111", above = 1000000000 },
  { asset = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", above = 1000000 },
]
```

## Outflow limits

An outflow limit bounds what one transfer moves out of the sender's ring
balance in one mint. The outflow counts every output that leaves the sender,
to another owner or out of the ring, adds every withdrawal and subtracts
every deposit. The proof shows the outflow is never negative, so a deposit
offsets at most what leaves the sender.

```toml
[policy]
limits = [
  { asset = "11111111111111111111111111111111", cap = 5000000000, cosign_above = 1000000000 },
]
```

A nonzero `cap` bounds the outflow. An outflow above a nonzero
`cosign_above` sets the transfer's approval bit, and the program then demands
the ring's co-signer. A ring without a co-signer refuses that transfer. Each
mint appears once, and each limit sets at least one bound.

A limit bounds one transfer, and the ring keeps no counter across transfers.
A cap of 100 admits two transfers of 60. A delegate move skips the limits, but
its proof still applies every rule.

## Sources and curators

Each list a rule reads has one source, the ring's own registry or a curator's.
A policy names at most one curator. A list `[policy.sources]` leaves out reads
the ring's own registry. The curator's writes reach every subscriber without a
copy of the records. Sources are set per cluster:

```toml
[policy.sources.devnet]
block = "<curator program id>"
```

Curator roots follow the floor and grace rules of
[member records](../custom-rings/docs/member-records.md#roots-floors-and-curators).
`zolana-ring list set-source <list> --curator <program id or name>` makes that
curator's registry the source of one list the table reads. `--own` returns the
list to the ring's registry. The CLI checks that the curator serves the list
from its own registry.

## Writing the policy

A policy ring pins its first table with `CreatePolicy`, and `SetPolicyRules`
replaces the table and the source map together. `CreatePolicy` refuses an
audit-only ring. `SetPolicySource` re-points one list. The config authority
signs every policy write. The program validates the table, rehashes it and
counts the write in the registry's generation. A transfer proven against the
old table fails after that write, and its notes stay unspent.
`InitSppRingConfig` registers a policy ring with SPP only after
`CreatePolicy`.

An auditor reconstructs the table history from the transaction history of the
member registry account. Every policy write is a signed instruction on that
account. `generation` counts the writes, and `generation_slot` names the slot
of the last one.

`zolana-ring policy show` prints the pinned table and its generation. `policy
check` compares it with `ring.toml`, and `policy set` replaces it after a
confirmation. An empty `[policy]` table pins no rule and no limit, and a later
`policy set` adds them.

## Limits

A table holds at most 16 rules, 8 mint thresholds and 8 outflow limits. A
policy transfer has exactly one sender, so it never spends the notes of two
owners.

Transaction size limits the shapes each rail serves. See
[Shapes](../custom-rings/README.md#shapes).
[The proof costs](../custom-rings/proof-costs.md#policy-statements) give the
policy key costs and the budgets of the keys of 2 and 4 outputs.

The [worked examples](../custom-rings/examples) cover an audit-only ring, an
empty policy, an own blocklist and a curated blocklist with an approval
exception. They also cover allowlists, per-mint owner thresholds and an
outflow limit.
