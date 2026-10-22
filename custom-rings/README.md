# Custom rings

No audit report is checked in.

A custom ring is a Solana program that governs a group of SPP notes, the notes
whose ring program id is its own. Every transfer, deposit and merge of those
notes passes through the ring program. The program verifies the ring's proofs
over the SPP instruction, then forwards that instruction to SPP signed by its
`ring_auth` PDA. SPP still checks inclusion, nullifiers and value
conservation, and the owner's authorization of each transfer outside the
delegate rail.

`program` is the ring program, and `interface` holds its account layouts,
instruction data, statements and errors. `policy` defines the lists and the
rule table, `member-registry` the record tree, and `indexer` applies record
writes for Photon. `transaction` encodes ring outputs, `sdk` builds, proves and
submits ring operations, and `client` is the auditor side. `cli` is the
`zolana-ring` operator binary, `test` holds the lifecycle tests on a local
validator, and `examples` holds one `ring.toml` per worked example.

A ring is one program deployment with one config. The config holds the auditor
key, the tier and whether the ring is confidential or anonymous.
The tier is policy or audit-only. One released program binary serves every
ring.

The guides cover [member records](docs/member-records.md),
[auditing](docs/auditing.md), [anonymous rings](docs/anonymous-rings.md) and
[the policy language](../docs/ring-policy.md). The byte layouts and statements
are in [Ring Program Interface](../docs/spec.md#ring-program-interface).

## Threat

A sender may try to move ring value past the ring's rules or to hide a note
from the auditor. Either needs an SPP instruction the ring program forwards.
The program forwards one only when its proofs verify against statements it
rebuilds from the instruction bytes, the slot and the accounts below. The ring
should refuse every transfer, deposit and merge that hides a note from the
auditor, and every transfer that breaks a rule, provided that

a) the verifying keys built into the program come from a sound setup of the
   pinned circuits,
b) SPP verifies its own proof over the instruction the ring forwards, and
c) the auditor key in the config belongs to the auditor.

The program trusts its config, member registry and record queue by owner and
discriminator. It trusts a curator registry by the address the policy names
and by its `members` PDA under the owning program. It trusts an anchor root by
SPP's ownership of the tree. It requires the payer's signature and the source
signer of every public deposit. The confidential rail also requires every
owner signer, and the delegate rail requires the configured delegate. A
demanded co-signer signs on every rail.

The program and the proofs do not check that a sender pays the address it
meant to pay. They do not check that a change or padding tag is random. They
do not check delivery on the packed layouts. See
[Limits](docs/auditing.md#limits).

## Rings and rails

A **confidential ring** hides amounts and assets. The owners of the spent
notes sign the transaction with their Solana keys, so senders are public. Each
ring output publishes its recipient's X25519 viewing key as its owner tag, so
an observer links every output paid to the same recipient.

An **anonymous ring** also hides senders and recipients. The sender signs
inside the SPP proof, and among the SPP accounts only the payer signs.
Each payment carries a tag its recipient scans for. See
[anonymous rings](docs/anonymous-rings.md).

A **policy ring** proves its rule table for every transfer, and an
**audit-only ring** proves the auditor disclosure alone. In both tiers every
transfer, deposit and merge proves what the auditor reads.

`Transact` settles a member transfer on SPP's confidential ring rail or its
anonymous ring rail, chosen by the config's `mode`. `DelegateTransact` lets the
ring's **delegate** move members' notes over SPP's ring authority rail. The
delegate signs in place of the owners, and a policy proof still applies every
rule. The ring refuses a public leg and an exit on that rail, so a delegate
cannot withdraw. SPP refuses the rail until governance enables it for the
ring.

Setting a delegate starts **key escrow**, and no instruction stops it. See
[Escrowed nullifier keys](docs/auditing.md#escrowed-nullifier-keys). The
delegate needs a confidential policy ring with a member registry.

## Roles

The **upgrade authority** deploys and upgrades the program, and only it creates
the config and sets the delegate.

The **config authority** writes the policy, the authority lists, the
co-signer, the insert fee and the reader grants. It pauses and resumes the
ring and registers it with SPP. `CreateConfig` gives the role to the upgrade
authority that signs it. `SetAuthority` gives the role to a new key, and both
keys sign.

The **auditor** holds the X25519 key the config stores. It reads every
transfer, deposit and merge, and its key authorizes no spend. The ring RPC
holds that key and serves the **readers** the config authority grants. See
[Reading a ring](docs/auditing.md#reading-a-ring).

A **curator** is another ring whose member registry serves lists of the
ring. The curator writes only its own records. Each subscriber trusts those
records for every list it reads from the curator.

The **co-signer** is a Solana key the config stores with a scope of operation
classes and per-mint withdrawal thresholds.
[Ring configuration](../docs/spec.md#ring-configuration) states the operations
it signs.

The **delegate** is a Solana key the upgrade authority sets once.
`zolana-ring delegate move` takes the delegate keypair and the auditor key, so
one operator holds both.
[Member records](docs/member-records.md#members-and-lists) defines a
**member**. **Governance** controls the ring's activation and its delegate
rail in SPP.

## How a transfer settles

1. The client builds the SPP transfer and the ring's compact transaction data.
   The data carries the audit proof, the policy proof on a policy ring, and the
   SPP proof with its `b` point compressed.
2. The program parses the data, each section sized by its flags, its shape
   and the counts and length prefixes it carries. It refuses trailing bytes
   and a zero disclosure field.
3. It checks the rail's signers, the funder of each public deposit and the
   co-signer that the config or the approval bit demands.
4. It rebuilds the audit statement and, on a policy ring, the policy statement
   from its accounts, the instruction and SPP's public amounts. It verifies
   each proof.
5. It invokes SPP with the expanded transact data and the `ring_auth` signer.

The audit statement binds the first nullifier and the published output hashes
that the SPP proof binds, so the auditor reads the transaction SPP settles.
Every proof attempt carries a fresh random salt. A retry under the same first
nullifier therefore repeats no keystream, disclosure pad or ring output
blinding.

## Shapes

SPP has keys for the 38 [supported shapes](../docs/spec.md#supported-shapes)
of `n_in x n_out`. The ring has audit and policy keys
for every one of them on the confidential rail. The anonymous rail has keys
for up to 32 published inputs at 2 outputs, 24 at 4 outputs, 16 at 8 outputs
and 1 at 16 outputs. The SDKs publish every input slot of an anonymous
transfer, so through them the rail serves exactly these shapes. An anonymous
transfer that spends a default-ring note takes at most 8 inputs and 8 outputs.
The delegate rail has keys for every shape up to 40 inputs.

Every rail has keys for more shapes than fit in one transaction. A v1
transaction carries at most 4,096 bytes and 64 addresses, and the bytes are
the first limit a shape reaches. The SDK test
`every_transfer_shape_takes_its_pinned_transaction_size` pins the bytes of
every keyed shape for each rail and tier, and it measures each policy ring with
a co-signer. It measures the confidential policy ring under key escrow.
Without key escrow that ring discloses one more field per output, so more
shapes exceed the limit. A
confidential audit-only ring cannot fit 8x16, 48x2 or 49x2. A confidential
policy ring under key escrow cannot fit 40x2, 48x2 or 49x2. An anonymous
policy ring cannot fit 32x2 or 1x16. The delegate rail cannot fit 40x2. A
curator, a second input tree,
an exit or a public leg adds bytes. The SDKs measure the transaction before
they prove and refuse one past the limit.

## Prerequisites

`zolana-ring` comes from a custom-rings release of this repository. The
release also ships the ring program, the ring proving keys and the ring RPC.
`zolana-ring deploy` runs `solana program deploy` and needs the Anza `solana`
CLI on `PATH`. A command that finds a tool missing fails and says how to
install it.

`zolana-ring localnet` runs `zolana dev start` and also needs the `zolana` CLI
of a zolana release and the Anza `solana-test-validator` on `PATH`. It
starts the validator, Photon and the prover, then the ring RPC with
`keys/auditor.key`, created when missing.

## Steps

1. `zolana-ring new` asks for the ring name, the service URLs of localnet and
   devnet, the target, the mode and the policy. It writes the ring directory,
   `ring.toml`, `keys/program-keypair.json` and a `.gitignore` for `keys/`
   and `.env`. The program keypair fixes the program id. Finishing without a
   policy option gives an audit-only ring, and `--policy-from <file>` imports
   a `[policy]` table.
2. `zolana-ring localnet` or `zolana-ring devnet` records the target.
   Localnet starts its services, and devnet probes the indexer and the prover.
3. `zolana-ring deploy` deploys the release program under the upgrade
   authority and checks the deployed bytes.
4. `zolana-ring init` takes the auditor key and creates the config. It creates
   the member registry and its queue, pins the policy of a policy ring and
   registers the ring with SPP. A rerun resumes at the first missing step.
5. On a pool without permissionless activation, governance activates the
   ring with SPP's `set_ring_activation`. `zolana-ring status` shows the
   activation.
6. `zolana-ring reader grant <reader>` admits a reader to the ring RPC. The
   grant holds until `reader revoke` closes it.
7. `zolana-ring list add|clear <list> --owner <address>` or `--asset <mint>`
   writes the authority lists. Members run `list join|leave` and
   `key register`, and `list apply` applies a due queue. See
   [member records](docs/member-records.md).
8. `zolana-ring cosigner set`, `insert-fee set` and `delegate set` configure
   the controls.

`zolana-ring pipeline` starts the localnet services on the localnet target, then
runs deploy, init, the authority's reader grant and a demo `transact`. It checks
a hosted ring RPC before `init` and a local one after it. `transfer`, `deposit`,
`merge` and `address` use the sender key in `keys/sender-keypair.json`.
`authority pause` stops every deposit, transfer and merge of the ring in SPP,
and `resume` opens it again. `policy show|check|set` reads and replaces the
pinned table. See [the policy language](../docs/ring-policy.md).

## Integration

The Rust SDK is `custom-ring-sdk`. `CustomRing::new(program_id)` returns the
ring handle. Its methods derive the ring's addresses, read its config, registry,
queue, pinned policy and status, and build the admin instructions. Every `prove`
is `async` over an `AsyncZolanaClient` and fails with a `RingError`.

`CustomRingTransfer` proves a confidential transfer from a
`ConfidentialTransaction`. `with_anonymous_signer` makes it an anonymous
transfer, and `with_payment` adds each payment. `DelegateTransfer` builds a
delegate move.
`prove` requests the SPP proof, the audit proof and the policy proof together.
It verifies the audit and policy proofs, and the SPP proof only when the
prover fetches the proof data. It refuses a rule the transfer breaks, an
outflow past its cap and an output owner without an escrowed key before it
proves.

`MemberListWrite`, `AuthorityListWrite` and `RegisterKey` write member
records, `RecordApplication` applies the queued writes, and `MemberRecords`
reads verified openings. `RingDeposit` and `CustomRingMerge` build audited
deposits and merges. `RingSubmission` proves, signs and sends a
`RingOperation`. It makes at most three attempts. A blockhash expiry, a stale
root or an oversized authority batch causes a new proof. A
`ProofVerificationFailed` causes a new proof only after a value the proof binds
changes or its epoch passes. Wallet sync of an anonymous ring is
`AnonymousRingSync` in `zolana-client`.

The TypeScript SDK exposes the ring under `@heliuslabs/zolana/ring`. See
[its README](../sdk-libs/ts/README.md#custom-rings).

The auditor side is `zolana-ring-client` in Rust and `auditRing`,
`auditRingMerges` and `recoverRingMemberNotes` in TypeScript. See
[auditing](docs/auditing.md). The operator CLI in `cli` reads a `ring.toml`
and exposes `parse_and_run`.

## Limits

A new auditor key, tier or choice of confidential or anonymous needs a new
ring.

A ring merge spends at most 50 inputs and an anonymous merge at most 24,
because a wider merge does not fit one v1 transaction.

## Pitfalls

The program creates its config and registry at the seeds `config` and
`members`, and it refuses an account of another layout at either address. A
ring of another layout therefore deploys as a new ring under a new program
id. `zolana-ring deploy` refuses to upgrade a program whose config or
registry the release does not decode.

Renouncing before `init` leaves the program without a ring, and a renounced
program takes no delegate. `authority renounce` refuses before `init`.

`init` asks the ring RPC for the auditor key only when `keys/auditor.key.pub`
is missing. It accepts a key the service signs with the key `ring.toml` pins
in `ring_rpc_pubkey`. Without a pin it accepts the key only with
`--trust-ring-rpc`, a flag for a local instance. A local key file against a
hosted ring RPC needs `--local-auditor`.

Keys and `.env` belong in a secret store. `status` and the URL list of `devnet`
and `localnet` show only the origin of a service URL. The `devnet` probes and
error output mask an `api-key=` value. `zolana-ring url` prints the complete
URL.
