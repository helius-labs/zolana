# Custom rings

A custom ring gates UTXOs tagged with its program id inside the Solana Privacy
Program. Their owners still hold the spending keys. The ring checks its
policy and authorizes SPP settlement with its `ring_auth` PDA. SPP verifies
the selected transfer or merge statement and maintains the trees and nullifiers.
Each ring is its own program deployment with its own authority, config and
services. Every custom ring is audited. The custom-ring circuit binds each
transfer to the ring's auditor and the program accepts no transact without
that proof.

`program` is the ring program, `sdk` the Rust client for it, `cli` the
`zolana-ring` operator binary, `test` the lifecycle test on a local validator,
`examples` one `ring.toml` per worked policy. The ring RPC in
`services/ring-rpc` holds the auditor key, `custom-rings/client` is the auditor
side it is built on. A custom-rings release (`just release-custom-rings <tag>
--upload --prerelease`) ships `zolana-ring`, the ring program, the ring
proving keys and the ring RPC together, the CLI deploys the binary of the
release it was built from. One released binary serves every ring, the rules
are data `init` pins from `ring.toml`.

See the [change overview](changes-overview.md), [proof costs](proof-costs.md) and
[audit map](audit-readiness.md) for the current guarantees and their tests.

## Reading the proof boundary

1. [`RuleTable`](policy/src/rule_table.rs) defines the obligations.
   [`PolicyConfig`](interface/src/state.rs) pins their hash, sources and address tree.
2. [`transaction.go`](../prover/server/custom_rings/circuits/policy/transaction.go)
   binds private slot openings to SPP's transaction hash.
   [`subjects.go`](../prover/server/custom_rings/circuits/policy/subjects.go)
   authenticates member records, and [`evaluate.go`](../prover/server/custom_rings/circuits/policy/evaluate.go)
   applies the rules to those openings.
3. [`limits.go`](../prover/server/custom_rings/circuits/policy/limits.go)
   bounds each transfer's outflow per mint and sets the approval bit.
4. [`transact.rs`](program/src/instructions/transact.rs) binds the proof to
   trusted accounts, checks public controls, and forwards the
   settlement to SPP.
5. [`pipeline`](sdk/src/pipeline/mod.rs) assembles the client proof inputs.
   [`indexer`](indexer/src/lib.rs) validates member transitions and builds the
   member registry's Merkle overlay. Photon owns block fetching,
   persistence and replay. Clients validate its proofs against the requested root
   before using them.

`PolicyConfig` stores the sixteen packed rules, eight list sources, eight
mint-specific amount thresholds and eight outflow rows. It also stores the
policy hash and update generation. A source names this ring's registry or a
curator's registry. A ring can use one curator.

Membership lives separately. `MemberRegistryRoot` stores the last 32 Merkle
roots and the next leaf index. Photon reconstructs each leaf as
`[member | next member | 64-bit list bitmap | escrow commitment]`. One record holds
all an owner's or mint's list memberships. List changes preserve its escrow
commitment. The program rejects an escrow change in a list update before proof
verification. Only proved key registration can set an empty escrow
commitment. A registered key is final. Registration preserves the list bits. The encrypted recovery
key travels in registration data and is indexed with the record.

This replaces versioned SPP list notes and their revocation proofs. Transfers
read a registry snapshot without changing it. A changed policy hash rejects
proofs for the old rules immediately. A list change can still leave an older
snapshot usable until its root leaves the 32-root history.

## Roles

The operator holds the upgrade authority keypair and the ring directory. It
deploys and upgrades the program, creates the config, pins the policy of a
policy ring and replaces its rule table, registers the ring with SPP, hands
the authority over or renounces it. The ring authority is the key in the ring
config, the operator's by default. It grants and revokes readers, pauses and
resumes the ring, writes the authority-written lists and points a list at a
curator or back at the ring's own entries. A curator is a ring whose lists
other rings read. It writes its own entries and touches nothing on its
subscribers, every subscriber trusts its writes wholly.
The auditor holds the ring's X25519 viewing key and reads transfers. That key
does not authorize a transfer to another owner or a withdrawal. A permanent
delegate is a separate Solana signer authorized to move members' notes. An
operator holding both keys can recover notes as the auditor and move them as
the delegate. A reader is a Solana key or a passkey the authority granted and
reads what the auditor reads. A participant is a shielded wallet that
deposits into the ring and transfers inside it.

The authority is a plain signer, a Squads vault holds it through proposals,
and `SetAuthority` hands it to another key, signed by both, readers, lists and
the pause move with it.
Readers are on-chain records, so the same proposal flow grants a regulator a
passkey without anyone sharing a key.

## Controls

A co-signer is a second Solana key the authority sets with `zolana-ring
cosigner set`, scoped to transfers, deposits, withdrawals or any mix. Every
transact and merge is a transfer and a public leg adds its class, so a
transfer cannot hide behind a small deposit. Withdrawals carry per-mint
thresholds summed over the legs of one transaction, a withdrawn mint without
a threshold always needs the co-signer. The `[cosigner]` table of `ring.toml`
holds the key, the scope names and the thresholds, `cosigner set` without
flags applies it. `cosigner clear` removes scoped approval. A proof-derived
approval requirement still fails without a configured co-signer. The transact,
transfer and merge commands take
`--cosigner-keypair`.

A permanent delegate is a Solana key the upgrade authority sets once with
`zolana-ring delegate set` and no instruction replaces or removes. The program
remains upgradeable. The delegate must sign each move. It moves notes between
members over the shielded pool's authority rail. Its dedicated policy key
keeps audit, list rules and ordinary amount guards and exempts the outflow
limits and their approval demand. The members' identities are
the screened parties. The ring refuses a public leg on that rail, so a
delegate cannot withdraw, and the shielded pool refuses the rail until
governance enables it for the ring with `set_ring_activation`. A move spends
the source member's notes with that member's nullifier key. `init` creates
the ring's member registry, a member-keyed tree the ring owns and Photon
indexes, and `transact` and `transfer` escrow the sender's key there on
first use, sealed to the ring auditor's X25519 key with a proof that binds
the ciphertext to the auditor the config pins. `zolana-ring key register`
runs that step alone. Registration binds the member's signature to an
encrypted nullifier key, but does not prove that the key matches the member's
existing notes. The SDKs check the supplied shielded address before proving.

The current delegate CLI expects one operator to hold both roles. `delegate
set` requires the matching `keys/auditor.key` and an initialized registry.
`delegate move --auditor-key` decrypts the registered nullifier key and
reconstructs unspent notes, then the delegate's Solana key signs the move.
The auditor key supplies proof material, not transfer authorization. The chain
checks the delegate signer independently and does not require the same
operator to hold both keys. A hosted ring RPC does not provide a local
auditor secret. Recovery requires a usable registered key and recoverable
note openings. SPP's existing merge rail is signatureless and preserves owner
and value. Recovered note material can support a merge, but cannot redirect
funds through that rail. A transfer-scoped co-signer gates
a delegate move like any transfer. A compromised delegate is contained by
governance disabling the rail or the authority pausing the ring.

Setting the delegate turns on key escrow, and no instruction turns it off.
`set_delegate` refuses an audit-only ring and a ring without an initialized
member registry. From then on the ring checks every UTXO output of a member
transfer, a delegate move or a deposit. Each output carries a key registered
for its owner, proven against one of the registry's last 32 roots. A plain
deposit is refused with
`DepositAuditRequired`, the audited deposit carries the check in its proof. A
merge keeps the key of its inputs. Notes created before the delegate is set
carry no check, so members register first. The SDKs refuse an unregistered
output key before proving, `UnregisteredOutputKey` in Rust. Ed25519 owners
sign registration directly. A PDA owner
registers only through a signed CPI from its program. A transact or an audited
deposit names the history slot of the registry root its proof binds, and a slot
no root was written to fails as `StaleMemberRegistryRoot`. `register_key` needs no
ring authority. Registrations and list updates both advance the root history.
Enough updates between proving and landing overwrite that slot and the
program rejects the proof. The SDK submissions
then read the history, find another root at the slot and prove again.

Deposit auditing is optional and defaults to off. `deploy --deposit-audit`
records the choice in `ring.toml`, and `init` applies it when creating the
ring config. The config authority can change it with `deposit-audit set
--required true` or `false`. The setting lives in a separate `deposit_audit`
PDA, without resizing the config or changing the auditor key.

When enabled, a direct deposit must prove that each auditor ciphertext opens
the owner commitment accepted by SPP. The ciphertext carries the owner hash
and blinding. Mint, amount and data commitments remain public. One proof covers
up to eight outputs, subject to the transaction size limit. The program checks
the pinned auditor, destination tree and exact deposit bytes before settlement.
Disabling the setting permits proofless deposits again. Existing deposits gain
no disclosure when the setting changes.

Asset screening uses registry lists, just like owner screening. For example,
`subject = "asset"` with `require = "allow"` checks the mint's Allow bit.
Use `zolana-ring list add allow --asset <MINT>` to set it, or `list clear` to
remove it. A list may come from the ring's own registry or its configured curator.
The old `assets = [...]` rule form is rejected. There is no eight-mint membership
cap. The eight-entry asset tables that remain configure amount thresholds only.
Scalar owner amount guards require all live outputs to use the same mint.
Use per-mint guards for mixed-mint transfers.

An outflow limit bounds what one sender moves out of its own balance per
mint in one transfer, shielded payments, exits and withdrawals alike, and
demands the co-signer on a transfer above a threshold. The `limits` array of
the `[policy]` table in `ring.toml` holds up to eight entries of mint, cap and
co-sign threshold, a zero cap leaves the mint uncapped and a zero threshold
disables the co-sign demand, and only the upgrade authority moves them. Each
transfer stands alone against its cap, the ring keeps no record and no
counter. The circuit sets the approval bit when an outflow passes a
threshold, the instruction carries that bit, and the program demands the
configured co-signer for it. The `transact` and `transfer` commands refuse to
send a transfer the proof marks for approval without `--cosigner-keypair`.

Ring controls require a fresh deployment. No state migration is provided.
The policy statements also require matching program verification keys, prover
keys and SDKs. Install the keys pinned by
`prover/server/prover/provingkeys/proving-keys.lock` together with the program.

## How auditor visibility works

Every transfer encrypts its transaction viewing key to the X25519 auditor
under a fresh ephemeral key. It also publishes a dedicated encrypted audit
record. The proof binds the encrypted secret to the published viewing key.
It also proves that the audit record contains the note fields used to compute
the output commitments.
Anonymous mode also discloses the sender, spent notes and recipients.

SPP binds these messages to the transfer. A valid transfer cannot hide its
committed outputs behind a different auditor ciphertext. Ordinary recipient
ciphertexts remain wallet-side and are outside this guarantee.

The order is fixed by the hashes. SPP hashes the messages into
`external_data_hash`, which the SPP proof commits to, and `private_tx_hash` is
a public input of the custom-ring circuit. `CustomRingTransfer::prove`
therefore encrypts the message first, runs the SPP proof over the
message-bearing external data, and only then finishes the custom-ring proof
over the resulting `private_tx_hash`. `CustomRingProofParams::encrypt` returns
a `PendingCustomRingProof` that only `finish` turns into proof inputs, so the
order cannot be broken by accident.

What this means when operating a ring. The auditor key is fixed at
`create_config`, changing the auditor means a new ring. While the program has
an upgrade authority only that key may create the config, so renounce after
`init`, not before. The auditor secret lives in the ring RPC, never in the ring
repository. A ring runs its own RPC from a key file, or takes a key from a
hosted RPC that derives one key per ring from a root secret and signs the key
it hands out. The ring pins that service key in `ring.toml` so a wrong auditor
cannot be slipped in at `init`. A transfer built with `with_ring_program_id`
binds its change and recipient notes to the ring, so value stays in the ring.
Exits are explicit, an owner may withdraw or `send_default_ring` to a default
pool note, and every such transact still carries the custom-ring proof, so the
auditor sees the exit. An exit slot is a default-ring slot on chain, its owner
tag is public like any default note. An entry moves the change into the ring
with the sent amount. A note bound to another ring is refused before proving.

## Prerequisites

`zolana-ring` from a custom-rings release of this repository, the release also
carries the ring program it deploys. On `PATH` before `zolana-ring deploy`:

- **Anza / Solana CLI** 4.x, the version CI pins —
  `sh -c "$(curl -sSfL https://release.anza.xyz/v4.0.2/install)"`. It deploys
  the program.

`zolana-ring localnet` runs `zolana dev start`, so the `zolana` cli of a
localnet release of this repository is on `PATH` too. Photon, the prover, the
SPP programs and their protocol accounts come from that release, the
validator is the release-pinned Surfpool runtime. The ring RPC and the prover's
ring keys come from the custom-rings release the ring cli came from, and
the ring RPC serves `keys/auditor.key`, created when missing. A rerun
keeps a live validator and its ledger and replaces the ring RPC with this
ring's. `pipeline` and `deploy` on localnet start whatever does not answer
before deploying, so `zolana-ring pipeline` alone brings a ring up. `just
ring-localnet` needs this repository's localnet prerequisites instead.

### Workspace localnet

Build the workspace CLI, Photon, ring RPC, xtask, prover and SBF programs first.
The ring keys must match `prover/server/prover/provingkeys/proving-keys.lock`.
Local mode verifies these files and fetches no custom-rings release.

```sh
cargo build -p photon-indexer --bin photon --features surfpool-fixture,custom-rings
export ZOLANA_RING_WORKSPACE=/absolute/path/to/zolana
export ZOLANA_PROCESS_SCOPE_DIR="$(mktemp -d)"
export SURFPOOL_BIN=/absolute/path/to/pinned/surfpool
export ZOLANA_RING_SURFPOOL_FIXTURE=1
"$ZOLANA_RING_WORKSPACE/target/debug/zolana-ring" dev
```

The `custom-rings` feature compiles the custom ring worker and RPC methods.
Photon runs the worker and serves those methods unless it is started with
`--disable-custom-rings`. Plain Photon builds have no custom ring
dependencies.

The fixture feature repairs Surfpool's synthetic parent block hashes on
loopback RPC only, opted in with `ZOLANA_RING_SURFPOOL_FIXTURE=1`. Production
builds leave it disabled and require the original parent hash links.

The ring RPC stays in the foreground. In a second terminal, reuse those exact
environment values and run `zolana-ring pipeline` from the ring directory.
Deployment uses the workspace program. Existing SPP keys must be cached or
available through the prover's configured manifest downloader. For concurrent
stacks, set `ZOLANA_PROVER_KEYS_DIR` to a separate cache holding the ring
keys the lock pins, two stacks sharing one cache collide on the download's
`.tmp` file.
To stop the base services, use the same environment and
`"$ZOLANA_RING_WORKSPACE/target/debug/zolana" dev start --local --stop` with
the RPC, Photon and prover ports from `ring.toml`. Only task-owned process
receipts authorize a stop.

`just test-custom-ring-validator` installs the pinned Surfpool under
`target/tools` unless `SURFPOOL_BIN` names one, runs under its own temporary
process scope and verifies the ring keys in `prover/server/proving-keys`
against the lock. Ports default to 40899 (RPC), 40784 (Photon) and 43001
(prover) plus `ZOLANA_PORT_OFFSET`, `RING_TEST_RPC_PORT`,
`RING_TEST_PHOTON_PORT` and `RING_TEST_PROVER_PORT` override them. An occupied
port refuses the run. Logs remain in the printed scratch directory.

## The pipeline and what each step locks in

`zolana-ring new` is a wizard. It asks for the ring name, the service URLs of
both clusters and the target, then offers common policy options and an
advanced rule builder. Picking an option selects the policy tier. Finishing
without one selects audit-only. A policy uses the SPP default tree as its address tree,
writes it explicitly to `ring.toml`, and asks for a source only for each list
its finished rules read. Each option compiles as one unit when added. The
wizard prints the `ring.toml` it will write and asks before writing. It writes
the ring directory, `ring.toml` with the answers and
`keys/program-keypair.json`, and fixes the program id, the address of that
keypair. `--silent` takes every default, an audit-only ring. `--policy-from
<file>` takes the `[policy]` table of a `ring.toml`, an example's included,
checks it on both clusters and skips the policy option questions. It creates
the authority keypair when `--authority-keypair` keeps the default
`~/.config/solana/id.json` and no file is there, any other path is the
operator's and a missing one is only reported. A curated list is picked from
the catalogue, the bundled `cli/catalogue.toml` per cluster merged with every
ring registered with SPP on the target that pins a policy,
`--catalogue <path or URL>` (`RING_CATALOGUE`) replaces the bundled file. The
policy grammar and the worked examples are in
[`docs/ring-policy.md`](../docs/ring-policy.md). In the ring,
`zolana-ring devnet` picks devnet and probes its services, `zolana-ring
localnet` picks localnet and starts them. `zolana-ring deploy` downloads the
ring program of the release the CLI came from, checks it against the lockfile
built into the CLI, and
fixes who may `init`, the upgrade authority. `--program-so` deploys a local
build instead. A cli whose embedded release ships no ring program refuses
`deploy` and names `--program-so`. A ring with a `[policy]` section is a
policy ring, the same binary serves it and an audit-only ring, the tier is
fixed at `init`. After the loader finishes, `deploy` reads the program back and
refuses to report success unless the bytes on chain hash to the file it
deployed. A binary already on chain byte for byte is reported present and
not uploaded again. `zolana-ring init` fixes the auditor. On a policy ring it
compiles `[policy]` for the target, checks that each curator is deployed,
pins a policy to the ring's address tree and serves its list from its own entries,
pins the table with `create_policy` under the upgrade authority, points each
curated list, reads the chain back and refuses a pinned policy differing from
`ring.toml`, then registers the ring with SPP, the program refuses to
register a policy ring before its policy is pinned. `zolana-ring policy show`
prints the pinned table with its generation, `policy check` compares it with
`ring.toml` and exits non-zero on a difference, `policy set` replaces it
under the upgrade authority, confirmed interactively or with `--yes`, proofs
built against the old table are refused from then on. After `init` the
authority can be transferred (confirmed interactively or with `--yes`, the
new key alone can hand it back) or renounced (confirmed the same way, and only
when the bytes on chain match the released program or the `--program-so`
given), readers come and go, and the program can be upgraded by running
`zolana-ring deploy` again. `zolana-ring authority pause` stops every ring
deposit, transfer and merge in SPP under the ring authority alone, `resume`
opens the ring again. `zolana-ring list add|clear <list>` writes the ring's
own entries, the member is `--owner <tag>` or `--asset <mint>`, `sol` for the
native token. `list show` takes the same flag and reads the entry from the
source the list points at. `list set-source <list> --curator <program id or
catalogue name>` or `--own` re-points a list under the ring authority. A mint
is a member like an owner tag, one list holds both kinds and a rule on
`subject = "asset"` reads the mints. `zolana-ring transact`
makes two ring deposits and one custom-ring transfer and reads it back, on a
policy ring whose rules reference `Allow` it enrols the sender and the
recipient in `Allow` first, unless a curator serves `Allow`. `zolana-ring
transfer` sends an amount to a shielded address. Both spend from
`keys/sender-keypair.json`, created on first use. Its change and fee budget
stay spendable with that key, keep it with the other keys.
`zolana-ring merge` syncs that sender, selects the smallest two to 24 clean
notes of one mint on one tree, and consolidates them. It merges SOL by default.
`--mint <address>` selects a registered SPL mint and `--count` caps the input
count, up to 54.
`zolana-ring pipeline` runs deploy to transact and takes `--program-so` like
`deploy`.

On devnet, configure the prover, indexer and ring RPC URLs in `ring.toml`.
They must run the matching release, including its proving keys and Photon's
member-registry projection. Photon enables custom-ring indexing by default when
built with its `custom-rings` feature. The CLI probes these services and does
not start them. A healthy HTTP endpoint alone does not prove key compatibility.
The hosted ring RPC derives one auditor key per
ring from a root secret, so it serves any ring that asks and a new ring needs
no restart. The order is what matters: a
ring takes its key from the service before `create_config`, because the config
fixes the auditor for good. `rpc-check` reports which of the three cases a ring
is in: served, registered with another auditor, or not yet initialized. `init`
refuses to pin a key from `keys/` against a service that holds its own.

The authority pays for every step. Localnet airdrops what a step spends,
devnet cannot, so a step it cannot pay for stops at the web faucet and
continues on the next keypress. Without a terminal the shortfall is an error.
`deploy` prices the loader's rent from the binary and `transact` its
deposits, so the pause names the amount instead of failing inside the deploy.

## Limits

Anonymous mode hides Ed25519 owners and discloses them to the auditor. Deposit
amounts remain public. The default ring stays nonanonymous. Rust anonymous
builders exclude delegates, merges, caches and direct outputs to the default
ring. Outflow limits remain supported. Auditor and viewing keys use canonical
X25519 encodings. P-256 ownership and historical viewing data require migration
before upgrading. Deployment checks the existing config before uploading. It
rejects a legacy auditor key layout and names the required migration.

The dedicated auditor disclosure encrypts the note fields the circuit uses to
compute commitments. Anonymous disclosure also binds the sender, spent notes
and recipients to the private transaction hash. Settlement requires this proof.
Ordinary recipient encryption stays wallet-side. A sender can make their own
payment unreadable, but cannot use that to bypass conservation or double-spend
checks. Protocols that rely on delivery, such as swaps, need a separate proof
of the recipient ciphertext and its binding to the intended recipient's key.

Ordinary rings without policy rules use `custom-ring-base-confidential` for
two-output auditor disclosure and `custom-ring-base` for other output counts.
Anonymous rings use `custom-ring-base`. The configured ring mode and settled
output count select the verifying key. The optimized circuits require the
matching program, proving keys and clients. One Go catalog drives the Rust
release catalog and TypeScript pins. `just check-custom-ring-keys` checks those
catalogs and every exported verifier against the pinned proving key. New keys
are generated locally and are not part of the historical release. Release staging
and deployment also compare every pinned key with the program's embedded
verifier markers. Missing, stale or insecure setup markers reject the binary.
The CLI
rejects an embedded release with missing or incompatible keys before download
or deployment. Workspace mode uses the locally built artifacts.

Policy transfers support ordinary capacities of 1, 2, 3, 4, 5, 6, 8, 12 or
16 inputs with 2 or 4 outputs. Anonymous capacities are 2×2, 2×4, 3×4 and
4×2. Delegate capacities are 2×2 and 4×4. Each has a general registry proof
and a smaller proof for records sharing an eight-leaf block. The exact 2×3
optimization remains available.

The exact keys require two published inputs, three published outputs and shared
registry paths. Compact padding omits trailing dummy slots and reveals those
counts. Delegate builders opt in with Rust's `.with_compact_padding()` or
TypeScript's `compactPadding: true`. Defaults retain padded counts. Anonymous
transfers allow a compact output suffix but reject compact inputs and caches.
SPP still receives a full padded witness. All 51 policy keys pass live settlement
and auditor recovery checks.

The complete V1 transaction must fit 4,096 bytes and 64 accounts. Capacities
with 8 or 16 outputs, or at least 24 inputs, are excluded. Even 16×4 can
exceed the limit with a curator, co-signer or extra data. The SDK checks the
core transfer before proving and the complete transaction at final assembly.
See the [change overview](changes-overview.md) for measured sizes and storage
layout, and [proof costs](proof-costs.md) for every supported capacity.

An outflow limit bounds one transfer, a sender may move up to the cap in
every transfer. A limited transfer has one sender. Delegation is exempt from
the limits. Ordinary policy and scoped co-signing apply to it.

## Reading a ring

The ring RPC answers signed reads. A reader signs an attestation naming the
ring, the time, a nonce and the page, a wallet as a message and a passkey
through WebAuthn, and gets the opened transactions back. The timestamp must be
within sixty seconds of the server's clock and a nonce is accepted once. Every
reader needs a read access record, the config authority has no implicit
access. A browser page needs its origin allowed on the RPC. The JSON-RPC contract
is in `services/ring-rpc/README.md`.

## Building on it

`custom-ring-sdk` starts from `CustomRing::new(program_id)`, the handle that
derives the ring's addresses, reads its typed accounts (`config`,
`policy_config`, `member_registry_root` and the others) and builds
the authority instructions (`create_config`, `init_spp_ring_config`,
`grant_read_access`, `set_paused`, `create_policy`, `set_policy_rules`,
`set_source_owner` and the others). `create_policy` and `set_policy_rules` take
a `RuleTable` built with `RuleTable::builder()` and the curator per shared
list. Every read and proof is `async` over an `AsyncZolanaClient`, which holds
the RPC, the indexer and the prover. A blocking caller runs an operation as
`zolana.block_on(op.prove(zolana.as_async()))`. Every operation fails with one
`RingError`.

A participant sends `RingDeposit`, prepares a `ConfidentialTransaction` from
the SPP transaction SDK and proves it with `CustomRingTransfer::new(..)`, the
list mutations use `UpdateMembers`. `prove` reads the table
from the policy config and trusts its rows only under the pinned hash
(`policy_config_table`), `client_rules_match` compares a table of the caller's
with the stored rows. `RingSubmission` proves, signs and sends a
`RingOperation` (a transfer, a delegate move, a key registration, a merge, a
deposit or a built instruction) as a v1 message. It keeps the intent across
`StaleMemberRegistryRoot`, a failed proof over an overwritten registry slot and a
verified blockhash expiry, with at most three signed attempts. Any other
failure is final. An unknown outcome keeps the signature for status
checks, `send_until_settled` polls it until the cluster settles it.
The auditor side is `zolana-ring-client`, `RingAudit` scans a ring and opens
its transactions, the ring RPC and the lifecycle test both use it. Auditor
discovery matches the auditor view tag. A transaction
belongs to the ring when, in its confirmed call stack read from Solana RPC,
the shielded pool instruction has the ring program as direct caller. A member
escrows its nullifier key with `RegisterKey`. `ReadMemberRecord` supplies its
`SealedKeyEntry`, which opens with the auditor key. `RingRecovery` rebuilds the
member's notes from the audit view and `DelegateTransfer` moves them.

Recovery reads the verified auditor openings directly. It checks ownership,
ring, amount and application hashes against the published commitments. Broken
or misleading recipient ciphertext cannot hide a proved note or abort its audit
page. The RPC returns these fields in `outputOpenings` with their tree contexts.
`outputs` contains optional recipient metadata. `undecryptableSlots` reports
missing or inconsistent recipient metadata, not missing auditor disclosure.

Recovery follows merge successors and checks each successor commitment. An
unknown proved asset stays in `unopened` until it is resolved or its note is
confirmed spent. Deposits with verified disclosure can start a recovered merge
chain. Deposits without disclosure encrypt their blinding only to the recipient.
Matching tags for those deposits appear in `unsupported_deposits`
(`unsupportedDeposits` in TypeScript), with ownership and spent status unknown.
Recovered notes are not a complete balance when either list is nonempty.
Missing mandatory disclosure fails recovery rather than returning a partial
balance as complete.

The TypeScript ring SDK in `@heliuslabs/zolana` (`sdk-libs/ts/src/ring`)
builds unsigned V1 transfers, withdrawals, exits, delegate moves and merges. Builders
read the ring's tier and policy, fetch member records from its own registry and
any curator, and include the required audit and policy proofs. Money inputs come from
`client.tree`, and `outputTree` defaults to it.
`createRingMemberRegistryRootInstruction` creates the member registry once,
`prepareRingKeyRegistration` enrols a member, `fetchRingSealedKey` and
`openRingSealedKey` read its key with the auditor key, and
`recoverRingMemberNotes` feeds `buildRingDelegateRecoveredTransaction`. Explicit
submission APIs handle signing and retry on `RingProgramError.staleMemberRegistryRoot`,
a failed proof over an overwritten registry slot and a verified blockhash
expiry. `createRingMergeSubmission` consolidates
two to 24 clean notes of one owner, asset and ring (up to 54 with `maxInputs`), preserving their
value and enforcing the configured transfer co-signer.

TypeScript callers needing restart recovery use `sendPersisted` with a
`WalletPersistence` store and cipher. It saves the signed attempt identity
and durable note holds before broadcasting. A failed save prevents broadcast.
Restore the wallet snapshot, sync, then call `reconcileRingSubmissions` to
check the retained signatures and save the results. Reconciliation does not
rebuild transactions. Unknown outcomes keep their holds, and confirmed
outcomes release them only after sync records the inputs as spent. Snapshot
version 4 stores pending submissions and still reads versions 2 and 3.

Generic wallet sync accepts a deposit payload decoder. Custom ring wallets
pass `customRingDepositPayload` as TypeScript `depositPayloadDecoder`, or
`zolana_ring_client::deposit_payload` to Rust `with_deposit_payload_decoder`.
These decoders accept ordinary recipient ciphertext and unwrap validated
custom audit capsules. Malformed capsules return an error.

The operator CLI in `cli` reads a `ring.toml` and exposes `parse_and_run`.

## Pitfalls and limits

Local rings share the ring RPC port, `zolana-ring localnet` replaces an RPC left
by another ring and `pipeline` keeps one that answers. A hosted ring RPC is only checked, never replaced, and a
ring pointed at one creates no local auditor key. `init` refuses an unpinned
hosted RPC, `--trust-ring-rpc` is for a local instance. The ring RPC releases
the key only to a request the upgrade authority signs while no config exists,
so `init` needs that keypair and the program must be deployed first. `init`
creates the config under the upgrade authority and hands it to
`config_authority_keypair` when that key differs. Input owners authorize the
spend, any signer may pay the transaction fee. Keys and `.env` belong in the
secret store, `new` writes a `.gitignore` for both, and a fresh machine mounts
them before its first pipeline run. `status`, `devnet`, `localnet` and error
output mask a `?api-key=` in a service URL, `zolana-ring url` prints it in
full.

Current transfers prove their dedicated auditor disclosure against the
committed outputs. Historical slots in another encoding may be undecryptable.
Direct deposits expose mint and amount, but auditor recovery also needs the
optional verified disclosure. A ring deposit
carries no list-policy proof.
The program still checks scoped co-signing and public deposit caps before
authorizing it. List rules apply when the note is transferred.
Both deposit instructions require the canonical deposit audit account after
the co-signer slots. Upgrade the ring clients with the program. The proofless
instruction is rejected while disclosure is required. An audited instruction
always verifies its proof, including when the setting is off.
Ring merge is also ciphertext-free: it combines up to 54 notes of one owner,
asset and ring into one note without moving value to another owner. The SDKs
fill the merge proof's unused slots with compact padding, which the transaction
leaves out, so a merge reveals how many notes it combines. It is not in
the auditor-tag scan. Any later transfer of the merged value still takes the
normal audited policy path.
SPP takes the pause only from the ring program's `ring_auth` PDA, a renounced
ring pauses only through its frozen `set_paused` instruction.

A changed policy hash takes effect at once, proofs over the prior hash fail
and their notes stay unspent. An identical re-pin preserves the statement.
`policy set` keeps the address
tree, a `ring.toml` naming another tree is refused, the tree is fixed at
`init`. Curated sources are per cluster, `[policy.sources.localnet]` and
`[policy.sources.devnet]` name their own curators and a catalogue name
resolves only on the cluster that lists it. The SDK refuses a `create_policy`
transaction past the signed V1 size (`TransactionTooLarge`). Rules may reference
any defined list. `UpdateMembers` requires the authority's signature for changes
to authority-written bits and the member's signature for member-written bits.
