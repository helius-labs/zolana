# Custom rings

A custom ring is a program that owns a set of UTXOs inside the Solana Privacy
Program. Each UTXO of the ring carries the ring's program id and the SPP
transfer proof binds it. SPP spends such UTXOs only through `ring_transact`,
whose ring config account is signed by the ring program's `ring_auth` PDA, so
every transfer in the ring enters through the ring program. The ring program
checks its policy and CPIs into SPP with that signature, SPP verifies the
transfer proof and the owner signatures and keeps the trees and nullifiers.
Each ring is its own program deployment with its own authority, config and
services. Every custom ring is audited. The custom-ring circuit binds each
transfer to the ring's auditor and the program accepts no transact without
that proof.

`program` is the ring program, `sdk` the Rust client for it, `cli` the
`zolana-ring` operator binary, `test` the lifecycle test on a local validator,
`examples` one `ring.toml` per worked policy. The ring RPC in
`services/ring-rpc` holds the auditor key, `custom-rings/client` is the auditor
side it is built on. A custom-rings release (`just release-custom-rings <tag>
--upload --prerelease`) ships `zolana-ring`, the ring program, the two ring
proving keys and the ring RPC together, the CLI deploys the binary of the
release it was built from. One released binary serves every ring, the rules
are data `init` pins from `ring.toml`.

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
The auditor is a P-256 viewing key inside a ring RPC and opens every transfer
of the ring. A reader is a Solana key or a passkey the authority granted and
reads what the auditor reads. A participant is a shielded wallet that deposits
into the ring and transfers inside it.

The authority is a plain signer, a Squads vault holds it through proposals,
and `SetAuthority` hands it to another key, signed by both, readers, lists and
the pause move with it.
Readers are on-chain records, so the same proposal flow grants a regulator a
passkey without anyone sharing a key.

## How auditor visibility works

Every transfer encrypts its transaction viewing key to the auditor under a
fresh ephemeral key and publishes the ciphertext as an SPP message. The ring
program accepts the transfer only with a proof that the ciphertext holds the
key behind the transfer's published viewing key. SPP folds the message into
the transfer's own proof, so a transfer cannot publish one ciphertext and prove
another. The auditor decrypts one message per transaction and opens every
output with it.

The order is fixed by the hashes. SPP folds the messages into
`external_data_hash` and that into `private_tx_hash`, and `private_tx_hash` is
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
validator is the Anza `solana-test-validator`, the ring RPC and the prover's
two ring keys, `custom_ring_policy.key` and `custom_ring_base.key`, come from the custom-rings
release the ring cli came from,
and the ring RPC serves `keys/auditor.key`, created when missing. A rerun
keeps a live validator and its ledger and replaces the ring RPC with this
ring's. `pipeline` and `deploy` on localnet start whatever does not answer
before deploying, so `zolana-ring pipeline` alone brings a ring up. `just
ring-localnet` needs this repository's localnet prerequisites instead.

## The pipeline and what each step locks in

`zolana-ring new` is a wizard. It asks for the ring name, the service URLs of
both clusters, the target and the tier, a policy ring then names its entries
tree, picks the lists its rules read, picks a source per list and adds rules
one at a time, each compiled as it is added. It prints the `ring.toml` it
will write and asks before writing. It writes the ring directory, `ring.toml`
with the answers and `keys/program-keypair.json`, and fixes the program id,
the address of that keypair. `--silent` takes every default, an audit-only
ring. `--policy-from <file>` takes the `[policy]` table of a `ring.toml`, an
example's included, checks it on both clusters and skips the tier and policy
questions. It creates the authority keypair when the answer keeps the default
`~/.config/solana/id.json` and no file is there; any other path is the
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
fixes who may `init`, the upgrade authority; `--program-so` deploys a local
build instead. A cli whose embedded release ships no ring program refuses
`deploy` and names `--program-so`. A ring with a `[policy]` section is a
policy ring, the same binary serves it and an audit-only ring, the tier is
fixed at `init`. After the loader finishes, `deploy` reads the program back and
refuses to report success unless the bytes on chain hash to the file it
deployed. A binary already on chain byte for byte is reported present and
not uploaded again. `zolana-ring init` fixes the auditor. On a policy ring it
compiles `[policy]` for the target, checks that each curator is deployed,
pins a policy and serves its list from its own entries in the ring's tree,
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
`zolana-ring pipeline` runs deploy to transact and takes `--program-so` like
`deploy`.

On devnet the prover, the indexer and the ring RPC are already deployed and
are probed, never started. The hosted ring RPC derives one auditor key per
ring from a root secret, so it serves any ring that asks and a new ring needs
no restart. The order is what matters: a
ring takes its key from the service before `create_config`, because the config
fixes the auditor for good. `rpc-check` reports which of the three cases a ring
is in: served, registered with another auditor, or not yet initialized. `init`
refuses to pin a key from `keys/` against a service that holds its own.

The authority pays for every step. Localnet airdrops what a step spends,
devnet cannot, so a step it cannot pay for stops at the web faucet and
continues on the next keypress; without a terminal the shortfall is an error.
`deploy` prices the loader's rent from the binary and `transact` its
deposits, so the pause names the amount instead of failing inside the deploy.

## Limits

Senders are not anonymous and deposits are public. Supported SDK paths accept
validated P-256 auditor keys. Raw config data is checked only for compressed
form and reserved points. An invalid P-256 curve point makes its ring unable
to transact.

The proofs bind output commitments and ciphertext bytes to one private
transaction hash. They do not prove that decrypted output plaintext opens its
commitment. The RPC reports what it decrypts and marks unreadable slots. It
cannot prove that reported values equal the committed UTXOs.

## Reading a ring

The ring RPC answers signed reads. A reader signs an attestation naming the
ring, the time, a nonce and the page, a wallet as a message and a passkey
through WebAuthn, and gets the opened transactions back. The timestamp must be
within sixty seconds of the server's clock and a nonce is accepted once. Every
reader needs a read access record, the config authority has no implicit
access. A browser page needs its origin allowed on the RPC. The wire contract
is in `services/ring-rpc/README.md`.

## Building on it

`custom-ring-sdk` starts from `CustomRing::new(program_id)`, the handle that
derives the config, read access record and `ring_auth` addresses and reads the
typed accounts. The authority builds `CreateConfig`, `InitSppRingConfig`,
`GrantReadAccess`, `RevokeReadAccess`, `SetAuthority` and `SetPaused` from it,
a policy ring adds `CreatePolicy`, `SetPolicyRules`, `SetSourceOwner` and the
entry mutations `CreateEntry` and `UpdateEntry`. `CreatePolicy` and
`SetPolicyRules` take a `RuleTable` built with `RuleTable::builder()` and the
curator per shared list, both refuse a transaction past one legacy packet. A
participant sends `RingDeposit`, prepares a `ConfidentialTransfer` from the
SPP transaction SDK
and proves it with
`CustomRingTransfer::new(..).with_tree(..).with_assets(..).prove(env)`,
where the environment is the indexer, the RPC and the prover. `prove` reads
the table from the policy config and trusts its rows only under the pinned
hash (`policy_config_table`), `client_rules_match` compares a table of the
caller's with the stored rows. `prove_async` serves both tiers. The custom-ring
instruction forwards SPP's full account list and does not fit a legacy
transaction, `V0WithLookupTable` submits it behind a throwaway lookup table.
The auditor side is `zolana-ring-client`, `RingAudit` scans a ring and opens
its transactions, the ring RPC and the lifecycle test both use it. The indexer
only matches the auditor view tag and needs no ring support. A transaction
belongs to the ring when, in its confirmed call stack read from Solana RPC,
the shielded pool instruction has the ring program as direct caller.

The TypeScript ring SDK in `@heliuslabs/zolana` (`sdk-libs/ts/src/ring`) proves
audit-only rings and policy rings with an empty table, a rules-bearing ring
fails with `RING_RULES_UNSUPPORTED`. It spends from `client.tree` only and
takes `entriesRoots` when the pinned entries tree is another tree. Its lookup
table builder reads the tier and the entries tree from the chain,
`fetchRingPolicyConfig` reads the rows and the generation, and
`setRingPausedInstruction` pauses and resumes the ring.

The operator CLI in `cli` reads a `ring.toml` and exposes `parse_and_run`.

## Pitfalls and limits

Local rings share the ring RPC port, `zolana-ring localnet` replaces an RPC left
by another ring and `pipeline` keeps one that answers; a hosted ring RPC is only checked, never replaced, and a
ring pointed at one creates no local auditor key. `init` refuses an unpinned
hosted RPC, `--trust-ring-rpc` is for a local instance. The ring RPC releases
the key only to a request the upgrade authority signs while no config exists,
so `init` needs that keypair and the program must be deployed first. `init`
creates the config under the upgrade authority and hands it to
`config_authority_keypair` when that key differs. The sender of a
custom-ring transfer pays its own v0 transaction. Keys and `.env` belong in the
secret store, `new` writes a `.gitignore` for both, and a fresh machine mounts
them before its first pipeline run. `status`, `devnet`, `localnet` and error
output mask a `?api-key=` in a service URL, `zolana-ring url` prints it in
full.

The auditor opens outputs created by the supported clients and reports slots
in another encoding as undecryptable. Ring deposits are public on chain and
not part of the auditor's view. A ring deposit passes no policy check, the ring
only lends its `ring_auth` signature, the rules apply when the note is spent.
SPP takes the pause only from the ring program's `ring_auth` PDA, a renounced
ring pauses only through its frozen `set_paused` instruction. The released
transfer proof does not prove that a ciphertext matches a committed output.

A re-pin takes effect at once, a proof built against the old table fails at
verification and its note stays unspent. `policy set` keeps the entries
tree, a `ring.toml` naming another tree is refused, the tree is fixed at
`init`. Curated sources are per cluster, `[policy.sources.localnet]` and
`[policy.sources.devnet]` name their own curators and a catalogue name
resolves only on the cluster that lists it. A table pinned with its curator
accounts can exceed one legacy packet at `create_policy`, `init` then pins it
over the ring's own sources and points each curated list afterwards. A rule
names authority-written lists only, the member-written lists are enrolled by
their members and read by no rule.
