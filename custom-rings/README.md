# Custom rings

A custom ring is a program that owns a set of UTXOs inside the Solana Privacy
Program. Each UTXO of the ring carries the ring's program id and the SPP
transfer proof binds it. SPP spends such UTXOs only through `ring_transact`,
whose ring config account is signed by the ring program's `ring_auth` PDA, so
every transfer in the ring enters through the ring program. The ring program
checks its policy and CPIs into SPP with that signature, SPP verifies the
transfer proof and the owner signatures and keeps the trees and nullifiers.
Each ring is its own program deployment with its own authority, config and
services. The ring in this directory adds an auditor.

`program` is the ring program, `sdk` the Rust client for it, `cli` the
operator CLI, `test` the lifecycle test on a local validator. The ring RPC in
`services/ring-rpc` holds the auditor key, `sdk-libs/ring-client` is the
auditor side it is built on. `templates/custom-ring` generates a ring
repository that is a thin shim over `cli`.

## Roles

The operator holds the upgrade authority keypair and the ring repository. It
deploys and upgrades the program, creates the config, registers the ring with
SPP, hands the authority over or renounces it. The ring authority is the key in
the ring config, the operator's by default, and it grants and revokes readers.
The auditor is a P-256 viewing key inside a ring RPC and opens every transfer
of the ring. A reader is a Solana key or a passkey the authority granted and
reads what the auditor reads. A participant is a shielded wallet that deposits
into the ring and transfers inside it.

The authority is a plain signer, a Squads vault holds it through proposals.
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
a public input of the audit circuit. `AuditedTransfer::prove` therefore
encrypts the message first, runs the SPP proof over the message-bearing
external data, and only then finishes the audit proof over the resulting
`private_tx_hash`. `AuditProofParams::encrypt` returns a `PendingAuditProof`
that only `finish` turns into proof inputs, so the order cannot be broken by
accident.

What this means when operating a ring. The auditor key is fixed at
`create_config`, changing the auditor means a new ring. While the program has
an upgrade authority only that key may create the config, so renounce after
`init`, not before. The auditor secret lives in the ring RPC, never in the ring
repository. A ring runs its own RPC from a key file, or takes a key from a
hosted RPC that derives one key per ring from a root secret and signs the key
it hands out. The ring pins that service key in `ring.toml` so a wrong auditor
cannot be slipped in at `init`. Every transfer output stays in the ring, the
SDK binds change and recipient notes to the ring id, so each hop is audited.

## The pipeline and what each step locks in

`just ring-new` in a Zolana checkout generates the ring repository and fixes
the program id, the address of the program keypair in the ring's `keys/`. In
the ring, `just localnet` or `just devnet` picks the cluster and starts or
probes its services. `just deploy` fixes who may `init`, the upgrade
authority. `just init` fixes the auditor. After `init` the authority can be
transferred or renounced, readers come and go, and the program can be
upgraded by running `just deploy` again. `just rpc` serves the auditor's view,
`just transact` makes two ring deposits and one audited transfer and reads it
back. `just pipeline` runs build to transact. The generated README is the
operator's guide.

`ring-localnet` starts the validator without the bundled prover and starts the
prover separately with a Redis queue, the audit circuit is served only through
that queue. `ZOLANA_PROVER_REDIS_URL` is required for it and for `transact`.

## Reading a ring

The ring RPC answers signed reads. A reader signs an attestation naming the
ring, the time, a nonce and the page, a wallet as a message and a passkey
through WebAuthn, and gets the opened transactions back. The timestamp must be
within sixty seconds of the server's clock and a nonce is accepted once. Every
reader needs a reader record, the config authority has no implicit access. A
browser page needs its origin allowed on the RPC. The wire contract is in
`services/ring-rpc/README.md`.

## Building on it

`custom-ring-sdk` starts from `CustomRing::new(program_id)`, the handle that
derives the config, reader record and `ring_auth` addresses and reads the
typed accounts. The authority builds `CreateConfig`, `InitSppRingConfig`,
`GrantReader` and `RevokeReader` from it. A participant sends `RingDeposit`,
prepares a `ConfidentialTransfer` from the SPP transaction SDK and proves it
with `AuditedTransfer::new(..).with_tree(..).with_assets(..).prove(env)`,
where the environment is the indexer, the RPC and the prover. The audited
instruction forwards SPP's full account list and does not fit a legacy
transaction, `V0WithLookupTable` submits it behind a throwaway lookup table.
The auditor side is `zolana-ring-client`, `RingAudit` scans a ring and opens
its transactions, the ring RPC and the lifecycle test both use it. The indexer
only matches the auditor view tag and needs no ring support. A transaction
belongs to the ring when, in its confirmed call stack read from Solana RPC,
the shielded pool instruction has the ring program as direct caller.

The operator CLI in `cli` reads a `ring.toml` and exposes `parse_and_run`, a
generated ring's binary is that one call. Features are declared once, in the
template's wizard, and reach the code as cargo features of the same name.

## Pitfalls and limits

Local rings share the ring RPC port, `just pipeline` replaces an RPC that
serves another ring. `init` refuses an unpinned hosted RPC, `--trust-ring-rpc`
is for a local instance. The sender of an audited transfer pays its own v0
transaction. Keys and `.env` belong in the secret store, a fresh checkout
mounts them before its first pipeline run.

The auditor opens outputs created by the supported clients and reports slots
in another encoding as undecryptable. Ring deposits are public on chain and
not part of the auditor's view. The released transfer proof does not prove that
a ciphertext matches a committed output.
