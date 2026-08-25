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
`zolana-ring` operator binary, `test` the lifecycle test on a local validator.
The ring RPC in `services/ring-rpc` holds the auditor key,
`custom-rings/client` is the auditor side it is built on. A release of this
repository ships `zolana-ring` and the ring program binary together, the CLI
deploys the binary of the release it was built from.

## Roles

The operator holds the upgrade authority keypair and the ring directory. It
deploys and upgrades the program, creates the config, registers the ring with
SPP, hands the authority over or renounces it. The ring authority is the key in
the ring config, the operator's by default, and it grants and revokes readers.
The auditor is a P-256 viewing key inside a ring RPC and opens every transfer
of the ring. A reader is a Solana key or a passkey the authority granted and
reads what the auditor reads. A participant is a shielded wallet that deposits
into the ring and transfers inside it.

The authority is a plain signer, a Squads vault holds it through proposals,
and `SetAuthority` hands it to another key, signed by both.
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
cannot be slipped in at `init`. The SDK binds change and recipient notes to
the ring id, so a plain transfer keeps value in the ring. Exits stay possible,
an owner may withdraw or send to a default pool note, and every such transact
still carries the custom-ring proof, so the auditor sees the exit.

## Prerequisites

`zolana-ring` from a release of this repository, the release also carries the
ring program it deploys. On `PATH` before `zolana-ring deploy`:

- **Anza / Solana CLI** 4.x, the version CI pins —
  `sh -c "$(curl -sSfL https://release.anza.xyz/v4.0.2/install)"`. It deploys
  the program.

`just ring-localnet` also needs this repository's localnet prerequisites and a
Redis in `ZOLANA_PROVER_REDIS_URL` for the custom-ring proof.

## The pipeline and what each step locks in

`zolana-ring new` writes the ring directory, `ring.toml` with the service URLs
it asked for and `keys/program-keypair.json`, and fixes the program id, the
address of that keypair. It creates the authority keypair when the answer
keeps the default `~/.config/solana/id.json` and no file is there; any other
path is the operator's and a missing one is only reported. In the ring,
`zolana-ring localnet` or `zolana-ring devnet` picks the cluster and probes
its services. `zolana-ring deploy` downloads the ring program of the release
the CLI came from, checks it against the lockfile built into the CLI, and
fixes who may `init`, the upgrade authority; `--program-so` deploys a local
build instead. After the loader finishes, `deploy` reads the program back and
refuses to report success unless the bytes on chain hash to the file it
deployed. `zolana-ring init` fixes the auditor. After `init` the authority
can be transferred (`--yes`, the new key alone can hand it back) or renounced
(`--yes`, and only when the bytes on chain match the released program or the
`--program-so` given), readers come and go, and the program can be upgraded
by running `zolana-ring deploy` again. `zolana-ring transact` makes two ring
deposits and one custom-ring transfer and reads it back, `zolana-ring transfer`
sends an amount to a shielded address. Both spend from
`keys/sender-keypair.json`, created on first use. Its change and fee budget
stay spendable with that key, keep it with the other keys. `zolana-ring
pipeline` runs deploy to transact.

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

`ring-localnet` starts the validator without the bundled prover and starts the
prover separately with a Redis queue, the custom-ring circuit is served only
through that queue. `ZOLANA_PROVER_REDIS_URL` is required for it and for `transact`.

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
`GrantReadAccess`, `RevokeReadAccess` and `SetAuthority` from it. A
participant sends `RingDeposit`, prepares a `ConfidentialTransfer` from the
SPP transaction SDK
and proves it with
`CustomRingTransfer::new(..).with_tree(..).with_assets(..).prove(env)`,
where the environment is the indexer, the RPC and the prover. The custom-ring
instruction forwards SPP's full account list and does not fit a legacy
transaction, `V0WithLookupTable` submits it behind a throwaway lookup table.
The auditor side is `zolana-ring-client`, `RingAudit` scans a ring and opens
its transactions, the ring RPC and the lifecycle test both use it. The indexer
only matches the auditor view tag and needs no ring support. A transaction
belongs to the ring when, in its confirmed call stack read from Solana RPC,
the shielded pool instruction has the ring program as direct caller.

The operator CLI in `cli` reads a `ring.toml` and exposes `parse_and_run`.

## Pitfalls and limits

Local rings share the ring RPC port, `zolana-ring pipeline` replaces an RPC that
serves another ring; a hosted ring RPC is only checked, never replaced, and a
ring pointed at one creates no local auditor key. `init` refuses an unpinned
hosted RPC, `--trust-ring-rpc` is for a local instance. The sender of a
custom-ring transfer pays its own v0 transaction. Keys and `.env` belong in the
secret store, `new` writes a `.gitignore` for both, and a fresh machine mounts
them before its first pipeline run. `status`, `devnet`, `localnet` and error
output mask a `?api-key=` in a service URL, `zolana-ring url` prints it in
full.

The auditor opens outputs created by the supported clients and reports slots
in another encoding as undecryptable. Ring deposits are public on chain and
not part of the auditor's view. The released transfer proof does not prove that
a ciphertext matches a committed output.
