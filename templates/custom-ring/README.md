# {{project-name}}

A custom ring on the Solana Privacy Program with an auditor. Transfers inside
the ring are confidential, amounts and recipients stay hidden on chain, and
every transfer carries a proof that one auditor key can open it. The program is
`custom-ring-program` from the Zolana checkout at `{{zolana_path}}`, generated
at revision `{{zolana_revision}}`, deployed at `{{program_id}}`. `ring.toml`
holds the wizard's answers and the active cluster, `.env` holds secrets and
`ring.toml` refers to them as `${NAME}`.

## Roles

The operator holds the upgrade authority keypair (`{{authority_keypair}}`) and
this repository. It deploys and upgrades the program, creates the config,
registers the ring with SPP, and hands the authority over or renounces it.

The ring authority is the key stored in the ring config, the operator's key by
default. It grants and revokes readers. A Squads vault can hold it and run the
same commands through proposals.

The auditor is a P-256 viewing key held by a ring RPC. It opens every transfer
of the ring.

A reader is a Solana key or a passkey the authority granted. It reads what the
auditor reads through the ring RPC. The authority itself has no implicit read
access, `pipeline` grants it and `transact` refuses to run without the grant.

A participant is a shielded wallet. It deposits into the ring and transfers
inside it.

## Prerequisites

On `PATH` in a fresh checkout:

- **Rust** 1.97.0, pinned by `rust-toolchain.toml`.
- **`just`** — `cargo install just --locked`.
- **Anza / Solana CLI** 4.x —
  `sh -c "$(curl -sSfL https://release.anza.xyz/v4.0.2/install)"`, for
  `cargo build-sbf`, `solana program deploy` and the key checks.

The Zolana checkout at `{{zolana_path}}` supplies the program, the ring RPC and,
on localnet, the validator and services, so its prerequisites apply to
`just localnet`. `just transact` needs the Redis in `ZOLANA_PROVER_REDIS_URL`.

## The pipeline

`just localnet` starts a validator with SPP, Photon and the prover from the
Zolana checkout and sets `target = "localnet"` in `ring.toml`.
`just devnet` sets `target = "devnet"` and probes the deployed Photon, prover
and ring RPC named in `ring.toml`. It starts nothing: on devnet the only things
built here are the ring's own program and CLI, and the only service it can run
is a ring RPC of your own, when `ring.toml` names `127.0.0.1`. Every other
recipe acts on the recorded target, `just urls` shows it.

`just pipeline` then runs build, deploy, init, ring RPC and transact. Each step
locks something in.

The program id was fixed when the wizard created `keys/program-keypair.json`.
`just deploy` deploys the program under the authority, or upgrades it in place
when it already exists. While the program has an upgrade authority only that
key may run `init`.

The authority pays for every step. Localnet airdrops what a step spends,
devnet does not: a step it cannot pay for prints the address and the amount and
waits for an airdrop at [the faucet](https://faucet.solana.com), then continues
on the next keypress. `solana airdrop` draws on the same quota and is rate
limited to refusing, so the pause does not suggest it. In CI, without a
terminal, the shortfall is an error.

`just init` fixes the auditor. Without `keys/auditor.key.pub` it asks the ring
RPC in `ring.toml` for a key and writes the public half there. A hosted RPC is
accepted only when its service key is pinned as `ring_rpc_pubkey` in
`ring.toml`, or with `init --trust-ring-rpc` for a local instance. The auditor
key cannot change afterwards, a different auditor is a different ring.

Where the ring RPC is hosted, devnet by default, that service holds the auditor
key: it derives one per ring, `just auditor-key` creates nothing and `init`
fetches the public half under the pinned service key. Only a ring RPC on
`127.0.0.1` reads `keys/`, and `init` refuses to pin a key from `keys/` against
a hosted service unless `init --local-auditor` says that is deliberate: a ring
that pins a key the service does not hold can never be read through it. On
devnet `just pipeline` asks the service about this ring before `init` runs.

After `init` the authority may move. `authority transfer <pubkey>` hands the
program to another key, then point `authority_keypair` in `ring.toml` at its
keypair. `authority renounce --yes` makes the program immutable.

`just rpc` serves the auditor's view from `keys/auditor.key`; against a hosted
ring RPC it refuses, that service already serves the ring. `just pipeline`
starts a local one in the background when none answers and leaves it running,
`just rpc-stop` ends it; on a hosted one it starts nothing and only runs
`rpc-check`.

`just transact` makes two ring deposits, one audited transfer, and reads the
transfer back through the ring RPC as the authority. The audit proof goes
through the prover's Redis queue, so `ZOLANA_PROVER_REDIS_URL` in `.env` must
name a reachable Redis, also for `just localnet`.

`just transfer <address> <lamports>` pays one shielded address inside the ring.
The address is the base58 form of `signing_pk || nullifier_pk || viewing_pk`, 99
bytes, the whole recipient, so the ring needs no registry entry for it. The
authority deposits the lamports, a throwaway sender spends all of them in one
audited transfer and keeps no change. Where the authority is a granted reader
the transfer is read back through the ring RPC, otherwise the command stops at
the signature.

Rerunning `just pipeline` after a code change is the upgrade path. Steps whose
state already exists are skipped.

## Readers

`just grant-reader <key>` lets a key read the ring through the ring RPC,
`just revoke-reader <key>` takes it back and returns the rent to the
authority. The key is a base58 Solana key or the 66-hex P-256 key of a
passkey. Reads are signed requests with a timestamp and a nonce, a browser
needs its origin in `RING_RPC_ALLOW_ORIGINS` and the matching
`RING_RPC_WEBAUTHN_RP_ID`.

## Features

| Feature | Status | Example |
| --- | --- | --- |
{{features_markdown}}
Features are declared once, in the template's `hooks/wizard.rhai`. The
`[features]` table in `ring.toml` records the choice. A feature in state
`ready` is wired to code through a cargo feature of the same name on
`custom-ring-program`, and on `custom-ring-cli` when it has a CLI side.
The wizard forwards the enabled ones to both crates.

## Pitfalls

Local rings share the ring RPC port. `just pipeline` replaces a local RPC that
serves another ring's auditor key, `rpc-check` tells the two apart. It never
replaces a hosted one.

`init` refuses an unpinned hosted RPC on purpose. Confirm the service key out
of band and pin it, `--trust-ring-rpc` is for an RPC on this machine.

The sender of an audited transfer pays its own v0 transaction and the lookup
table behind it, the instruction does not fit a packet with a separate fee
payer. `transact` funds the throwaway sender for that.

Deploys and transactions on devnet cost devnet SOL, `just status` shows the
authority's balance and the pipeline stops for a faucet airdrop when it runs
short. The Helius API key lives in `.env`, `.env.example` lists
the keys.

Keep `keys/` and `.env` out of git and in the deployment secret store. A fresh
checkout mounts the program keypair and the auditor key through
`CUSTOM_RING_PROGRAM_KEYPAIR_FILE` and `CUSTOM_RING_AUDITOR_KEY_FILE` before
`just pipeline`.

## Limits

The auditor opens outputs created by the supported clients. Slots in another
encoding are reported as undecryptable, `transact` prints them. Ring deposits
are public on chain and are not part of the auditor's view. The released
transfer proof does not prove that a ciphertext matches a committed output.
