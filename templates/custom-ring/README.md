# {{project-name}}

A custom ring on the Solana Privacy Program: confidential transfers whose
per-transaction viewing key is verifiably encrypted to this ring's auditor. The
program logic is `custom-ring-program` from the zolana checkout at
`{{zolana_path}}`; this repository pins the deploy address
`{{program_id}}`, records the wizard's answers in `ring.toml`, and drives the
pipeline with `just`.

Authority: `{{authority_keypair}}`. The cluster is chosen at run time, `just
localnet` or `just devnet` record it in `ring.toml` (`target`) and every later
step acts on it.

## Pipeline

| Step | Command | What happens |
| --- | --- | --- |
| 1 | `just ring-new` (in zolana) | this repository |
| 2 | `just repo` | GitHub repository created and pushed with `gh` |
| 3 | `just localnet` or `just devnet` | localnet: a validator with SPP, Photon and the prover from the zolana checkout. devnet: Photon and the prover on this machine against devnet. Both set `target` in `ring.toml` |
| 4 | `just build` | `cargo build-sbf` of the program at the pinned address |
| 5 | `just deploy` | `solana program deploy` to the target, the authority becomes the upgrade authority. On a deployed program this is the upgrade, growing program data when the binary grew |
| 6 | `just init` | auditor key created by `ring-rpc keygen` (secret stays here, public half committed), `create_config` (gated on the upgrade authority), the policy, and `init_spp_ring_config` |
| 7 | `just rpc` | ring RPC serving `getDecryptedTransactions` with the auditor key against the target |
| 8 | `just transact` | two ring deposits, one audited transfer, the auditor's view read back |

`just pipeline` runs steps 4 to 8 against the active target and leaves the ring
RPC running for the auditor's reads (`just rpc-stop` ends it). After a code
change it is the upgrade path: `deploy` upgrades in place, `init` finds its
accounts and does nothing. `cargo run -p {{project-name}} -- authority transfer
<pubkey>` hands the program to another key (then point `authority_keypair` in
`ring.toml` at it), `authority renounce --yes` makes it immutable. `just
localnet-stop` and `just devnet-stop` tear the services down. On devnet
deploys and transactions cost real devnet SOL, `status` shows the authority's
balance, and a hosted ring RPC (`init --trust-ring-rpc`, or `ring_rpc_pubkey`
in `ring.toml`) can stand in for the local one.

## Features

| Feature | Status | Example |
| --- | --- | --- |
{{features_markdown}}
Features are declared in the template's `hooks/wizard.rhai`; a ring regenerated
with the template picks up new ones.

## Layout

- `program/` the on-chain program: `custom-ring-program` behind this ring's
  entrypoint and address (`.cargo/config.toml`).
- `cli/` the operator CLI (`status`, `deploy`, `init`, `transact`, `authority`), from
  `custom-ring-cli`.
- `keys/` the program keypair and the auditor secret, never committed, and
  `auditor.key.pub`, the auditor public key the ring config carries, committed.
- `ring.toml` the wizard's answers.
