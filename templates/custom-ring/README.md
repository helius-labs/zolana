# {{project-name}}

A custom ring on the Solana Privacy Program: confidential transfers whose
per-transaction viewing key is verifiably encrypted to this ring's auditor. The
program logic is `custom-ring-program` from the zolana checkout at
`{{zolana_path}}`. This repository pins the deploy address
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
| 3 | `just localnet` or `just devnet` | localnet: a validator with SPP, Photon and the prover from the zolana checkout. devnet: the hosted devnet Photon and prover from `ring.toml` (or local ones when `ring.toml` points at 127.0.0.1). Both set `target` in `ring.toml` |
| 4 | `just build` | `cargo build-sbf` of the program at the pinned address |
| 5 | `just deploy` | `solana program deploy` to the target, the authority becomes the upgrade authority. On a deployed program this is the upgrade, growing program data when the binary grew |
| 6 | `just init` | auditor key created by `ring-rpc keygen` (secret stays here, public half committed), `create_config` (gated on the upgrade authority) and `init_spp_ring_config` |
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
in `ring.toml`) can stand in for the local one. Secrets such as the Helius API
key live in `.env` (ignored in git, `.env.example` shows the keys) and
`ring.toml` refers to them as `${NAME}`.

## Features

| Feature | Status | Example |
| --- | --- | --- |
{{features_markdown}}
Features are declared in the template's `hooks/wizard.rhai`, and a ring
regenerated with the template picks up new ones. Enabled features that carry
on-chain values live in `ring.toml`'s `[policy]` table. `allowed_assets` (mints the ring
accepts, `SOL` for native SOL), `withdrawals` (the default rule for public
withdrawals out of the ring: `open`, `blocked`, or `approval`),
`[policy.asset_withdrawals]` (a rule per mint) and `approver` (the key whose
sign-off an `approval` rule needs). `just init` writes the policy on chain, and
`cargo run -p {{project-name}} -- policy show|apply|set` reads it back, re-applies
`ring.toml`, or changes one part at a time (`policy set --withdrawals approval
--approver <pubkey>`, `policy set --asset-withdrawals SOL=open`, `policy set
--allow-asset <mint>`, `policy set --any-asset`). Under an approval rule the
approver runs `approve <private_tx_hash>` for a proven transact, and the
transact then carries the approval account, and `transact --withdraw <lamports>`
demonstrates it with the authority as approver.

## Layout

- `program/` the on-chain program: `custom-ring-program` behind this ring's
  entrypoint and address (`.cargo/config.toml`).
- `cli/` the operator CLI (`status`, `deploy`, `init`, `policy`, `transact`, `authority`), from
  `custom-ring-cli`.
- `keys/` the program keypair and the auditor secret, never committed, and
  `auditor.key.pub`, the auditor public key the ring config carries, committed.
- `ring.toml` the wizard's answers.
