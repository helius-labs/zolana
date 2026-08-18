# {{project-name}}

A custom ring on the Solana Privacy Program: confidential transfers whose
per-transaction viewing key is verifiably encrypted to this ring's auditor. The
program logic is `custom-ring-program` from the zolana checkout at
`{{zolana_path}}`; this repository pins the deploy address
`{{program_id}}`, records the wizard's answers in `ring.toml`, and drives the
pipeline with `just`.

Target: `{{target}}`. Authority: `{{authority_keypair}}`.

## Pipeline

| Step | Command | What happens |
| --- | --- | --- |
| 1 | `just ring-new` (in zolana) | this repository |
| 2 | `just repo` | GitHub repository created and pushed with `gh` |
| 3 | `just build` | `cargo build-sbf` of the program at the pinned address |
| 4 | `just deploy` | `solana program deploy`, the authority becomes the upgrade authority |
| 5 | `just init` | auditor key created by `ring-rpc keygen`, `create_config` (gated on the upgrade authority) and `init_spp_ring_config` |
| 6 | `just rpc` | ring RPC serving `getDecryptedTransactions` with the auditor key |
| 7 | `just transact` | two ring deposits, one audited transfer, the auditor's view read back |

`just pipeline` runs steps 3 to 7 and leaves the ring RPC running for the
auditor's reads (`just rpc-stop` ends it). On the localnet target, `just
localnet` first starts a validator with SPP, Photon and the prover from the
zolana checkout, and `just localnet-stop` tears it down.

## Features

| Feature | Status | Example |
| --- | --- | --- |
{{features_markdown}}
Features are declared in the template's `hooks/wizard.rhai`; a ring regenerated
with the template picks up new ones.

## Layout

- `program/` the on-chain program: `custom-ring-program` behind this ring's
  entrypoint and address (`.cargo/config.toml`).
- `cli/` the operator CLI (`status`, `deploy`, `init`, `transact`), from
  `custom-ring-cli`.
- `keys/` the program keypair and the auditor key. Never committed.
- `ring.toml` the wizard's answers.
