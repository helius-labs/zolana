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
| 4 | `just deploy` | `solana program deploy`, the authority becomes the upgrade authority; on a deployed program this is the upgrade, growing program data when the binary grew |
| 5 | `just init` | auditor key created by `ring-rpc keygen` (localnet) or handed out by the ring RPC signed with the service key `ring.toml` pins, `create_config` (gated on the upgrade authority), the policy, and `init_spp_ring_config` |
| 6 | `just rpc` | ring RPC serving `getDecryptedTransactions` with the auditor key |
| 7 | `just transact` | two ring deposits, one audited transfer, the auditor's view read back |

`just pipeline` runs steps 3 to 7 and leaves the ring RPC running for the
auditor's reads (`just rpc-stop` ends it). After a code change it is the
upgrade path: `deploy` upgrades in place, `init` finds its accounts and does
nothing. `cargo run -p {{project-name}} -- authority transfer <pubkey>` hands the
program to another key (then point `authority_keypair` in `ring.toml` at it),
`authority renounce --yes` makes it immutable. On the localnet target, `just
localnet` first starts a validator with SPP, Photon and the prover from the
zolana checkout, and `just localnet-stop` tears it down.

## Features

| Feature | Status | Example |
| --- | --- | --- |
{{features_markdown}}
Features are declared in the template's `hooks/wizard.rhai`; a ring regenerated
with the template picks up new ones. Enabled features that carry on-chain
values live in `ring.toml`'s `[policy]` table: `allowed_assets` (mints the ring
accepts, `SOL` for native SOL), `withdrawals` (the default rule for public
withdrawals out of the ring: `open`, `blocked`, or `approval`),
`[policy.asset_withdrawals]` (a rule per mint) and `approver` (the key whose
sign-off an `approval` rule needs). `just init` writes the policy on chain, and
`cargo run -p {{project-name}} -- policy show|apply|set` reads it back, re-applies
`ring.toml`, or changes one part at a time (`policy set --withdrawals approval
--approver <pubkey>`, `policy set --asset-withdrawals SOL=open`, `policy set
--allow-asset <mint>`, `policy set --any-asset`). Under an approval rule the
approver runs `approve <private_tx_hash>` for a proven transact, and the
transact then carries the approval account; `transact --withdraw <lamports>`
demonstrates it with the authority as approver.

## Layout

- `program/` the on-chain program: `custom-ring-program` behind this ring's
  entrypoint and address (`.cargo/config.toml`).
- `cli/` the operator CLI (`status`, `deploy`, `init`, `policy`, `transact`, `authority`), from
  `custom-ring-cli`.
- `keys/` the program keypair and the auditor secret, never committed, and
  `auditor.key.pub`, the auditor public key the ring config carries, committed.
- `ring.toml` the wizard's answers.
