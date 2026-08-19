# Templates

## custom-ring

A cargo-generate template that produces a custom ring repository: a thin
program crate over `custom-ring-program` pinned to a fresh deploy address, an
operator CLI over `custom-ring-cli`, `ring.toml` with the wizard's answers, and a
`justfile` for the pipeline (build, GitHub repo, deploy under the user's key,
init with the auditor key, ring RPC, transact).

Run it through the driver, which generates the program keypair, passes the
per-clone service URLs, and copies this checkout's `Cargo.lock` so the ring
resolves dependencies exactly as zolana does:

```bash
just ring-new              # ring lands next to this checkout
just ring-new ~/rings      # or in a chosen parent directory
```

Non-interactive runs pass every answer with `-d`, and `--silent` turns the
remaining questions into their defaults.

```bash
RING_NAME=demo tools/ring-wizard.sh /tmp --silent -d target=localnet \
  -d authority_keypair=~/.config/solana/id.json
```

### The wizard

`custom-ring/hooks/wizard.rhai` runs as a cargo-generate `pre` hook, the first
stage that sees `-d` values. It prints the pipeline, asks for the target
(`localnet` or `devnet`, `mainnet` is listed and refused), the authority keypair
(default the Solana CLI keypair), the service URLs (localnet defaults from the
driver, devnet asks, plus the ring RPC's service pubkey that `init` pins), and
the features.

`FEATURES` in that file is the registry. Each entry has an `id`, a display
`name`, an `example` and a `state`: `always` (on for every ring), `ready`
(offered as a yes/no question) or `coming_soon` (listed, disabled). Adding a
feature is one entry, and `ring.toml` and the README table follow. The resolved
answer is `<id>_enabled` (a bool), which is what liquid files and
`[conditional]` blocks read. Features that need on-chain values add them to
`policy_toml`, rendered as `ring.toml`'s `[policy]` table: `allowed_assets`
asks for the mints (`-d allowed_assets=SOL,<mint>` without prompts, `SOL` is
native SOL) and `withdrawal_rules` asks for the default withdrawal rule
(`-d withdrawals=blocked|approval|open`, where `approval` needs an approver,
default the authority, `-d approver=<pubkey>`). `just init` writes the policy
on chain and the CLI's `policy` command shows or changes it, per asset too.

### Variables

| Variable | Source |
| --- | --- |
| `project-name` | cargo-generate `--name` |
| `target`, `authority_keypair`, `rpc_url`, `indexer_url`, `prover_url`, `ring_rpc_url`, `ring_rpc_port` | wizard prompts, or `-d` |
| `program_id` | driver (`solana-keygen new`), or `-d` |
| `zolana_path` | driver (this checkout), or `-d` |
| `default_rpc_url`, `default_indexer_url`, `default_prover_url`, `default_ring_rpc_port` | driver, from `ZOLANA_PORT_OFFSET` |
| `silent` | driver, for `--silent` |
| `feature_<id>` | `-d` only, the answer for a `ready` feature |
| `<id>_enabled`, `features_toml`, `features_markdown`, `policy_toml` | computed by the wizard |

`just test-ring-template` generates a ring without prompts and builds its
workspace. CI runs it in the custom-ring job.
