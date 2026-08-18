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

Non-interactive runs pass every answer with `-d`; `--silent` turns remaining
questions into their defaults:

```bash
RING_NAME=demo tools/ring-wizard.sh /tmp --silent -d target=localnet \
  -d authority_keypair=~/.config/solana/id.json
```

### The wizard

`custom-ring/hooks/wizard.rhai` runs as a cargo-generate `pre` hook, the first
stage that sees `-d` values. It prints the pipeline, asks for the target
(`localnet`, `devnet`; `mainnet` is listed and refused), the authority keypair
(default the Solana CLI keypair), the service URLs (localnet defaults from the
driver, devnet asks), and the features.

`FEATURES` in that file is the registry. Each entry has an `id`, a display
`name`, an `example` and a `state`: `always` (on for every ring), `ready`
(offered as a yes/no question, enabled ids become cargo features of
`custom-ring-program` in the generated `program/Cargo.toml`) or `coming_soon`
(listed, disabled). Adding a feature is one entry; `ring.toml`, the README table
and the cargo feature list follow.

### Variables

| Variable | Source |
| --- | --- |
| `project-name` | cargo-generate `--name` |
| `target`, `authority_keypair`, `rpc_url`, `indexer_url`, `prover_url`, `ring_rpc_url`, `ring_rpc_port` | wizard prompts, or `-d` |
| `program_id` | driver (`solana-keygen new`), or `-d` |
| `zolana_path` | driver (this checkout), or `-d` |
| `default_rpc_url`, `default_indexer_url`, `default_prover_url`, `default_ring_rpc_port` | driver, from `ZOLANA_PORT_OFFSET` |
| `silent` | driver, for `--silent` |
| `feature_<id>`, `features_toml`, `features_markdown`, `program_features` | computed by the wizard |

`just test-ring-template` generates a ring without prompts and builds its
workspace; CI runs it in the custom-ring job.
