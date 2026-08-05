# zolana CLI

Install the `zolana` binary directly from the repository (no checkout needed).
This builds from source, so it pulls the workspace's git dependencies; the CLI is
not published to crates.io.

```bash
cargo install --git https://github.com/helius-labs/zolana --tag v0.1.0-alpha zolana-cli
```

Installing at the release tag keeps the CLI's embedded proving-key/artifact
lockfile in sync with the artifacts it downloads. Use a newer `--tag`, or
`--branch main` / `--rev <sha>`, to track other revisions; re-run with `--force`
to update an existing install.

For local development from a checkout, install from the working tree instead:

```bash
cargo install --path cli --force
```

If `zolana` is not found, add Cargo bin to your PATH:

```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Verify:

```bash
which zolana
zolana --help
```

Commands:

```bash
zolana config get
zolana config set --keypair ~/.config/zolana/pid.json --rpc-url http://127.0.0.1:8899 --indexer-url http://127.0.0.1:8784 --prover-url http://127.0.0.1:3001
zolana wallet init --airdrop-lamports 1000000000
zolana dev pool create-tree --tree-keypair /tmp/zolana-tree.json --airdrop-lamports 20000000000
zolana sync --indexer-url http://127.0.0.1:8784
zolana balance --indexer-url http://127.0.0.1:8784
zolana deposit --amount 1000000000 --mint SOL --airdrop-lamports 2000000000
zolana transfer --to <RECIPIENT_SOLANA_PUBKEY> --amount 300000000 --mint SOL
zolana withdraw --to <PUBLIC_SOL_PUBKEY> --amount 200000000 --mint SOL
```

Wallet commands use the wallet file's Solana funding key for fees/public SOL
deposits and its shielded keypair for private ownership. `wallet init` creates
or loads the wallet file and registers its shielded keys in the on-chain
user-registry program. `deposit` shields public SOL into the local wallet by
default and requires that wallet to be registered; `deposit --to <PUBKEY>`
resolves the recipient from the on-chain user registry and never reads the
recipient's wallet secrets. `transfer --to <PUBKEY>` resolves registered
recipients from the on-chain user registry; if the registry record is absent,
the transfer is built as a public SOL withdrawal to that pubkey. `withdraw --to
<PUBKEY>` always uses a regular public Solana destination.

CLI-wide defaults live at `~/.config/zolana/config.json`. Explicit flags win
over config values, and config values win over built-in localnet defaults. The
`keypair` config field is the path to the wallet file (`pid.json`). `dev pool
create-tree` writes the created tree pubkey into this config file; `deposit`,
`transfer`, and `withdraw` only require `--tree` when neither the flag nor config
has a tree.

Optional wallet path:

```bash
--keypair /path/to/pid.json
```

## Local dev environment

```bash
zolana dev start          # or: zolana test-env
```

By default `dev start` bootstraps a ready-to-use localnet from a pinned GitHub
release: it downloads the shielded-pool, user-registry, and Squads smart-account
programs, an account-snapshot bundle (protocol config, asset counter, the pool
tree at the default tree address, and the Squads authority accounts), and the
prover and Photon binaries, plus the custom surfpool binary from its own release.
Every artifact is verified against the sha256 lockfile embedded in the CLI
(`cli/release-artifacts.lock`) and cached under `~/.config/zolana/cache/<tag>/`,
so repeat starts are offline. This means a fresh `cargo install --path cli` can
boot a fully-initialized localnet with no repo checkout and nothing prebuilt.

Use `--local` to run against locally built artifacts instead (what dev and CI
use after `just build-programs` / `just build-prover-server` / `just
build-photon`):

```bash
zolana dev start --local --sbf-program <ID> target/deploy/<program>.so
```

Passing any explicit `--sbf-program` also implies local mode. Override the
release download host with `ZOLANA_RELEASE_URL`.

Maintainers publish the release with
`just release <tag> --upload --prerelease` (omit the flags for a dry run that only
stages assets and regenerates the lockfile). It builds the programs, the host +
linux-x64 prover/photon binaries, snapshots the initialized accounts in-process
with LiteSVM (no keypairs or running validator needed), and regenerates the
lockfile.
