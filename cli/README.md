# zolana CLI

Run from repo root:

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
zolana wallet create-tree --tree-keypair /tmp/zolana-tree.json --airdrop-lamports 20000000000
zolana wallet sync --indexer-url http://127.0.0.1:8784
zolana wallet balance --indexer-url http://127.0.0.1:8784
zolana wallet deposit --amount 1000000000 --mint SOL --airdrop-lamports 2000000000
zolana wallet transfer --to <RECIPIENT_SOLANA_PUBKEY> --amount 300000000 --mint SOL
zolana wallet withdraw --to <PUBLIC_SOL_PUBKEY> --amount 200000000 --mint SOL
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
`keypair` config field is the path to the wallet file (`pid.json`). `create-tree`
writes the created tree pubkey into this config file; `deposit`, `transfer`, and
`withdraw` only require `--tree` when neither the flag nor config has a tree.

## Merge service

The merge service consolidates several small private UTXOs owned by this wallet
into fewer UTXOs. It needs the wallet secrets locally, a Solana RPC, Photon
indexer, prover server, and the configured shielded-pool tree.

Commands:

```bash
# Enable background merge mode on-chain. This opts into merge service and sets
# the wallet as its own sync delegate. It does not start a process.
zolana wallet merge-service enable

# Run the merge loop in the current terminal until Ctrl+C or an error.
zolana wallet merge-service start

# Start the merge loop in the background and write a pid file/log under
# ~/.config/zolana/merge-service/.
zolana wallet merge-service start --background

# Stop a background or foreground merge-service process started by this CLI.
zolana wallet merge-service stop

# Run one merge pass and exit. Useful for cron/systemd timers.
zolana wallet merge-service once

# Show registry state and whether a pid-file process is running.
zolana wallet merge-service status
```

`start` is the long-running mode. It loops forever: sync wallet, submit at most
one merge when there are mergeable UTXOs, wait for Photon to index it, sleep
(`--interval-secs`, default 30), and repeat. If RPC, Photon, or the prover fails,
the process exits; use a process manager if you need automatic restarts.

Stopping and disabling are different:

```bash
# Stop only the local process. Registry stays self-delegated, so transfer/withdraw
# pre-action merges remain skipped until you start the service again or disable
# background mode.
zolana wallet merge-service stop

# Disable only background mode. This stops the process, revokes self-delegation,
# and keeps on-chain merge permission enabled so transfer/withdraw can run inline
# pre-action merges again.
zolana wallet merge-service disable --background-only

# Disable merging entirely. This stops the process, revokes self-delegation, and
# sets merge_service=false on-chain. Background and pre-action merges are both off.
zolana wallet merge-service disable
```

Pre-action behavior for `transfer` and `withdraw`:

- Runs inline merges when `merge_service=true` and the wallet is not
  self-delegated.
- Skips inline merges when background mode is active
  (`merge_service=true` and `sync_delegate=<wallet pubkey>`).
- Skips inline merges when `merge_service=false`; merges are disabled on-chain.

Optional wallet path:

```bash
--keypair /path/to/pid.json
```

