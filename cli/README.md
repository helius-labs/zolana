# rings CLI

Run from repo root:

```bash
cargo install --path cli --force
```

If `rings` is not found, add Cargo bin to your PATH:

```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Verify:

```bash
which rings
rings --help
```

Commands:

```bash
rings config get
rings config set --keypair ~/.config/rings/pid.json --rpc-url http://127.0.0.1:8899 --indexer-url http://127.0.0.1:8784 --prover-url http://127.0.0.1:3001
rings wallet init --airdrop-lamports 1000000000
rings wallet create-tree --tree-keypair /tmp/rings-tree.json --airdrop-lamports 20000000000
rings wallet sync --indexer-url http://127.0.0.1:8784
rings wallet balance --indexer-url http://127.0.0.1:8784
rings wallet deposit --amount 1000000000 --mint SOL --airdrop-lamports 2000000000
rings wallet transfer --to <RECIPIENT_SOLANA_PUBKEY> --amount 300000000 --mint SOL
rings wallet withdraw --to <PUBLIC_SOL_PUBKEY> --amount 200000000 --mint SOL
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

CLI-wide defaults live at `~/.config/rings/config.json`. Explicit flags win
over config values, and config values win over built-in localnet defaults. The
`keypair` config field is the path to the wallet file (`pid.json`). `create-tree`
writes the created tree pubkey into this config file; `deposit`, `transfer`, and
`withdraw` only require `--tree` when neither the flag nor config has a tree.

Optional wallet path:

```bash
--keypair /path/to/pid.json
```

