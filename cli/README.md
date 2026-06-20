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
zolana wallet init --airdrop 1000000000
zolana wallet create-tree --tree-keypair /tmp/zolana-tree.json --airdrop 20000000000
zolana wallet sync --indexer-url http://127.0.0.1:8784
zolana wallet balance --indexer-url http://127.0.0.1:8784
zolana wallet deposit --to <RECIPIENT_SOLANA_PUBKEY> --amount 1000000000 --mint SOL --airdrop 2000000000
zolana wallet transfer --to <RECIPIENT_SOLANA_PUBKEY> --amount 300000000 --mint SOL
zolana wallet withdraw --to <PUBLIC_SOL_PUBKEY> --amount 200000000 --mint SOL
```

Wallet commands use the wallet file's Solana funding key for fees/public SOL
deposits and its shielded keypair for private ownership. `wallet init` creates
or loads the wallet file and registers its shielded keys in the on-chain
user-registry program. `deposit --to <PUBKEY>` and `transfer --to <PUBKEY>`
resolve that owner pubkey from the on-chain user registry.

CLI-wide defaults live at `~/.config/zolana/config.json`. 

Optional wallet path:

```bash
--keypair /path/to/pid.json
```

