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
zolana wallet init
zolana wallet create-tree --tree-keypair /tmp/zolana-tree.json --airdrop-lamports 20000000000
zolana wallet sync --indexer-url http://127.0.0.1:8784
zolana wallet balance --indexer-url http://127.0.0.1:8784
zolana wallet deposit --tree <TREE_PUBKEY> --to /tmp/bob.pid.json --amount 1000000000 --mint SOL --airdrop-lamports 2000000000
zolana wallet transfer --tree <TREE_PUBKEY> --to <RECIPIENT_SOLANA_PUBKEY> --amount 300000000 --mint SOL
zolana wallet withdraw --tree <TREE_PUBKEY> --to <PUBLIC_SOL_PUBKEY> --amount 200000000 --mint SOL
```

Wallet commands use the wallet file's Solana funding key for fees/public SOL
deposits and its shielded keypair for private ownership. `wallet init` writes a
temporary local user-registry JSON entry, and `transfer --to <PUBKEY>` resolves
that pubkey to the recipient shielded address from that file until the CLI reads
the on-chain user-registry program directly. `deposit --to` still points at a
recipient wallet file for the proofless deposit blinding path.

Optional wallet path:

```bash
--keypair /path/to/pid.json
```

