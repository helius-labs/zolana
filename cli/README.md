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
zolana config set --keypair ~/.config/zolana/id.json --rpc-url http://127.0.0.1:8899 --indexer-url http://127.0.0.1:8784 --prover-url http://127.0.0.1:3001
zolana wallet new
zolana wallet address
zolana wallet address --funding
zolana wallet create-tree --tree-keypair /tmp/zolana-tree.json --airdrop-lamports 20000000000
zolana wallet balance --indexer-url http://127.0.0.1:8784
zolana wallet deposit --amount 1000000000 --mint SOL --airdrop-lamports 2000000000
zolana wallet transfer --to <RECIPIENT_SHIELDED_ADDRESS> --amount 300000000 --mint SOL
zolana wallet withdraw --to <PUBLIC_SOL_PUBKEY> --amount 200000000 --mint SOL
```

Wallet commands use the wallet file's Solana funding key for fees/public SOL
deposits and its shielded keypair for private ownership. `wallet new` is an
offline operation: it creates a fresh shielded identity and a funding key
without sending a transaction. Pass `--funding-keypair
~/.config/solana/id.json` to reuse an existing standard Solana keypair as the
funding/fee-payer key. `wallet address` prints the self-contained shielded
recipient address; `wallet address --funding` prints the public funding key.

`deposit` shields public assets into the local wallet by default. `deposit --to
<SHIELDED_ADDRESS>` and `transfer --to <SHIELDED_ADDRESS>` accept the exact value
printed by `wallet address`, so receiving private transfers does not require an
on-chain registry record. Private transfers never fall back to a public
payment. Use `withdraw --to <PUBKEY>` for an explicit public Solana destination.
Balance and transaction commands synchronize wallet state automatically.

CLI-wide defaults live at `~/.config/zolana/config.json`. Explicit flags win
over config values, and config values win over built-in localnet defaults. The
wallet path precedence is `-k/--keypair`, then `config.keypair`, then
`~/.config/zolana/id.json`. Use `-C/--config <PATH>` to select another config
file; it takes precedence over `ZOLANA_CONFIG`. `create-tree` writes the created
tree pubkey into the selected config file; `deposit`, `transfer`, and `withdraw`
only require `--tree` when neither the flag nor config has a tree.

Optional wallet path:

```bash
-k /path/to/id.json
```
