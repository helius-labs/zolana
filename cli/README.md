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
zolana balance
zolana deposit --amount 100 --mint SOL
zolana transfer --to-wallet /tmp/bob.json --amount 30 --mint SOL
zolana withdraw --amount 20 --mint SOL --to 11111111111111111111111111111111
```

Optional path overrides

```bash
--wallet /path/to/wallet.json
--state-file /path/to/state.json
```

