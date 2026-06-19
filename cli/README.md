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
zolana wallet sync
zolana wallet balance
zolana wallet deposit --to 11111111111111111111111111111111 --amount 100 --mint SOL
zolana wallet transfer --to /tmp/bob.pid.json --amount 30 --mint SOL
zolana wallet withdraw --to 11111111111111111111111111111111 --amount 20 --mint SOL
```

Optional keypair path

```bash
--keypair /path/to/pid.json
```

