# zolana CLI

Install from the repository root:

```bash
cargo install --path cli --force
zolana --help
```

## Configuration

CLI defaults live in `~/.config/zolana/config.json`. Use `-C/--config` to
select an isolated config file for one invocation:

```bash
zolana -C /tmp/alice-config.json config set \
  --keypair /tmp/alice.json \
  --rpc-url http://127.0.0.1:8899 \
  --indexer-url http://127.0.0.1:8784 \
  --prover-url http://127.0.0.1:3001
zolana -C /tmp/alice-config.json config get
zolana -C /tmp/alice-config.json config unset tree
```

Config-file precedence is `-C/--config`, then `ZOLANA_CONFIG`, then
`~/.config/zolana/config.json`. Wallet selection is `-k/--keypair`, then
the configured `keypair`, then `~/.config/zolana/id.json`. RPC, indexer, and
prover flags override their configured values; config values override the
built-in localnet service defaults. Tree selection is `--tree`, then the
configured `tree`, then the protocol's canonical deployed tree.

`wallet new --outfile` overrides the configured keypair destination; without it,
creation uses the configured `keypair` and then the `id.json` default. There are
no named wallets.

## Wallet Setup

Creating a wallet is local and does not contact the network. Creation refuses
to overwrite an existing wallet file and prints a self-contained shielded
address that can receive immediately:

```bash
zolana config set --keypair ~/.config/zolana/id.json
zolana wallet new
zolana wallet address
```

Use `--funding-keypair /path/to/solana/id.json` with `wallet new` to use an
existing Solana key as the wallet's public owner and fee payer. The wallet file
stores that funding secret together with its shielded keys and must be protected
accordingly.

Use `-k` to operate on a wallet other than the configured default:

```bash
zolana wallet new --outfile /tmp/bob.json
zolana wallet address -k /tmp/bob.json
zolana wallet address -k /tmp/bob.json --funding
```

## Local Operator Flow

`create-tree` and `test-mint` are top-level operator commands:

```bash
zolana create-tree \
  --tree-keypair /tmp/zolana-tree.json \
  --airdrop-lamports 20000000000

zolana test-mint \
  --amount 1000000 \
  --airdrop-lamports 2000000000
```

`create-tree` creates a tree for a local or custom deployment and saves it as
the selected config's tree override. `test-mint`
saves the mint-to-asset-ID mapping and mints into the selected wallet owner's
associated token account. SPL deposits derive and use that same owner-specific
ATA. Asset mappings store only the mint and on-chain asset ID; owner-specific
token-account addresses are never global config.

Because both commands persist network-specific values, they use the RPC from
the selected config rather than accepting a one-off RPC override. Use `-C` for
another local network.

## Transfers

Amounts and destinations are positional. SOL amounts use decimal SOL units;
SPL amounts use raw base units.

```bash
zolana wallet balance
zolana wallet utxos --mint SOL
zolana wallet deposit 1 --mint SOL
zolana wallet transfer 0.3 <SHIELDED_ADDRESS> --mint SOL
zolana wallet withdraw 0.2 <PUBLIC_SOLANA_PUBKEY> --mint SOL

zolana wallet deposit 600000 --mint <SPL_MINT>
zolana wallet utxos --mint <SPL_MINT>
zolana wallet transfer 250000 <SHIELDED_ADDRESS> --mint <SPL_MINT>
zolana wallet withdraw 100000 <PUBLIC_SOLANA_PUBKEY> --mint <SPL_MINT>
```

`wallet transfer` accepts only the self-contained address printed by `wallet
address`. Use `wallet withdraw` for an intentional public settlement. A deposit
without `--to` shields to the selected wallet; `--to <SHIELDED_ADDRESS>` shields
to someone else. `wallet set-merging on` initializes the on-chain merge-consent
record when that optional feature is first enabled.

Wallet commands synchronize private state automatically. There is no public
`wallet sync` command.
