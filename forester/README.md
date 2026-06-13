# Forester

Forester is the off-chain service responsible for shielded-pool tree
maintenance. In the current skeleton it exposes the direct SPP submission helper
for `batch_update_nullifier_tree`; queue scanning and proof generation are
reintroduced separately.

## Scope

- Builds SPP maintenance instructions directly through `zolana-interface`.
- Signs with the protocol authority configured in SPP `ProtocolConfig`.
- Submits a proposed nullifier-tree root plus compressed Groth16 proof.
- Does not depend on the removed registry program.

## Development

```bash
cargo check -p forester --all-targets
cargo test -p forester
```

The CLI is still a skeleton:

```bash
cargo run -p forester -- start
```
