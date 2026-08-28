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

## Commands

All commands read `RPC_URL` and `PHOTON_URL` from the environment (a local
`.env` is loaded). `run` additionally needs `PROVER_URL` and `PAYER`;
`close-markers` needs `PAYER`; `info` uses `PAYER` only to report the forester
balance when it is set.

```bash
cargo run -p forester -- info [--tree <PUBKEY>] [--json]
cargo run -p forester -- run --settings <PUBKEY> [--tree <PUBKEY>] [--watch] [--dry-run] ...
cargo run -p forester -- close-markers [--tree <PUBKEY>] [--max-transactions N] [--watch] [--poll-secs S]
```

### `close-markers`

Every queued nullifier owns a nine-byte marker PDA funded from the tree. Once a
queue batch is appended and retires, the tree's `close_before_index` advances
past that batch and its markers become closable by anyone; closing returns the
marker rent to the tree. `close-markers` performs that cleanup:

1. reads `close_before_index` (`w`) from the tree account;
2. fetches the queued nullifiers with sequence `< w` from Photon
   (`getNullifierQueueElements`, paged);
3. drops markers that no longer exist (`getMultipleAccounts`, 100 per call);
4. packs the rest into `close_nullifier_markers` instructions, sized by
   serializing each legacy transaction against the 1232-byte limit (15 markers
   per transaction);
5. submits them with `PAYER` as fee payer and exits non-zero on the first
   failure.

`--watch` repeats with `--poll-secs` between passes and only rescans sequences
it has not already closed. `info` prints `close_before_index` and a per-batch
`retired` flag so the remaining cleanup work is visible without a payer key.
