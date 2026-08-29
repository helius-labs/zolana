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
`close-nullifier-pdas` needs `PAYER`; `info` uses `PAYER` only to report the forester
balance when it is set.

```bash
cargo run -p forester -- info [--tree <PUBKEY>] [--json]
cargo run -p forester -- run --settings <PUBKEY> [--tree <PUBKEY>] [--watch] [--dry-run] ...
cargo run -p forester -- close-nullifier-pdas [--tree <PUBKEY>] [--from-seq N] [--max-transactions N] [--watch] [--poll-secs S]
```

### `close-nullifier-pdas`

Every queued nullifier owns a nine-byte PDA funded from the tree. Once a
successor queue batch is fully appended, the tree's `close_before_index`
advances past the preceding batch and its PDAs become closable by anyone;
closing returns the PDA rent to the tree. Batch storage may be reused before
that point. `close-nullifier-pdas` performs the cleanup:

1. reads `close_before_index` (`w`) from the tree account;
2. fetches the queued nullifiers with sequence `< w` from Photon
   (`getNullifierQueueElements`, paged);
3. drops PDAs that no longer exist (`getMultipleAccounts`, 100 per call);
4. packs the rest into `close_nullifier_pdas` instructions, deriving the
   capacity from the 1232-byte legacy transaction limit;
5. submits them with `PAYER` as fee payer, replanning if another permissionless
   closer wins a PDA race.

`--watch` repeats with `--poll-secs` between passes and only rescans sequences
it has not already closed. On restart, pass the last completed watermark via
`--from-seq` (and persist it in the process supervisor) to avoid rescanning from
zero. Failed watch passes retain their scan watermark and retry instead of
terminating the daemon. `info` prints `close_before_index` and a per-batch
`reclaimable` flag so the remaining cleanup work is visible without a payer key.
