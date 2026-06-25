# Photon: the Rings Indexer

Photon indexes Rings shielded-pool transactions and exposes the Rings JSON-RPC API:

- `get_encrypted_utxos_by_tags`
- `get_shielded_transactions_by_tags`
- `get_merkle_proofs`
- `get_non_inclusion_proofs`

## Quick Start

Run against a local validator:

```bash
photon
```

Run against a specific RPC URL:

```bash
photon --rpc-url=http://127.0.0.1:8899
```

Use Postgres instead of the default temporary SQLite database:

```bash
export DATABASE_URL="postgres://postgres@localhost/postgres"
photon-migration up
photon --db-url="$DATABASE_URL"
```

Use Yellowstone gRPC for block streaming:

```bash
photon --rpc-url=https://api.devnet.solana.com --grpc-url=<grpc_url>
```

## Rings BlockInfo Snapshots

Photon snapshots store filtered `BlockInfo` payloads, not materialized database rows. The
snapshotter keeps only transactions that contain Rings events, so a new Photon binary can replay
the snapshot through the current parser and persistence code even when the internal database schema
changes.

Write snapshots to a local directory:

```bash
photon-snapshotter \
  --rpc-url=https://api.mainnet-beta.solana.com \
  --snapshot-dir=./rings-snapshots \
  --start-slot=<slot>
```

Serve existing snapshots without generating new ones:

```bash
photon-snapshotter --snapshot-dir=./rings-snapshots --disable-snapshot-generation
```

Download snapshots from a snapshotter:

```bash
photon-snapshot-loader \
  --snapshot-server-url=http://127.0.0.1:8825 \
  --snapshot-dir=./rings-snapshots
```

Bootstrap Photon from snapshots, then continue live indexing from the restored slot:

```bash
photon \
  --db-url="$DATABASE_URL" \
  --rpc-url=https://api.mainnet-beta.solana.com \
  --snapshot-dir=./rings-snapshots
```

`--r2-bucket`/`--r2-prefix` and `--gcs-bucket`/`--gcs-prefix` are available for remote snapshot
storage.

## Operations

Photon fails closed when it cannot safely reconstruct Rings nullifier tree batches. A
non-contiguous nullifier queue or reconstructed-root mismatch makes the indexer retry the same
block batch until the underlying data or code is fixed. Alert on stale `getIndexerHealth` results,
`block_batch_index_failures`, and errors containing `Cannot reconstruct nullifier batch` or
`Reconstructed nullifier root mismatch`.

## Development

Run the Rings integration tests:

```bash
cargo test --test integration_tests
```

Check the main binary:

```bash
cargo check --bin photon
```

Generate the Rings OpenAPI spec:

```bash
cargo run --bin photon-openapi
```
