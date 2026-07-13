# Photon: the Rings Indexer

Photon indexes Rings shielded-pool transactions and exposes the Rings JSON-RPC API:

- `get_encrypted_utxos_by_tags`
- `get_shielded_transactions_by_tags`
- `get_merkle_proofs`
- `get_non_inclusion_proofs`
- `get_nullifier_queue_elements`

Photon is built from the Zolana Cargo workspace so its event parser, tree
layout, SDK contract, and localnet tests always use the same source revision.

## Quick Start

Run against a local validator:

```bash
cargo run -p photon-indexer --bin photon
```

Run against a specific RPC URL:

```bash
cargo run -p photon-indexer --bin photon -- --rpc-url=http://127.0.0.1:8899
```

Use Postgres instead of the default temporary SQLite database:

```bash
export DATABASE_URL="postgres://postgres@localhost/postgres"
cargo run -p photon-indexer --bin photon-migration -- up
cargo run -p photon-indexer --bin photon -- --db-url="$DATABASE_URL"
```

Use Yellowstone gRPC for block streaming:

```bash
cargo run -p photon-indexer --bin photon -- \
  --rpc-url=https://api.devnet.solana.com \
  --grpc-url=<grpc_url>
```

## Rings BlockInfo Snapshots

Photon snapshots store filtered `BlockInfo` payloads, not materialized database rows. The
snapshotter keeps only transactions that contain Rings events, so a new Photon binary can replay
the snapshot through the current parser and persistence code even when the internal database schema
changes.

Write snapshots to a local directory:

```bash
cargo run -p photon-indexer --bin photon-snapshotter -- \
  --rpc-url=https://api.mainnet-beta.solana.com \
  --snapshot-dir=./rings-snapshots \
  --start-slot=<slot>
```

Serve existing snapshots without generating new ones:

```bash
cargo run -p photon-indexer --bin photon-snapshotter -- \
  --snapshot-dir=./rings-snapshots \
  --disable-snapshot-generation
```

Download snapshots from a snapshotter:

```bash
cargo run -p photon-indexer --bin photon-snapshot-loader -- \
  --snapshot-server-url=http://127.0.0.1:8825 \
  --snapshot-dir=./rings-snapshots
```

Bootstrap Photon from snapshots, then continue live indexing from the restored slot:

```bash
cargo run -p photon-indexer --bin photon -- \
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

### Container releases

Production images are published by `.github/workflows/photon-image.yml` through
the protected `photon-production` environment. Configure
`ECR_HELIUS_PROD_AWS_ROLE_ARN` as an environment variable containing an AWS IAM
role that trusts GitHub's OIDC provider only for
`repo:helius-labs/zolana:environment:photon-production`, and restrict that role
to the Photon ECR Public repository. Restrict the environment's deployment tags
to `photon-zolana-*` and require approval for manual releases. Fork releases are
identified by the Zolana commit that contains the Photon source, using
`photon-zolana-<12-character-zolana-commit>`; the imported crate's upstream
version is not used as a Zolana release version.

ECR Public does not provide server-side immutable tags. The workflow serializes
production releases, refuses tags that already exist, publishes a commit tag
first, and verifies both remote tags resolve to the same digest. These checks
narrow but cannot eliminate a race with a publisher outside this workflow;
production access must therefore remain exclusive to this role.

## Development

Run the Rings integration tests:

```bash
cargo test -p photon-indexer
```

Check the main binary:

```bash
cargo check -p photon-indexer --bin photon
```

Generate the Rings OpenAPI spec:

```bash
npm install --global @apidevtools/swagger-cli@4.0.4
cargo run -p photon-indexer --bin photon-openapi
```
