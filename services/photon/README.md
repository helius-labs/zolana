# Photon: the Rings Indexer

Photon indexes Rings shielded-pool transactions and exposes the Rings JSON-RPC API:

- `getEncryptedUtxosByTags`
- `getShieldedTransactionsBySignature`
- `getShieldedTransactionsByTags`
- `getMerkleProofs`
- `getNonInclusionProofs`
- `getNullifierQueueElements`

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

Images are published by `.github/workflows/publish-image.yml`, which publishes
photon, the prover and the forester, through the protected `image-publish`
environment. Configure `vars.AWS_IMAGE_PUBLISHER_ROLE_ARN` as a repository
variable holding an AWS IAM role that trusts GitHub's OIDC provider only for
`repo:helius-labs/zolana:environment:image-publish`, and restrict that role to
the zolnet ECR repositories.

Two channels. `release` requires the tag to name the commit
(`<service>-zolana-<12-character-zolana-commit>`) and the commit to be on `main`;
the imported crate's upstream version is not a Zolana release version. `preview`
takes any branch and any tag, and refuses a `-zolana-` tag so a preview cannot
claim a release name. Both are attested and immutable.

The registry is private ECR with `IMMUTABLE` tags, so the registry itself refuses
to move a published tag. The workflow also serializes publishes per service,
refuses tags that already exist, publishes the `sha-<commit>` alias first, and
verifies both remote tags resolve to the same digest — a clearer failure than a
push rejection, not the only guard.

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
