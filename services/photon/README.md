# Photon: the Rings Indexer

Photon indexes Rings shielded-pool transactions and exposes the Rings JSON-RPC API:

- `get_encrypted_utxos_by_tags`
- `get_shielded_transactions_by_signature`
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

### Signature lookup rollout

`get_shielded_transactions_by_signature` returns the indexed Rings events for one Solana
transaction signature. Results preserve `event_index` order because one signature can contain
multiple Rings events. Existing deployments need no migration or reindex: the Rings schema
already stores these rows under the `(signature, event_index)` index.

Deploy Photon before clients that call `get_shielded_transactions_by_signature`. Publish the
Photon image from the Zolana commit that contains this method, deploy
`public.ecr.aws/f7o9l7p1/photon@sha256:<digest>`, and run both checks below against the deployed
RPC. `KNOWN_SIGNATURE` must be a signature already indexed by that Photon instance.

```bash
PHOTON_URL=https://<photon-host>
KNOWN_SIGNATURE=<indexed-rings-signature>
UNKNOWN_SIGNATURE=1111111111111111111111111111111111111111111111111111111111111111

lookup() {
  curl -fsS "$PHOTON_URL" \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_shielded_transactions_by_signature\",\"params\":{\"tx_signature\":\"$1\"}}"
}

known="$(lookup "$KNOWN_SIGNATURE")"
jq -e --arg signature "$KNOWN_SIGNATURE" \
  '.result.transactions | length > 0 and all(.[]; .transaction.tx_signature == $signature)' \
  <<<"$known"

unknown="$(lookup "$UNKNOWN_SIGNATURE")"
jq -e '.result.transactions == []' <<<"$unknown"
```

After the smoke passes, pin the matching Zolana commit in consumers and deploy each consumer as
an immutable image or platform revision. Until that commit is published as an immutable release,
do not substitute a branch, working tree, or mutable image tag for the pin.

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
