# Photon: the Rings Indexer

Photon indexes Rings shielded-pool transactions and exposes the Rings JSON-RPC API:

- `getEncryptedUtxosByTags`
- `getShieldedTransactionsBySignature`
- `getShieldedTransactionsByTags`
- `getMerkleProofs`
- `getNonInclusionProofs`
- `getNullifierQueueElements`
- `getUserRecords`

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

### Ring-scoped history

`getShieldedTransactionsByTags` and `getEncryptedUtxosByTags` accept `tags: []`
only with an explicit `ringProgramId`. The scan includes the ring's deposits,
transfers and merges without recipient tags. The filter uses the SPP instruction's
ring-config account, including rings whose registration was not indexed.
An empty tag list without a ring is rejected. Nonempty tags still narrow the scan.

The existing page limit and ordered cursors apply. Follow `nextCursor` while pages
are full. Save `scannedThrough` from the terminal page to resume after new indexing.
Ciphertexts stay opaque to Photon. Auditor recovery decrypts the returned deposit
capsules and transfer messages client-side.

### Custom rings

The ring projector queues every `WriteRecords` and `RegisterKey` write in the
ring's record queue and applies the whole queue to the 4-ary record tree when
`ApplyRecords` lands. `AuthorityWriteRecords` queues its own writes behind the
pending ones, applies the queue the same way and raises the registry floor to
the applied position. Each application must reach the root and append index the
instruction recorded. A mismatch stops that ring's projection, logs an error and
counts `custom_ring_registry_stopped`, and its reads stay unavailable until a
rollback of the block lifts the stop.

`getRingMemberRecord` and `getRingMemberOpenings` open members under any root the
on-chain history still holds. The response carries the root's history slot and
the queue position it applied, the value a transfer compares with the registry
floor. An absent member opens the low record that brackets it, and a registered
member's record carries its sealed nullifier key. `getRingMemberRecords`
pages leaves at the newest root. `getRingMemberRegistryRoot` returns the root
history, the floor fields, the append index and the path of the next empty leaf,
`null` once the registry is full.
`getRingRecordQueue` returns the pending writes, and `getRingApplyProofInputs`
the inputs of the apply proof over them, followed by the authority writes the
request names. Every read checks the chain's registry and queue accounts after
its database read. `context.slot` is the projection tip, so a client waits until
it reaches the slot of its own write.

One ring projector serves the member registry. It runs alongside SPP indexing with
its own durable cursor and undo journal and applies confirmed blocks in order.
On a fork it suspends lookups, rewinds its own rows, and replays canonical
blocks. SPP tables stay untouched. An SPP indexer fork or archive gap can still
prevent an ordinary SPP proof from being obtained.

A ring whose instruction fails validation, or whose registry or queue account is
missing, is quarantined. Its lookups stay unavailable, every other ring keeps
serving, and a rollback of the fault's journaled block lifts the quarantine.
An otherwise valid registry ahead of the indexer is retried, not quarantined.
Late activation resumes from the ring's durable checkpoint after interruption.
Lookups wait until replay reaches the global custom ring tip.

Use a persistent `--db-url` and run migrations before starting a new binary.
The default temporary database is discarded on startup. For a fresh ring,
`--custom-rings-start-slot` may name its creation slot and must repeat the
stored value on every restart. Do not start after the ring's
`CREATE_MEMBER_REGISTRY` instruction. Keep RPC history available from that
slot, and back up the database and its undo journal.

The member registry answers `-32070` for an unavailable projection, `-32071` for
a root or append index it no longer serves, `-32075` for a page with a gap, and
`-32076` when the record queue moved under an apply request.

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

The photon image is built with the `custom-rings` feature, so custom ring
indexing runs unless photon is started with `--disable-custom-rings`.

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
