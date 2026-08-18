# Ring RPC

Serves decrypted transactions of one custom ring to its auditor. The service
holds the ring's auditor viewing key, reads ring transactions from a Photon
indexer by the auditor view tag, recovers each transaction's viewing key from the
auditor message, and returns the opened output slots.

```bash
cargo run -p zolana-ring-rpc -- keygen --out keys/auditor.key
cargo run -p zolana-ring-rpc -- serve \
  --indexer-url http://127.0.0.1:8784 \
  --rpc-url http://127.0.0.1:8899 \
  --auditor-key-file keys/auditor.key
```

`keygen` writes the P256 secret as 64 hex characters (mode 0600) and the SEC1
compressed public key to `keys/auditor.key.pub`, which is what the ring's
`create_config` takes. Every `serve` flag has an environment variable
(`RING_RPC_PORT`, `RING_RPC_INDEXER_URL`, `RING_RPC_SOLANA_RPC_URL`,
`RING_RPC_AUDITOR_KEY_FILE`). The Solana RPC is read once at startup for the SPL
asset registry.

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `health` (also `GET /health`) | none | `{ auditor_view_tag }` |
| `getDecryptedTransactions` | `{ cursor?, limit? }` | `{ context, value: { items, skipped, cursor } }` |

`items` are transactions the key opened, each with `outputs` (slot index, asset
mint, amount, blinding, ring program id), the slot positions the key did not
open, and the nullifiers. `skipped` lists transactions tagged for this auditor
that did not audit, with the reason. Scalars use the indexer's encodings.

## Boundaries

One ring per instance. No request authentication, no per-user scoping, decrypt
on read. The spec's signed `get_decrypted_utxos_by_owner` and
`get_decrypted_transactions_by_owner` build on this service.
