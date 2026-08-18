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

## Auditor page

`GET /` renders the auditor's view on the server (maud, no script): every
transaction the key opened, newest first, with `from` (the transaction's Solana
signers), and per output `to` (the viewing key the slot was encrypted to, marked
as change when it is the sender's own), asset, amount, blinding and ring
program. The newest page refreshes itself every few seconds; `older` follows
the indexer cursor. `GET /ready` answers 200 while the indexer answers.

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `health` (also `GET /health`) | none | `{ auditor_view_tag }` |
| `getDecryptedTransactions` | `{ cursor?, limit? }` | `{ context, value: { items, skipped, cursor } }` |

`items` are transactions the key opened, each with `signers`, `outputs` (slot
index, recipient viewing key, asset mint, amount, blinding, ring program id),
the slot positions the key did not open, and the nullifiers. `skipped` lists
transactions tagged for this auditor that did not audit, with the reason.
Scalars use the indexer's encodings. Signers come from the Solana RPC and are
empty when it no longer holds the transaction.

## Operating it

The listener binds to loopback (`--bind`) and answers cross-origin browser
calls only for origins named with `--allow-origin`; the built-in page is
same-origin and needs none. Requests time out after `--request-timeout-secs`
and each upstream call after `--upstream-timeout-secs`. The key file must not be
readable by other users unless `--allow-shared-key-file` says so.

## Boundaries

One ring per instance. No request authentication, no per-user scoping, decrypt
on read. The spec's signed `get_decrypted_utxos_by_owner` and
`get_decrypted_transactions_by_owner` build on this service.
