# Ring RPC

Serves decrypted transactions of custom rings to their auditor. The service holds
the auditor viewing keys, reads ring transactions from a Photon indexer by the
auditor view tag (the x-coordinate of the auditor public key, on the last
message of every ring transact), recovers each transaction's viewing key from
the auditor message, and returns the opened output slots.

Two key modes. Local: one key from a file, one ring per instance.

```bash
cargo run -p zolana-ring-rpc -- keygen --out keys/auditor.key
cargo run -p zolana-ring-rpc -- serve \
  --indexer-url http://127.0.0.1:8784 \
  --rpc-url http://127.0.0.1:8899 \
  --auditor-key-file keys/auditor.key
```

Derived: `HKDF(root_secret, ring_program_id)`, any ring on demand, the key a
ring gets is minted by `createAuditorKey` and stays stable across restarts.

```bash
cargo run -p zolana-ring-rpc -- serve \
  --indexer-url http://127.0.0.1:8784 \
  --rpc-url http://127.0.0.1:8899 \
  --root-secret-file keys/root.secret        # 32 bytes as 64 hex characters
```

`keygen` writes the P256 secret as 64 hex characters (mode 0600) and the SEC1
compressed public key to `keys/auditor.key.pub`, which is what the ring's
`create_config` takes. Every `serve` flag has an environment variable
(`RING_RPC_PORT`, `RING_RPC_INDEXER_URL`, `RING_RPC_SOLANA_RPC_URL`,
`RING_RPC_AUDITOR_KEY_FILE`, `RING_RPC_ROOT_SECRET_FILE`). The Solana RPC is
read once at startup for the SPL asset registry.

## Auditor page

`GET /` renders the auditor's view on the server (maud, no script): every
transaction the key opened, newest first, with `from` (the transaction's Solana
signers), and per output `to` (the viewing key the slot was encrypted to),
asset, amount, blinding and ring program. `?ring=<program id>` selects the ring
in derived mode. The newest page refreshes itself every few seconds; `older`
follows the indexer cursor. `GET /ready` answers 200 while the indexer answers.

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `health` (also `GET /health`) | none | `{ mode, auditor_view_tag? }` |
| `createAuditorKey` | `{ ring_program_id }` | `{ ring_program_id, auditor_pubkey, auditor_view_tag, key_version }` |
| `getDecryptedTransactions` | `{ ring_program_id?, cursor?, limit? }` | `{ context, value: { items, skipped, cursor } }` |

`mode` is `local` or `derived`. `ring_program_id` is required in derived mode
and ignored in local mode. `items` are transactions the key opened, each with
`signers`, `outputs` (slot index, recipient viewing key, asset mint, amount,
blinding, ring program id), the slot positions the key did not open, and the
nullifiers. `skipped` lists transactions tagged for this auditor that did not
audit, with the reason. Signers come from the Solana RPC and are empty when it
no longer holds the transaction.

## Operating it

The listener binds to loopback (`--bind`) and answers cross-origin browser
calls only for origins named with `--allow-origin`; the built-in page is
same-origin and needs none. Requests time out after `--request-timeout-secs`
and each upstream call after `--upstream-timeout-secs`. Key files must not be
readable by other users unless `--allow-shared-key-file` says so.

## Boundaries

No request authentication, no per-user scoping, decrypt on read. The spec's
signed `get_decrypted_utxos_by_owner` and `get_decrypted_transactions_by_owner`
build on this service.
