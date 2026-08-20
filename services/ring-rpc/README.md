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
  --auditor-key-file keys/auditor.key --ring-program-id <program id>
```

Derived: `HKDF(root_secret, genesis_hash || ring_program_id)`, any ring on
demand. The key a ring gets is minted by `createAuditorKey`, stays stable across
restarts, and differs per cluster for the same ring id. Nothing is kept per
ring between requests.

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

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `health` (also `GET /health`) | none | `{ mode, service_pubkey, auditor_view_tag? }` |
| `createAuditorKey` | `{ ring_program_id }` | `{ ring_program_id, auditor_pubkey, auditor_view_tag, service_pubkey, signature }` |
| `getDecryptedTransactions` | `{ ring_program_id?, cursor?, limit?, auth: { scope, reader, timestamp, signature, webauthn? } }` | `{ context, value: { items, skipped, cursor } }` |

`mode` is `local` or `derived`. `ring_program_id` is required in derived mode
and ignored in local mode, where `--ring-program-id` names the one ring the key
serves.

Reads are signed. `auth.signature` is `auth.reader`'s signature over the text
`zolana/ring-rpc-read/v1` followed by one line each of `scope: <ring|participant>`,
`ring: <base58>`, `timestamp: <unix seconds>`, `limit: <n or 0>`,
`cursor: <base64 or empty>`, joined with `\n`, `auth.timestamp` within a minute
of the service clock. Text, so browser wallets show it and sign it.
Two scopes. `ring` needs the ring authority its on-chain config records (an
ed25519 key) or a reader the authority granted on chain, an ed25519 key or a
P-256 passkey, and returns every transaction plus the skipped list. A passkey
signs through WebAuthn: `auth.signature` is the DER signature,
`auth.webauthn.{authenticator_data, client_data_json}` the authenticator
output, the challenge `SHA-256` of the bytes above, and the origin must be one
named with `--allow-origin` (so no allowed origin, no passkeys). `participant`
takes any key and returns only that key's side: an ed25519 signer of a
transaction sees the transactions it signed in full, a P-256 viewing key (SEC1
compressed, ECDSA over `SHA-256(message)`) sees only the outputs encrypted to
it, and a key outside a transaction sees nothing. A read signed by another key
than it claims, for another ring, or captured earlier is refused with
`unauthorized`. `GetDecryptedTransactionsRequest::unsigned(..)` builds both:
`.sign(authority)`, `.sign_as_sender(signer)`, `.sign_as_recipient(viewing_key)`. `signature` is the instance's ed25519 signature over
`"zolana/ring-auditor-key/v1" || ring_program_id || auditor_pubkey` with
`service_pubkey`, which is derived from the instance's secret and so survives
restarts. A ring pins that key in `ring.toml` (`ring_rpc_pubkey`) after
confirming it out of band, and its `init` refuses an auditor key signed by any
other key. The auditor key is fixed at `create_config`, so this is the one
moment the ring can be given the wrong auditor. `items` are transactions the key opened, each with
`signers`, `outputs` (slot index, recipient viewing key, asset mint, amount,
blinding, ring program id), the slot positions the key did not open, and the
nullifiers. `skipped` lists transactions tagged for this auditor that did not
audit, with the reason. Signers come from the Solana RPC and are empty when it
no longer holds the transaction.

## Operating it

The listener binds to loopback (`--bind`) and answers cross-origin browser
calls only for origins named with `--allow-origin`. `GET /ready` answers 200
while the indexer answers. Requests time out after `--request-timeout-secs`
and each upstream call after `--upstream-timeout-secs`. Key files must not be
readable by other users unless `--allow-shared-key-file` says so.

## Boundaries

Decrypt on read. The participant scope is the spec's signed
`get_decrypted_transactions_by_owner` over what the auditor can see; a reader
list for third-party auditors is not there yet, so the auditor is the ring
authority.
