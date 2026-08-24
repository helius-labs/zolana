# Ring RPC

Ring RPC holds an auditor viewing key and opens custom ring transfer outputs. It reads ring transactions from Photon and checks ring access accounts on Solana.

## Keys

Local mode serves one ring with one auditor key file. Generate the key before ring config creation.

```bash
cargo run -p zolana-ring-rpc -- keygen --out keys/auditor.key
cargo run -p zolana-ring-rpc -- serve \
  --indexer-url http://127.0.0.1:8784 \
  --rpc-url http://127.0.0.1:8899 \
  --auditor-key-file keys/auditor.key \
  --ring-program-id <program-id>
```

The command writes the secret with owner access only. It writes the compressed public key to `keys/auditor.key.pub`.

Derived mode serves a stable key for each ring and cluster, for as many rings as ask. Generate a root secret with `keygen --kind root`. Protect one root as carefully as all keys derived from it. The key comes from the root, the cluster genesis hash and the ring program id, so a new ring needs no configuration, no restart, and nothing stored. Repointing the service at another cluster changes every derived key and orphans every ring already registered.

A ring must take its auditor key from the service before it creates its config. The config fixes the auditor for the life of the ring, so a ring registered with any other key can never be read here, whatever the service derives for it. `ringStatus` reports which of the three cases a ring is in.

`createAuditorKey` returns a service signature over the ring and auditor key. The current ring program does not verify the service signature. Operators must verify and pin the service public key through a separate trusted channel.

## JSON RPC

All wire fields use camel case.

| Method | Request | Result |
| --- | --- | --- |
| `health` | none | Service mode, service public key, and local view tag |
| `createAuditorKey` | Ring program ID | Auditor key and service attestation |
| `ringStatus` | Ring program ID | The key held for the ring, and whether its config names that key (`served`), another one (`foreignAuditor`), or does not exist yet (`uninitialized`) |
| `ringDeposits` | Ring program ID, examined signature limit, and page cursor | The deposits found, the next cursor, and the oldest slot examined |
| `getDecryptedTransactions` | Ring, page, and read authorization | Decrypted transaction page |

`ringDeposits` walks ring history backwards from the newest signature. A deposit publishes its asset and amount, so the method needs no auditor key and no read authorization. Its `limit` counts signatures examined rather than deposits found, so a page can hold no deposits and still have history behind it. The default limit is 50 and the service clamps it to 200.

The response `cursor` is opaque and goes back in the next request. It is present while older ring history remains and absent at the end, so a client pages until it is absent. `oldestSlot` reports the slot of the oldest signature the page examined, absent when the page examined nothing. A client that merges deposits with another paginated stream needs `oldestSlot` to know how far back an empty page reached.

The read authorization contains a canonical reader key, Unix timestamp, random nonce, and signature. The signature binds the ring, timestamp, nonce, cursor, and limit. Ed25519 readers sign the attestation bytes. P256 readers use WebAuthn with user verification.

Only a canonical read access record grants access. The config authority has no implicit access. The onchain auditor public key must match the auditor key held by Ring RPC.

Allowed WebAuthn origins need an explicit RP ID. The RP ID can be the origin host or a valid parent domain. Cross origin assertions are rejected.

Accepted nonces are held in process memory for the timestamp window. Run one process for each service key. Multiple replicas need a shared nonce store before they can use the same key.

## Audit result

Each opened output includes the asset mint, amount, recipient viewing key, and ring field. Each transaction also includes public nullifiers and undecryptable output positions. The response does not identify private input owners and does not return blindings.

The released transfer proof does not prove that output ciphertext matches the committed UTXO. The ring program checks Confidential framing. Ring RPC reports output slots that it cannot decrypt. A decrypted value is not proof of the committed plaintext.

A transaction that carries the auditor view tag but did not run under this ring is not reported. It reaches neither the audited items nor the skipped rows, and the page cursor still advances past it, so an empty page is not the end of the history.

Photon is an integrity boundary for transaction rows, slots, signatures, ciphertext, and nullifiers. It needs no ring support. Ring RPC reads the matched transactions by the auditor view tag, then fetches each one from Solana RPC and keeps it only when the shielded pool instruction has the ring program as its direct caller, the position that holds the `ring_auth` signer. It also checks the supported transaction shape. It does not verify the default transfer proof.

## Operation

The server accepts loopback binds only, put a TLS proxy in front of it for remote clients. `--insecure-public-bind` lifts that for a test deployment and serves the decrypted audit data over plain HTTP. Keep the proxy request body limit at or below the service limit.

`GET /health` reports the service identity. `GET /ready` checks Photon and Solana RPC. In local mode it also checks that the ring config still names the auditor key held here. In derived mode it re-reads the cluster genesis hash and fails when it differs from the one captured at boot, because that hash binds every derived key. A failed probe names the check in the response body.

One request rate window gates every JSON RPC method and `GET /ready`, so nothing reaches an upstream unmetered. `health`, `createAuditorKey`, `ringStatus` and `ringDeposits` are unauthenticated and take that gate alone. In local mode `ringDeposits` answers for the served ring only, like `ringStatus`. `getDecryptedTransactions` adds a global concurrency slot, one page at a time for each reader, and the read authorization. Key files must have owner access only unless the operator selects the shared file option.
