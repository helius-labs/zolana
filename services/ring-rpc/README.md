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

The command writes the secret with owner access only. It writes the X25519 public key to `keys/auditor.key.pub`.

Derived mode serves a stable key for each ring and cluster, for as many rings as ask. Generate a root secret with `keygen --kind root`. Protect one root as carefully as all keys derived from it. The key comes from the root, the cluster genesis hash and the ring program id, so a new ring needs no configuration, no restart, and nothing stored. Repointing the service at another cluster changes every derived key and orphans every ring already registered.

A ring must take its auditor key from the service before it creates its config. The config fixes the auditor for the life of the ring, so a ring registered with any other key can never be read here, whatever the service derives for it. `ringStatus` reports which of the three cases a ring is in.

`createAuditorKey` answers only a request signed by the authority the ring's config names, or, while no config exists, by the program's Loader v3 upgrade authority. The signature binds the cluster genesis hash, the ring, a Unix timestamp and a random nonce. The service reads the authority from the chain on every request and accepts a nonce once. `ringStatus` and `health` never return the key the service holds, only the key the config already publishes. The response carries a service signature over the ring and auditor key. The current ring program does not verify the service signature. Operators must verify and pin the service public key through a separate trusted channel.

## JSON RPC

All wire fields use camel case.

| Method | Request | Result |
| --- | --- | --- |
| `health` | none | Service mode and service public key |
| `createAuditorKey` | Ring program ID and authority authorization | Auditor key and service attestation |
| `ringStatus` | Ring program ID | Whether the ring's config names the key held here (`served`), another one (`foreignAuditor`), or does not exist yet (`uninitialized`), with the config's key when it exists |
| `ringDeposits` | Ring program ID, examined signature limit, and page cursor | The deposits found, the next cursor, and the oldest slot examined |
| `getDecryptedTransactions` | Ring, page, and read authorization | Decrypted transaction page |
| `getAuditedMerges` | Ring, page, and read authorization | Commitment-checked merge openings and unresolved outputs |

`ringDeposits` walks ring history backwards from the newest signature. A deposit publishes its asset and amount, so the method needs no auditor key and no read authorization. Its `limit` counts signatures examined rather than deposits found, so a page can hold no deposits and still have history behind it. The default limit is 50 and the service clamps it to 200.

The response `cursor` is opaque and goes back in the next request. It is present while older ring history remains and absent at the end, so a client pages until it is absent. `oldestSlot` reports the slot of the oldest signature the page examined, absent when the page examined nothing. A client that merges deposits with another paginated stream needs `oldestSlot` to know how far back an empty page reached.

The read authorization contains a canonical reader key, Unix timestamp, random nonce, and signature. The signature binds the ring, timestamp, nonce, cursor, and limit. Ed25519 readers sign the attestation bytes. P256 readers use WebAuthn with user verification.

The authority authorization contains the authority address, the cluster genesis hash, Unix timestamp, random nonce, and a raw Ed25519 signature over the attestation bytes. Both authorizations share the timestamp skew and the per-ring nonce set.

Only a canonical read access record grants access. The config authority has no implicit access. The onchain auditor public key must match the auditor key held by Ring RPC.

Allowed WebAuthn origins need an explicit RP ID. The RP ID can be the origin host or a valid parent domain. Cross origin assertions are rejected.

Accepted nonces are held in process memory for the timestamp window. Run one process for each service key. Multiple replicas need a shared nonce store before they can use the same key.

## Audit result

`outputOpenings` carries the verified auditor disclosure for every output slot. Each entry contains its note fields and published tree context. The client checks their commitments. These openings remain available when recipient ciphertext is missing, corrupt or misleading.

`outputs` carries optional recipient metadata. `payloadErrors` names each slot without an entry there and why, a frame, decrypt, commitment, asset or pair-hint failure. Neither field replaces `outputOpenings`. Unknown asset fields stay in the verified openings. The service attempts to resolve them from the asset registry without dropping the disclosure when a refresh fails.

Mandatory auditor encryption is proved against the committed notes. Ordinary recipient ciphertext is not proved. Anonymous disclosure also reveals the checked sender, spent notes and recipients to the auditor. A malformed mandatory disclosure is reported as a skipped transaction with a reason. It cannot be presented as a successfully opened payment.

A transaction that carries the auditor view tag but did not run under this ring is not reported. It reaches neither the audited items nor the skipped rows, and the page cursor still advances past it, so an empty page is not the end of the history.

Photon supplies transaction discovery. Ring RPC fetches each candidate from Solana RPC and requires successful execution with the ring as SPP's direct caller. It reconstructs the exact SPP event and checks the indexed commitments, ciphertext, viewing metadata, nullifiers and output positions against it. Recovery applies the same check to deposits, merges and spend-query responses. Transfer proofs are enforced by the confirmed on-chain execution.

Clients of Ring RPC trust the configured service to perform these checks. Validating the returned opening commitments alone does not independently authenticate chain history.

The chain RPC remains trusted for confirmed contents. Photon remains trusted for complete history. These checks detect changed contents, but cannot prove that an indexer omitted no transaction. Rows that fail event binding or disclosure checks appear in `skipped`. A failed chain lookup returns an error.

`getAuditedMerges` checks each confirmed merge against the chain and tries auditor keys from authenticated member-registry pages. It stops searching once every output on the history page has a commitment-checked opening. Each request is limited to 100 registry pages and 100,000 key and output attempts. If either limit is reached before the scan is complete, the method returns `audit scan exceeded its per-request work budget`. It does not return a partial page. A direct Rust `MergeAudit` scan has no default key-attempt limit and can search the full registry. Photon history rows must advance strictly past the requested cursor, so a repeated event cannot be counted on a later signed page.

## Operation

The server accepts loopback binds only, put a TLS proxy in front of it for remote clients. `--insecure-public-bind` lifts that for a test deployment and serves the decrypted audit data over plain HTTP. Keep the proxy request body limit at or below the service limit.

`GET /health` reports the service identity. `GET /ready` checks Photon and Solana RPC. In local mode it also checks that the ring config still names the auditor key held here. In derived mode it re-reads the cluster genesis hash and fails when it differs from the one captured at boot, because that hash binds every derived key. A failed probe names the check in the response body.

One request rate window gates every JSON RPC method and `GET /ready`, so nothing reaches an upstream unmetered. `health`, `ringStatus` and `ringDeposits` are unauthenticated and take that gate alone. `createAuditorKey` takes the authentication gate and its concurrency slot, since it verifies a signature and reads the chain. In local mode `ringDeposits` answers for the served ring only, like `ringStatus`. `getDecryptedTransactions` adds a global concurrency slot, one page at a time for each reader, and the read authorization. Key files must have owner access only unless the operator selects the shared file option.
