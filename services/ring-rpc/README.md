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

`createAuditorKey` answers only a request signed by the authority the ring's config names, or, while no config exists, by the program's Loader v3 upgrade authority. The signature binds the cluster genesis hash, the ring, a Unix timestamp and a random nonce. The service reads the authority from the chain on every request and accepts a nonce once. `ringStatus` and `health` never return the key the service holds, only the key the config already publishes. The response carries a service signature over the cluster, the ring, the auditor key and the request nonce. The current ring program does not verify the service signature. Operators must verify and pin the service public key through a separate trusted channel.

## JSON RPC

All wire fields use camel case.

| Method | Request | Result |
| --- | --- | --- |
| `health` | none | Service mode and service public key |
| `createAuditorKey` | Ring program ID and authority authorization | Auditor key and service attestation |
| `ringStatus` | Ring program ID | Whether the ring's config names the key held here (`served`), another one (`foreignAuditor`), or does not exist yet (`uninitialized`), with the config's key when it exists |
| `ringDeposits` | Ring program ID, examined signature limit, and page cursor | The deposits found, the next cursor, and the oldest slot examined |
| `getDecryptedTransactions` | Ring, page, and read authorization | Decrypted transaction page |
| `getAuditedMerges` | Ring, page, and read authorization | Hash-checked merge openings and unresolved outputs |
| `getAuditedUtxos` | Ring, 1 to 100 UTXO hashes, and read authorization | `utxos`, in request order, the opening of each hash the service opened, `null` for any other |

`ringDeposits` walks ring history backwards from the newest signature. A deposit publishes its asset and amount, so the method needs no auditor key and no read authorization. Its `limit` counts signatures examined rather than deposits found, so a page can hold no deposits and still have history behind it. The default limit is 50 and the service clamps it to 200.

The response `cursor` is opaque and goes back in the next request. It is present while older ring history remains and absent at the end, so a client pages until it is absent. `oldestSlot` reports the slot of the oldest signature the page examined, absent when the page examined nothing. A client that merges deposits with another paginated stream needs `oldestSlot` to know how far back an empty page reached.

The read authorization contains a canonical reader key, Unix timestamp, random nonce, and signature. The signature binds the method, cluster, service key, ring, timestamp, nonce, cursor, and limit. Ed25519 readers sign the attestation bytes. P256 readers use WebAuthn with user verification.

The authority authorization contains the authority address, the cluster genesis hash, Unix timestamp, random nonce, and a raw Ed25519 signature over the attestation bytes. Both authorizations share the timestamp skew and the per-ring nonce set.

Only a canonical read access record grants access. The config authority has no implicit access. The onchain auditor public key must match the auditor key held by Ring RPC.

Allowed WebAuthn origins need an explicit RP ID. The RP ID can be the origin host or a valid parent domain. Cross origin assertions are rejected.

Accepted nonces are held in process memory for the timestamp window. Run one process for each service key. Multiple replicas need a shared nonce store before they can use the same key.

## Audit result

`outputs` lists every slot whose opening rebuilds its published UTXO hash, with the UTXO, its tree context and, on a ring output, the recipient key and the anonymous tag. `payloadErrors` names every other slot and why. `frame` is a slot without a body of its layout. `disclosure` is a slot whose disclosure bytes do not parse under the layout. `recipientKey` is a recipient key with no X25519 agreement. `commitment` is an opening that hashes to another UTXO hash. `escrowUnknown` is an owner whose escrowed nullifier key the background backfill has not read from the registry. An asset the registry does not know keeps its opening without a mint.

The audit proof binds every disclosure field to the settled notes. The recipient ciphertext of a 2 or 4 output transfer stays outside it. An anonymous disclosure also reveals the sender, the spent notes and the recipients to the auditor. A malformed disclosure is reported as a skipped transaction with a reason. It cannot be presented as a successfully opened payment.

An anonymous transfer that spends no default-ring note names its first spent note by its UTXO hash and every later one by the first 16 bytes of its hash. The service keeps every note it opened in process memory and opens such an input from there. It finds a later input among the ring notes of the first note's owner that carry its prefix. When more of the owner's ring notes carry one prefix than inputs name it, each such input lists those notes as `candidates` and carries no opening. A background backfill reads the ring history from where it stopped and opens every transfer, audited deposit and anonymous merge, so a later page finds the notes they created. A deposit's capsule names the owner hash and no nullifier key, so a deposited note carries none, and neither does the sender of a transfer whose first spent note was deposited. A transfer whose spent note the service has not opened yet appears in `skipped` as `unseenInput`. A restart rebuilds the notes from the ring history.

`getAuditedUtxos` serves the same notes from memory. Its read authorization binds the cluster, the service key, the ring, the timestamp, the nonce and the SHA-256 digest of the hashes in request order.

A transaction that carries the auditor view tag but did not run under this ring is not reported. It reaches neither the audited items nor the skipped rows, and the page cursor still advances past it, so an empty page is not the end of the history.

Photon supplies transaction discovery. Ring RPC fetches each candidate from Solana RPC and requires successful execution with the ring as SPP's direct caller. It reconstructs the exact SPP event and checks the indexed UTXO hashes, ciphertext, viewing metadata, nullifiers and output positions against it. Recovery applies the same check to deposits, merges and spend-query responses. Transfer proofs are enforced by the confirmed on-chain execution.

Clients of Ring RPC trust the configured service to perform these checks. Rebuilding the UTXO hashes of the returned openings alone does not independently authenticate chain history.

The chain RPC remains trusted for confirmed contents. Photon remains trusted for complete history. These checks detect changed contents, but cannot prove that an indexer omitted no transaction. Rows that fail event binding or disclosure checks appear in `skipped`. A failed chain lookup returns an error.

`getAuditedMerges` checks each confirmed merge against the chain and tries auditor keys from authenticated member-registry pages. It stops searching once every output on the history page has a hash-checked opening. Each request is limited to 100 registry pages and 100,000 key and output attempts. If either limit is reached before the scan is complete, the method returns `audit scan exceeded its per-request work budget`. It does not return a partial page. A direct Rust `MergeAudit` scan has no default key-attempt limit and can search the full registry. Photon history rows must advance strictly past the requested cursor, so a repeated event cannot be counted on a later signed page.

## Operation

The server accepts loopback binds only, put a TLS proxy in front of it for remote clients. `--insecure-public-bind` lifts that for a test deployment and serves the decrypted audit data over plain HTTP. Keep the proxy request body limit at or below the service limit.

`GET /health` reports the service identity. `GET /ready` checks Photon and Solana RPC. In local mode it also checks that the ring config still names the auditor key held here. In derived mode it re-reads the cluster genesis hash and fails when it differs from the one captured at boot, because that hash binds every derived key. A failed probe names the check in the response body.

Four lanes admit the JSON RPC methods, and each lane has its own one-second request window. `ringStatus` takes the public lane, the one lane without a concurrency cap. `ringDeposits` takes the deposit lane and spends one unit plus one for each signature it may examine. `createAuditorKey` and `getAuditedUtxos` take an authentication slot, since they verify a signature and read the chain. `getDecryptedTransactions` and `getAuditedMerges` release the authentication slot after the read authorization and hold a read slot for the page. A reader runs one read request at a time on each ring. `health` and `GET /ready` take no lane. `GET /ready` runs one upstream probe at a time and answers from its last result for one second. In local mode `ringDeposits` answers for the served ring only, like `ringStatus`. Key files must have owner access only unless the operator selects the shared file option.
