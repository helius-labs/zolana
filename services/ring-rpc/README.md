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

Derived mode serves a stable key for each ring and cluster. Generate a root secret with `keygen --kind root`. Protect one root as carefully as all keys derived from it.

`createAuditorKey` returns a service signature over the ring and auditor key. The current ring program does not verify the service signature. Operators must verify and pin the service public key through a separate trusted channel.

## JSON RPC

All wire fields use camel case.

| Method | Request | Result |
| --- | --- | --- |
| `health` | none | Service mode, service public key, and local view tag |
| `createAuditorKey` | Ring program ID | Auditor key and service attestation |
| `getDecryptedTransactions` | Ring, page, and read authorization | Decrypted transaction page |

The read authorization contains a canonical reader key, Unix timestamp, random nonce, and signature. The signature binds the ring, timestamp, nonce, cursor, and limit. Ed25519 readers sign the attestation bytes. P256 readers use WebAuthn with user verification.

Only a canonical reader record grants access. The config authority has no implicit access. The onchain auditor public key must match the auditor key held by Ring RPC.

Allowed WebAuthn origins need an explicit RP ID. The RP ID can be the origin host or a valid parent domain. Cross origin assertions are rejected.

Accepted nonces are held in process memory for the timestamp window. Run one process for each service key. Multiple replicas need a shared nonce store before they can use the same key.

## Audit result

Each opened output includes the asset mint, amount, recipient viewing key, and ring field. Each transaction also includes public nullifiers and undecryptable output positions. The response does not identify private input owners and does not return blindings.

The released transfer proof does not prove that output ciphertext matches the committed UTXO. The ring program checks Confidential framing. Ring RPC reports output slots that it cannot decrypt. A decrypted value is not proof of the committed plaintext.

Photon is an integrity boundary for transaction rows, slots, signatures, ciphertext, and nullifiers. It needs no ring support. Ring RPC reads the matched transactions by the auditor view tag, then fetches each one from Solana RPC and keeps it only when the shielded pool instruction has the ring program as its direct caller, the position that holds the `ring_auth` signer. It also checks the supported transaction shape. It does not verify the default transfer proof.

## Operation

The server accepts loopback binds only. Put a TLS proxy in front of it for remote clients. Keep the proxy request body limit at or below the service limit.

`GET /health` reports the service identity. `GET /ready` checks Photon, Solana RPC, and the local ring auditor key. Key files must have owner access only unless the operator selects the shared file option.
