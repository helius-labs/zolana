# Zolana RPC API

JSON-RPC 2.0 API surface for the Zolana shielded pool.

The API is served by independent backends that MAY be bundled by a single RPC provider:

- **Photon Indexer** -- indexes the UTXO tree, nullifier tree, and encrypted UTXOs. Default-pocket users fetch ciphertexts here and decrypt client-side.
- **Pocket RPC** -- holds a policy pocket's auditor key; serves decrypted UTXOs and balances to policy-pocket users.
- **Decryption Service** -- opt-in; holds a per-user decryption capability for default-pocket users who want server-built proof inputs (Mode 1).
- **Merge Service** -- opt-in; merges a user's UTXOs into fewer larger UTXOs.

Each method accepts a JSON-RPC 2.0 request envelope and returns a JSON-RPC 2.0 response.

## Photon Indexer

| # | Endpoint | Description | Response |
|---|----------|-------------|----------|
| 1 | `/get_encrypted_utxos` | Returns encrypted UTXO records whose `encrypted_utxos` blob matches all of the supplied byte filters. Filters are AND-ed. Each filter is a `(offset, bytes)` pair; the server matches if `blob[offset .. offset + len(bytes)] == bytes`.  The set of indexed offsets is implementation-defined; see the indexing strategy in the spec. Filters on unindexed offsets MAY be rejected.  Results are ordered by `(slot, tx_index, output_index)` and paginated via the opaque `cursor` field. | `GetEncryptedUtxosResponse` |
| 2 | `/get_proof` | Submits proof inputs to the prover and returns a compressed Groth16 proof. Caller is responsible for constructing the proof inputs (Mode 2) or delegating to the Decryption Service (Mode 1). | `GetProofResponse` |
| 3 | `/send_transaction` | Submits a transaction to the SPP. Two modes:  - **Mode 1 (server-built proof inputs)** -- caller signs `P256(recipient || amount)`;   the RPC selects input UTXOs, builds proof inputs, fetches the proof, and submits.   Requires a Decryption Service relationship. - **Mode 2 (client-built proof inputs)** -- caller signs `P256(tx_hash)` where   `tx_hash` binds all input and output UTXO hashes. The RPC acts as a relayer only. | `SendTransactionResponse` |

## Pocket RPC

| # | Endpoint | Description | Response |
|---|----------|-------------|----------|
| 4 | `/get_decrypted_utxos` | Returns the caller's UTXOs decrypted server-side using the pocket auditor key. | `GetDecryptedUtxosResponse` |
| 5 | `/get_balance` | Get aggregate shielded balance for a pocket member | `GetBalanceResponse` |
| 6 | `/get_instruction` | Returns a built instruction (with proof) for the caller to sign and submit directly. Used for shield, where the user signs the Solana transaction. | `GetInstructionResponse` |

---
*Auto-generated from `openapi.yaml`. Do not edit manually.*
*Regenerate with: `./docs/api/generate-readme.sh` or `just gen-api-readme`.*
