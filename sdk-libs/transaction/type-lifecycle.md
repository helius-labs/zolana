| Step | Current types | Where they live | How they are used |
|---|---|---|---|
| **1. Fetch encrypted UTXOs** | `GetEncryptedUtxosByTagsResponse`, `EncryptedUtxoMatch` | `zolana-client` | Return matching output payloads with transaction signature, slot, viewing public key and salt. |
| | `GetShieldedTransactionsByTagsResponse`, `ShieldedTransaction` | `zolana-client`, `zolana-transaction/src/indexer_types.rs` | The transaction-oriented retrieval path returns outputs, messages, nullifiers and transaction metadata together. |
| | `OutputSlot`, `OutputContext` | `zolana-transaction/src/indexer_types.rs` | Carry each output's view tag, encoded payload, commitment hash, tree ID and leaf index. |
| | `Context` | `zolana-client` | Shared response metadata: block time and highest indexed slot. |
| **2. Decrypt and verify UTXOs** | `OutputDataEncoding`, `DecodeCx`, `OwnerCx` | `zolana-event`, `zolana-transaction` | Identify the payload encoding and provide the viewing key, transaction metadata and owner information for decoding. |
| | `AssetRegistry`, `Mint` | `zolana-transaction` | Resolve a decrypted asset ID into its mint address and compact ID. |
| | `Utxo` | `zolana-transaction` | The decoded note: owner, mint, amount, blinding, ring and data. Its commitment is recomputed and verified. |
| | `WalletUtxo` | `zolana-transaction` | A decoded note with commitment, nullifier, data hashes and indexed context; verification is a separate step. |
| | `DecryptionResult`, `SpendableDecryptionResult` | `zolana-transaction` | `decrypt()` returns all decoded candidates. After application-specific hash reconstruction, `verify_spendable()` checks ownership, commitments and observed spends, returning ordinary balances and verified data-bearing notes separately. `decrypt_spendable()` wraps both calls. |
| | `AssetBalance`, `Balances` | `zolana-transaction` | Group spendable notes and amounts by asset in the stateless decryption result. |
| **3. Select input UTXOs** | `WalletUtxo`, `SpendInputParams`, `SelectedSpendInputs` | `zolana-transaction`, `zolana-wallet` | Wallet selection consumes a spending request and returns selected proof inputs and their trees. |
| | `WalletUtxo` | `zolana-transaction` | Input accepted by the transaction builder, retaining the note, tree location and transaction-history metadata until padding. |
| | `UnsignedInputUtxo` | `zolana-wallet` | Private wallet intermediate carrying selected note data before conversion to `SppProofInputUtxo`. |
| **4. Create requested outputs and settlement operations** | `ConfidentialTransaction` | `zolana-transaction` | Mutable builder holding selected `WalletUtxo` inputs, requested outputs and public settlement requests. |
| | `MergeTransaction` | `zolana-transaction` | `new()` and `new_with_ring()` accept wallet UTXOs and validate input counts, assets and ring data without keys. |
| | `Recipient`, `ShieldedAddress` | `zolana-transaction`, `zolana-keypair` | Describe the output recipient, mint, amount and ring; the address supplies ownership and encryption public keys. |
| | `SppProofOutputUtxo` | `zolana-transaction` | Prospective output with mint, amount, blinding, recipient information, ring and data commitments. |
| | `PublicTransferRequest`, `SettlementTarget` | `zolana-transaction` | Describe a deposit or withdrawal and its public SOL account or SPL token account. |
| | `UnsignedPrivateTransaction`, `PrivateTransactionAction`, `CreatedTransfer`, `CreatedWithdrawal` | `zolana-wallet` | Higher-level wallet request wrappers recording selected inputs, the requested action, settlement accounts and approval information. They wrap planning before encryption. |
| **5. Finalize and encrypt** | `ConfidentialTransaction`, `Shape`, `SppProofInputUtxo`, `SppProofOutputUtxo` | `zolana-transaction` | `pad_utxos()` calculates change, converts wallet inputs to proof inputs and pads both vectors in order. The conversion preserves tree IDs and leaf indices and drops transaction-history metadata. `encrypt()` selects a shape and calls padding if needed, then assigns final output blindings. |
| | `MergeProofInputs`, `ConfidentialOutputPlaintext` | `zolana-transaction` | `encrypt(&shielded_keys)` derives the sender address, deterministic output blinding and transaction viewing key, then delegates to `encrypt_with_viewing_key(&sender, &tx_viewing_key, output_blinding)`. The lower-level method validates ownership, encrypts the consolidated output using the confidential format and a fresh salt, converts wallet inputs and pads them. The result carries the ciphertext, viewing public key and salt; publishing these still requires merge instruction and event support. |
| | `ConfidentialOutputPlaintext`, `ConfidentialEncode`, `MessageData`, `OutputDataEncoding` | `zolana-transaction`, `zolana-event` | Encode and encrypt each output into a payload with a view tag. |
| | `ResolvedOwnerTag`, `OwnerTag`, `TransactOutput` | `zolana-transaction`, `zolana-interface` | Associate each encrypted output with its resolved owner tag and commitment. |
| | `SettlementTransfer`, `ExternalData` | `zolana-transaction` | Assemble public settlement legs, encrypted outputs, viewing public key, salt and messages. |
| | `SppProofInputs` | `zolana-transaction` | Return value of `encrypt()`: finalized plaintext input/output UTXOs, blinding seed, output tree ID, payer and encrypted external data. No proof or Solana signature yet. |
| | `SignedPrivateTransaction`, `TransactInterfaceTransferAccounts` | `zolana-client`, `zolana-interface` | Existing client wrapper around `SppProofInputs` plus settlement account information. Despite its name, the wrapper contains no signature. |
| **6. Request the proof — assuming the prover fetches input proofs** | `SppProofInputs`, `SppProofInputUtxo` | `zolana-transaction` | Supply the prepared transaction; proof fetching reads commitments, nullifiers and tree IDs directly from borrowed input UTXOs. |
| | `SpendProof`, `MerkleProof`, `NonInclusionProof`, `TransferInputUtxo` | `zolana-client` | Existing types for commitment inclusion, nullifier non-inclusion and inputs with attached proofs. Under the agreed flow, fetching and attaching these happen inside the prover. |
| | `PublicTransfers`, `PrivateTxHash` | `zolana-transaction` | Compute per-asset public settlement fields and the private transaction commitment. |
| | `TransferProver`, `BuiltCircuit`, `ProverVariant`, `ProverInputs`, `TransferInputs`, `AssembledTransfer` | `zolana-client` | Existing circuit/witness assembly representations. Under the agreed flow these are proving internals, rather than additional caller-facing preparation steps. `AssembledTransfer` also holds instruction data awaiting the proof. |
| | `Proof`, `ProofCompressed`, `TransactProof` | `zolana-client`, `zolana-interface` | Represent the generated proof and its conversion into the form attached to the instruction. |
| **7. Create the instruction** | `TransactIxData`, `TransactProof` | `zolana-interface` | Complete the instruction data with the proof and public transaction fields. Instruction data and witness are assembled together; this step attaches the resulting proof. |
| | `Transact`, `TransactInterfaceTransferAccounts`, `AccountMeta`, `Instruction` | `zolana-interface`, Solana crates | Combine instruction data with payer, signer, tree and settlement accounts to construct the Solana instruction. |
| **8. Build and sign the Solana transaction** | `ComputeBudgetConfig`, `Hash`, `VersionedMessage` | `zolana-client`, Solana crates | Combine instructions, payer, compute configuration and a fresh blockhash into the transaction message. |
| | `Signer`, `VersionedTransaction` | Solana crates | Collect required signatures and produce the signed Solana transaction. |
| **9. Send the transaction** | `VersionedTransaction`, `Signature` | Solana crates | Submit the signed transaction through RPC and retain its signature for tracking. |
| **10. Confirm and update wallet state** | `Signature`, `GetShieldedTransactionsBySignatureResponse`, `IndexedShieldedTransaction`, `ShieldedTransaction` | Solana crates, `zolana-client`, `zolana-transaction` | Wait for confirmation and indexing, then retrieve published transaction data. |
| | `Wallet`, `SyncReport`, `PrivateTransaction`, `PrivateTransactionId` | `zolana-wallet` | Track spent inputs, decrypt new outputs and update holdings, history and synchronization results. `PrivateTransaction` is a wallet history record. |
| | `WalletUtxo`, `AssetBalance` | `zolana-transaction` | Store newly discovered spendable notes and updated balances, ready for another selection. |

| Types used across steps | Steps | How they are used |
|---|---|---|
| `ProofInputUtxo` | 6 | Field-element representation in `zolana-client::prover`, converted from input and output UTXOs for circuit witness assembly. Commitment verification and transaction construction hash directly in `zolana-transaction`. |
| `Blinding` | 2–6 | Blinding carried by a note and used in commitment/nullifier calculations. Final output blindings are assigned in step 5. |
| `Mint`, `Data`, `DataRecord` | 2–6 | Resolved asset information and note data carried through decryption, selection, output creation, encryption and proving. |
