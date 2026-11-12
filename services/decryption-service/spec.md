# Decryption Service

The decryption service lets users receive private transfers at a Solana address without registering a private wallet. It runs in a TEE and returns decrypted UTXOs to authorized requesters over an end-to-end encrypted connection.

## Transfer flow

Alice wants to send Bob 10 USDC privately. Bob has not registered his viewing and nullifier keys with the registry program.

### Send

1. Alice enters Bob's Solana wallet address.
2. The SDK looks up Bob's address in the registry and finds no registered private wallet.
3. The SDK verifies the TEE's attestation and requests Bob's recipient-specific viewing and nullifier public keys over an end-to-end encrypted connection. Helius relays the encrypted request and response.
4. Alice sends Bob 10 USDC privately, committing his UTXO to Bob's signing public key and nullifier public key, and encrypting it to Bob's service-derived viewing public key.

### Receive

1. Bob fetches the encrypted UTXO.
2. Bob signs a decryption request with his Solana key and sends it to the TEE over an end-to-end encrypted connection.
3. The TEE verifies Bob's signature, decrypts the UTXO, and checks that the signing key owns the UTXO.
4. The TEE returns the decrypted UTXO and Bob's nullifier secret over the encrypted connection.
5. Bob retains the nullifier secret to spend these UTXOs; his signature is still required to authorize a spend.

## Decryption Server

### Startup

1. TEE initialization and attestation.
   1. Start the server inside a TEE.
   2. Obtain Nitro attestation containing the enclave's recipient encryption public key.
   3. Require the KMS key policy to restrict seed decryption to approved enclave measurements; fail startup if attestation or seed recovery fails.
2. KMS seed recovery and key derivation.

   Follow the [Nitro prover's seed recovery](../../tools/nitro/README.md#shared-key):
   1. Provision a 32-byte seed once using `KMS.GenerateDataKeyWithoutPlaintext`. Store the encrypted seed and its encryption context with durable backups.
   2. Call `KMS.Decrypt` with the encrypted seed, encryption context, and Nitro attestation in `Recipient`. KMS verifies the enclave measurements and returns `CiphertextForRecipient`; the enclave unwraps it to recover the seed.
   3. Derive recipient-specific keys on demand inside the TEE using HKDF-SHA256. `recipient_pk` is the 32-byte Ed25519 key inside the request's `PublicKey` (`recipient_pubkey` or `signer_pubkey`). `nullifier_prk` is the `prk` of the service's initial seed, retained independently of viewing key rotation.
      ```text
       prk := HKDF-Extract(salt=∅, IKM=seed)
       viewing_sk := clamp(HKDF-Expand(
           prk, "TSPP/view_key/ed25519/x25519/v1" || recipient_pk, L=32))
       viewing_pk := 0x04 || X25519(viewing_sk, 9)
       nullifier_secret := HKDF-Expand(
           nullifier_prk, "TSPP/nf_key/ed25519/v1" || recipient_pk, L=31)
       nullifier_pk := Poseidon(nullifier_secret)
      ```
   
      The service must never expose plaintext seeds or viewing private keys outside the TEE.
   
      Viewing and nullifier keys use distinct derivation labels, each bound to the recipient's public key. Senders receive only the two public keys; the recipient receives the nullifier secret after signature and UTXO ownership verification. A UTXO's nullifier key is fixed when the UTXO is created.
3. Key rotation and recovery.
   1. After a restart, recover the same seed to reconstruct the same recipient keys.
   2. To rotate viewing keys, provision a new seed and return its recipient viewing public keys through `getPublicKey`; retain the initial seed for `nullifier_prk`.
   3. Retain every encrypted seed, its encryption context, and access to its KMS key so a replacement enclave with the same measurements can recover existing UTXOs. An enclave with other measurements receives the seeds through the enclave upgrade in step 4.
   4. Restore a missing encrypted seed from backup; never generate a replacement for existing payments. Fail recovery if the original seed cannot be restored.
   5. Back up each encrypted seed, encryption context, and KMS key ARN using [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).
   6. Protect each KMS key from deletion and policy changes using the [existing Nitro key-policy protection](../../tools/nitro/README.md#roles). After that protection the policy cannot change.
4. Enclave upgrade.

   A KMS key policy names one set of enclave measurements, so a new enclave image cannot recover the service seeds from KMS. The running enclave hands them over:
   1. Deploy the new image with its own KMS key and a 32-byte release seed, provisioned as in step 2 with a key policy that names the new measurements. The release seed is used only to encrypt handed-over seeds.
   2. The new enclave draws an X25519 keypair and requests a Nitro attestation document that contains its public key and a nonce drawn by the running enclave.
   3. The running enclave verifies the document with the [aws-nitro checks](../../prover/tee/WIRE_CONTRACT.md#aws-nitro). It requires PCR0, PCR1 and PCR2 to equal the measurements of a [signed release](../../prover/tee/WIRE_CONTRACT.md#signed-policy) whose version is higher than its own and which the release keys pinned in its own image signed.
   4. The running enclave encrypts the seeds it holds, and which of them is the initial seed, to the attested public key with HPKE base mode and the info `TSPP/decryption-service/handover/v1`.
   5. The new enclave encrypts each received seed with AES-256-GCM using a wrap key and stores the results with the backups of step 3. After a restart it recovers its release seed from KMS and decrypts them.
      ```text
       wrap_key := HKDF-Expand(
           HKDF-Extract(salt=∅, IKM=release_seed),
           "TSPP/decryption-service/seed_wrap/v1", L=32)
      ```
   6. Before requests move to the new enclaves, check that they return the same `getPublicKey` response as the running enclaves for the same recipient, and that a restarted new enclave still does. Keep the running enclaves until both checks pass. A release without a completed handover must not replace them.
   
      The release keys can approve an image that receives the seeds, so they are part of the trust root for the derived viewing keys and nullifier secrets.

### API calls


| API call       | Inputs                                                          | Output                                                                                                                              |
| -------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `getPublicKey` | Encrypted request containing the recipient's Solana public key. | Encrypted response containing the recipient-specific viewing and nullifier public keys derived by the service.                      |
| `decrypt`      | Encrypted decryption request.                                   | Encrypted response containing the decrypted UTXO and the recipient's nullifier secret, after verifying the signature and ownership. |


#### `getPublicKey`

Return the viewing and nullifier public keys derived for `recipient_pubkey`. Reject a `recipient_pubkey` whose curve is not Ed25519. The viewing private key stays inside the TEE.

The request and response use the [encrypted transport](#end-to-end-encrypted-communication). A response that decrypts comes from the attested enclave, and the relay does not learn which recipient a sender looks up. A UTXO created with keys from another source cannot be decrypted by the service or spent by the recipient.

```rust
use spr_keypair::{PublicKey, X25519Pubkey};

pub struct GetPublicKeyRequest {
    pub recipient_pubkey: PublicKey,
}

pub struct GetPublicKeyResponse {
    pub viewing_pubkey: X25519Pubkey,
    pub nullifier_pubkey: [u8; 32],
}
```

#### `decrypt`

```rust
use spr_keypair::{PublicKey, Signature, X25519Pubkey};
use spr_transaction::{OutputSlot, Utxo};

pub struct DecryptRequest {
    pub ciphertext: Vec<u8>,
}

pub struct DecryptResponse {
    pub ciphertext: Vec<u8>,
}

pub struct DecryptRequestPlaintext {
    pub signer_pubkey: PublicKey,
    pub signature: Signature,
    pub viewing_pubkey: X25519Pubkey,
    pub tx_viewing_pubkey: X25519Pubkey,
    pub salt: [u8; 16],
    pub slot_index: u32,
    pub output: OutputSlot,
}

pub struct DecryptResponsePlaintext {
    pub utxo: Utxo,
    pub nullifier_secret: [u8; 31],
}
```

`signature` is the signer's Ed25519 signature over `decrypt_message`, a Solana off-chain message v0 with the encoding of [`derivation_message`](../../docs/spec.md#solana-wallet) and its own payload and application domain. `signer_pubkey` is the message's one signer.

```text
decrypt_label      := "TSPP/decryption-service/decrypt/v1"
payload            := decrypt_label || "/" || hex(output.output_context.hash)
application_domain := SHA-256(decrypt_label)
```

`hex` is lowercase, so the payload is printable ASCII as message format 0 requires. One signature authorizes the decryption of one output.

1. Decrypt and decode the request inside the TEE. Reject a `signer_pubkey` whose curve is not Ed25519.
2. Rebuild `decrypt_message` from `signer_pubkey` and the output hash, and verify `signature` over it using `signer_pubkey`. Reject the request if verification fails.
3. Find the current or retained seed root whose recipient-specific viewing public key for `signer_pubkey` matches `viewing_pubkey`, then decrypt the UTXO with that key.
4. Derive the signer's recipient-specific nullifier secret and compute the UTXO hash using its nullifier public key, the plaintext, and `signer_pubkey`.
5. Check that the computed hash equals `output.output_context.hash` from the request. The service has no view of Solana state; the SDK compares the returned UTXO with the output hash it fetched.
6. Encrypt the decrypted UTXO and the recipient's nullifier secret back to the requester and return them.

#### End-to-end encrypted communication

`getPublicKey` and `decrypt` are sent encrypted. Attestation verification and request/response encryption follow the [TEE wire contract](../../prover/tee/WIRE_CONTRACT.md) with these values:

| Contract parameter | Decryption service value |
| --- | --- |
| `platform` | `aws-nitro` |
| `gpu` | null, so `gpu_digest` is 32 zero bytes |
| `report_data` domain | `TSPP/decryption-service/transport/v1/report` |
| HPKE info | `TSPP/decryption-service/transport/v1` |
| Response export label | `TSPP/decryption-service/transport/v1/response` |
| Encrypted routes | `POST /getPublicKey`, `POST /decrypt` |



## SDK

1. **Send:** look up the recipient in the registry. If unregistered, call `getPublicKey(recipient_pubkey)` through the attested encrypted transport and use the returned viewing and nullifier public keys to create the transfer.
2. **Receive:** fetch encrypted UTXOs and send signed `decrypt` requests through the attested encrypted transport. Recompute each returned UTXO's hash, compare it with the fetched output hash, and retain its nullifier secret.
3. **Spend:** use the UTXO's retained nullifier secret and the owner's Solana signature to create the spend.

### Future work

For PDA authorization verification we need an authorization pda. We can bridge the verification pda state with wormhole into the TEE.