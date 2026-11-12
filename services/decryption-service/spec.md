# Decryption Service

The decryption service lets users receive private transfers at a Solana address without registering a private wallet. It runs in a TEE and returns decrypted UTXOs to authorized requesters over an end-to-end encrypted connection.

## Transfer flow

Alice wants to send Bob 10 USDC privately. Bob has not registered his viewing and nullifier keys with the registry program.

### Send

1. Alice enters Bob's Solana wallet address.
2. The SDK looks up Bob's address in the registry and finds no registered private wallet.
3. The SDK requests Bob's recipient-specific viewing and nullifier public keys from the decryption service through Helius.
4. Alice sends Bob 10 USDC privately, committing his UTXO to Bob's signing public key and nullifier public key, and encrypting it to Bob's service-derived viewing public key.

### Receive

1. Bob fetches the encrypted UTXO.
2. Bob signs a decryption request with his Solana key and sends it to the TEE over an end-to-end encrypted connection.
3. The TEE decrypts the UTXO, verifies Bob's signature, and checks that the signing key owns the UTXO.
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
   3. Derive recipient-specific keys on demand inside the TEE using HKDF-SHA256. `recipient_pk` is the recipient's raw 32-byte Solana public key. `nullifier_prk` is the `prk` of the service's initial seed, retained independently of viewing key rotation.

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
   3. Retain every encrypted seed, its encryption context, and access to its KMS key so replacement enclaves can recover existing UTXOs.
   4. Restore a missing encrypted seed from backup; never generate a replacement for existing payments. Fail recovery if the original seed cannot be restored.
   5. Back up each encrypted seed, encryption context, and KMS key ARN using [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) in compliance mode for the configured retention period; retain the object version ID and protect the KMS key separately.
   6. Protect the KMS key from deletion and policy changes using the [existing Nitro key-policy protection](../../tools/nitro/README.md#roles).

### API calls

| API call | Inputs | Output |
|---|---|---|
| `getPublicKey` | Recipient's Solana public key. | The recipient-specific viewing and nullifier public keys derived by the service. |
| `decrypt` | Encrypted decryption request. | Encrypted response containing the decrypted UTXO and the recipient's nullifier secret, after verifying the signature and ownership. |

#### `getPublicKey`

Return the viewing and nullifier public keys derived for `recipient_pubkey`. The viewing private key stays inside the TEE.

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

1. Decrypt and decode the request inside the TEE.
2. Find the current or retained seed root whose recipient-specific viewing public key for `signer_pubkey` matches `viewing_pubkey`, then decrypt the UTXO with that key.
3. Derive the signer's recipient-specific nullifier secret and compute the UTXO hash using its nullifier public key, the plaintext, and `signer_pubkey`.
4. Check that the computed hash matches the authenticated output commitment.
5. Verify the request signature using `signer_pubkey`.
6. Encrypt the decrypted UTXO and the recipient's nullifier secret back to the requester and return them.

##### End-to-end encrypted communication

Attestation verification and request/response encryption follow the [TEE wire contract](../../prover/tee/WIRE_CONTRACT.md), using `TSPP/decryption-service/transport/v1` as the HPKE info and `TSPP/decryption-service/transport/v1/response` as the response-export label.



## SDK

1. **Send:** look up the recipient in the registry. If unregistered, call `getPublicKey(recipient_pubkey)` and use the returned viewing and nullifier public keys to create the transfer.
2. **Receive:** fetch encrypted UTXOs and send signed `decrypt` requests through the attested encrypted transport. Verify each returned UTXO against its commitment and retain its nullifier secret.
3. **Spend:** use the UTXO's retained nullifier secret and the owner's Solana signature to create the spend.

### Future work

PDA authorization verification, we need an authorization pda. You can bridge the pda state with wormhole into the TEE.