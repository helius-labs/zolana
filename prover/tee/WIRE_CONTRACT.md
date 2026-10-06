# Encrypted prover wire contract, v1

This contract lets a client encrypt a prover request to a key that only a measured confidential computing environment holds.
Each platform proves the environment its own way and carries the same 64-byte binding.
JSON fields are snake_case, and byte fields and the `Zolana-Tee-Enc` and `Zolana-Tee-Ciphertext` values are lowercase hex.

| Method | Request | Result |
|--------|---------|--------|
| `GET /tee/v1/attestation?nonce=<32 bytes hex>` | a fresh nonce and the prover API key | `platform`, `hpke_public_key`, `gpu` and `evidence` |
| any prover route, encrypted | `Zolana-Tee: v1`, `Zolana-Tee-Enc`, and the encrypted bytes in the body or, for GET, in `Zolana-Tee-Ciphertext` | the inner status, `Zolana-Tee: v1`, and the encrypted status and body |

The prover serves a request without `Zolana-Tee` in plaintext, so the TEE requirement is the client's choice.
The proof routes, `/proving-keys` and the attestation route also answer under the `/v1/zolana` gateway prefix.

## Attestation

`platform` names the format of `evidence`, `dstack-tdx` or `aws-nitro`.
A client refuses a platform its policy does not name.
It refuses an attestation without a `gpu` field, and a non-null `gpu` from a platform that hosts no GPU, before the platform's checks.
Every platform binds the client's nonce, the key that requests are encrypted to, and the GPU verdict into a 64-byte value:

```
report_data = SHA-512("zolana/prover-tee/v1/report" || nonce || hpke_public_key || gpu_digest)
```

`gpu_digest` is the SHA-256 of the `gpu` string, or 32 zero bytes when `gpu` is null.
`gpu` is the raw NRAS response for GPU evidence that the prover collects with the nonce below and verifies inside the environment:

```
gpu_nonce = SHA-256("zolana/prover-tee/v1/gpu" || nonce || hpke_public_key)
```

A client accepts the prover only when its platform's checks below pass, report_data matches, and a policy that requires a GPU sees a non-null `gpu`.

### dstack-tdx

An Intel TDX confidential VM on Phala dstack.
The HPKE key derives from the app's KMS key, so any compose deployed under the app can read the traffic.
`evidence` holds `quote`, `event_log`, `vm_config` and `collateral`, and the quote's report_data is the binding above.
Intel signs `collateral`, so a client accepts it from the prover.
It holds the dcap-qvl `QuoteCollateralV3` fields.
Each `event_log` entry has `imr`, `event_type`, `digest`, `event` and `event_payload`.
An RTMR3 entry can carry an empty `digest`.
A client recomputes every RTMR3 digest, rejects a stated one that differs, and replays from 48 zero bytes:

```
digest = SHA-384(le32(0x08000001) || ":" || event || ":" || event_payload)
rtmr3  = SHA-384(rtmr3 || digest)
```

The checks:

- the quote verifies against Intel's root with the collateral at the current time, and the TD is not in debug mode
- the TCB status, MRTD and RTMR0 to RTMR2 are pinned
- every RTMR3 entry has `event_type` 0x08000001, and the replay equals the quoted RTMR3
- the `app-id`, `compose-hash` and `os-image-hash` events each appear once and are pinned
- the `key-provider` event appears once, and its JSON payload has `name` `kms` and a pinned hex `id`
- `hpke_public_key` is pinned

### aws-nitro

An AWS Nitro Enclave without a GPU.
The enclave draws its HPKE key at boot and never exports it, so each boot attests a new key and a client pins the image, not the key.
`evidence` holds `document`, the attestation document the Nitro Secure Module signs, a COSE_Sign1 structure.
The prover requests it with `user_data` set to report_data, `nonce` set to the client's nonce, and `public_key` set to `hpke_public_key`.

The checks:

- the COSE_Sign1 bytes, its protected header and its payload each hold one CBOR item with no trailing bytes
- none of the three carries a tag, except one optional leading tag 18 on the COSE_Sign1
- none carries a float, an indefinite byte or text string, or a simple value other than false, true and null
- every integer is at most 2^53 minus 1 in magnitude, every text is valid UTF-8, and non-empty arrays and maps nest at most 16 deep
- the COSE_Sign1 structure names ES384 in its protected header, and the document's `certificate` signs it
- `cabundle[0]` is byte for byte the AWS Nitro Enclaves root G1, SHA-256 fingerprint `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`
- the chain runs from `certificate` through `cabundle` in reverse order to the root, each certificate is signed with ecdsa-with-SHA384 by a P-384 key whose subject is its issuer, and each issuer is a CA whose path length and key usage allow the signature
- every certificate is valid at the current time, with up to 300 seconds of tolerance on `notBefore`, and a critical extension other than basic constraints and key usage fails the chain
- the document is a CBOR map of at most 16 entries, and every map in it has unique text or integer keys
- the document holds text where text is due, byte strings where bytes are due and integers where integers are due
- the document has a `module_id` and a `timestamp`, `pcrs` holds at most 32 entries, `cabundle` at most 8 certificates, `digest` is `SHA384`, PCR0, PCR1 and PCR2 are pinned, and PCR0 is not zero as in a debug enclave
- `user_data`, `nonce` and `public_key` equal report_data, the client's nonce and `hpke_public_key`

## Policy

A policy is a JSON object with `platform`, the platform's pins, `gpu` (`required` or `optional`) and `max_age_secs`, the time a passed attestation is reused.
A `dstack-tdx` policy pins `app_id`, `hpke_public_key`, `key_provider_id`, `os_image_hashes`, `measurements` (`mrtd`, `rtmr0`, `rtmr1`, `rtmr2`), `compose_hashes` and `tcb_statuses`.
An `aws-nitro` policy pins `measurements` (`pcr0`, `pcr1`, `pcr2`).

## Encryption

The client encrypts a request body with HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM.
The recipient is `hpke_public_key`, and the info is `zolana/prover-tee/v1`.
`Zolana-Tee-Enc` carries the encapsulated key.
A GET carries its encrypted bytes in `Zolana-Tee-Ciphertext`, because fetch refuses a GET body.
Every other method carries them as an `application/octet-stream` body.
The AAD is the method and the request target without its `api-key` parameters:

```
aad = METHOD " " path [ "?" query ]
```

The path is the one sent.
The query keeps its pairs in order and drops empty pairs and every pair whose key is `api-key`.
The AAD omits `?` when no pair remains.
The answer is AES-256-GCM with a fresh random 12-byte nonce and empty AAD, under the 32-byte HPKE export `zolana/prover-tee/v1/response`.
Its wire bytes are the nonce, ciphertext and 16-byte tag.
Its plaintext is the status as a big-endian `u16`, then the body.
A replayed request derives the same response key, but each answer gets an independent nonce.
A client refuses a 2xx answer without `Zolana-Tee: v1`.
A 400 `tee_decryption_failed` answer means the request does not decrypt under the key the prover holds.
On `aws-nitro`, whose key changes at every boot, the client then attests again and resends the call once.
A resent proof request costs only a second proof, because an encrypted prover runs each request synchronously and keeps no job state.
An unencrypted failure reaches the caller as unauthenticated, so load shedding and retries still work.

## Authorization

TEE servers require synchronous execution and reject queue configuration. A visible job ID is not a client credential.

The prover API key travels in `X-API-Key`, as a Bearer token, or as the `api-key` query parameter.
The AAD never covers it, so a proxy can move or strip it.

## Proxies

A proxy keeps the path and the non-credential query pairs as sent.
It forwards `Zolana-Tee`, `Zolana-Tee-Enc` and `Zolana-Tee-Ciphertext`, and passes octet-stream bodies through unchanged.
For browsers it allows the three headers in CORS preflight and exposes `Zolana-Tee`.
An authorization subrequest to the prover must drop `Zolana-Tee`, or the prover tries to decrypt it.

## Errors

| Status | `code` | Cause |
|--------|--------|-------|
| 400 | `invalid_nonce` | the nonce is not 32 bytes of hex |
| 401 | `unauthorized` | the API key is missing or wrong |
| 429 | `attestation_busy` | quote capacity is exhausted, retry after the `Retry-After` seconds |
| 503 | `attestation_unavailable` | the prover cannot produce attestation evidence |
| 400 | `tee_version_unsupported` | `Zolana-Tee` names another version |
| 400 | `tee_request_malformed` | an encrypted HEAD, a missing or non-hex `Zolana-Tee-Enc` or GET `Zolana-Tee-Ciphertext`, a `Zolana-Tee-Enc` not of 32 bytes, or a body over the size cap |
| 400 | `tee_decryption_failed` | the encrypted request does not decrypt under the held key |

## Test vectors

`testdata/vectors.json` pins report_data with and without a GPU verdict, the GPU nonce, and an encrypted request with its encrypted answer.
`aad_cases` pins the AAD of each request target.
`ikm` derives the prover key with RFC 9180 `DeriveKeyPair`.
`testdata/nitro_cbor_cases.json` pins whether a client accepts each `aws-nitro` case when it trusts `root` in place of the AWS root.
A case holds a full COSE_Sign1, or a payload the test signs with `leaf_key` into a tagged COSE_Sign1.
