# Sealed prover wire contract, v1

This contract lets a client seal a prover request to a key that only a measured Intel TDX confidential VM holds.
The key derives from the app's KMS key, so any compose deployed under the app can read the traffic.
JSON fields are snake_case, and byte fields and the `Zolana-Tee-Enc` and `Zolana-Tee-Seal` values are lowercase hex.

| Method | Request | Result |
|--------|---------|--------|
| `GET /tee/v1/attestation?nonce=<32 bytes hex>` | a fresh nonce and the prover API key | `quote`, `event_log`, `vm_config`, `collateral`, `hpke_public_key` and `gpu` |
| any prover route, sealed | `Zolana-Tee: v1`, `Zolana-Tee-Enc`, and the sealed bytes in the body or, for GET, in `Zolana-Tee-Seal` | the inner status, `Zolana-Tee: v1`, and the sealed status and body |

The prover serves a request without `Zolana-Tee` in plaintext, so the TEE requirement is the client's choice.
The proof routes, `/proving-keys` and the attestation route also answer under the `/v1/zolana` gateway prefix.

## Attestation

The quote's 64-byte report_data binds the client's nonce, the key that requests are sealed to, and the GPU verdict:

```
report_data = SHA-512("zolana/prover-tee/v1/report" || nonce || hpke_public_key || gpu_digest)
```

`gpu_digest` is the SHA-256 of the `gpu` string, or 32 zero bytes when `gpu` is null.
`gpu` is the raw NRAS response for GPU evidence that the prover collects with the nonce below and verifies inside the TDX guest:

```
gpu_nonce = SHA-256("zolana/prover-tee/v1/gpu" || nonce || hpke_public_key)
```

Intel signs `collateral`, so a client accepts it from the prover.
It holds the dcap-qvl `QuoteCollateralV3` fields.
Each `event_log` entry has `imr`, `event_type`, `digest`, `event` and `event_payload`.
An RTMR3 entry can carry an empty `digest`.
A client recomputes every RTMR3 digest, rejects a stated one that differs, and replays from 48 zero bytes:

```
digest = SHA-384(le32(0x08000001) || ":" || event || ":" || event_payload)
rtmr3  = SHA-384(rtmr3 || digest)
```

A client accepts the prover only when all of these hold:

- the quote verifies against Intel's root with the collateral at the current time
- the TCB status, MRTD and RTMR0 to RTMR2 are pinned
- every RTMR3 entry has `event_type` 0x08000001, and the replay equals the quoted RTMR3
- the `app-id`, `compose-hash` and `os-image-hash` events each appear once and are pinned
- the `key-provider` event appears once, and its JSON payload has `name` `kms` and a pinned hex `id`
- `hpke_public_key` is pinned
- report_data matches
- a policy that requires a GPU sees a non-null `gpu`

## Sealing

The client seals a request body with HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM.
The recipient is `hpke_public_key`, and the info is `zolana/prover-tee/v1`.
`Zolana-Tee-Enc` carries the encapsulated key.
A GET carries its sealed bytes in `Zolana-Tee-Seal`, because fetch refuses a GET body.
Every other method carries them as an `application/octet-stream` body.
The AAD is the method and the request target without its `api-key` parameters:

```
aad = METHOD " " path [ "?" query ]
```

The path is the one sent.
The query keeps its pairs in order and drops empty pairs and every pair whose key is `api-key`.
The AAD omits `?` when no pair remains.
The answer is AES-256-GCM with a zero 12-byte nonce and empty AAD, under the 32-byte HPKE export `zolana/prover-tee/v1/response`.
Its plaintext is the status as a big-endian `u16`, then the body.
A client refuses a 2xx answer without `Zolana-Tee: v1`.
An unsealed failure reaches the caller as unauthenticated, so load shedding and retries still work.

## Authorization

The prover API key travels in `X-API-Key`, as a Bearer token, or as the `api-key` query parameter.
The AAD never covers it, so a proxy can move or strip it.

## Proxies

A proxy keeps the path and the non-credential query pairs as sent.
It forwards `Zolana-Tee`, `Zolana-Tee-Enc` and `Zolana-Tee-Seal`, and passes octet-stream bodies through unchanged.
For browsers it allows the three headers in CORS preflight and exposes `Zolana-Tee`.
An authorization subrequest to the prover must drop `Zolana-Tee`, or the prover tries to open it.

## Errors

| Status | `code` | Cause |
|--------|--------|-------|
| 400 | `invalid_nonce` | the nonce is not 32 bytes of hex |
| 401 | `unauthorized` | the API key is missing or wrong |
| 429 | `attestation_busy` | quote capacity is exhausted, retry after the `Retry-After` seconds |
| 503 | `attestation_unavailable` | the prover cannot produce attestation evidence |
| 400 | `tee_version_unsupported` | `Zolana-Tee` names another version |
| 400 | `tee_seal_invalid` | the sealed request does not open |

## Test vectors

`testdata/vectors.json` pins report_data with and without a GPU verdict, the GPU nonce, and a sealed request with its sealed answer.
`aad_cases` pins the AAD of each request target.
`ikm` derives the prover key with RFC 9180 `DeriveKeyPair`.
