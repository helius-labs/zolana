# Mock GK for TEE fleet tests

One loopback URL exposes the prover routes used by the TEE SDK:

```text
Browser / Node / Rust SDK
    → mock GK (API key, CORS, header allowlists)
    → recipient router (attestation selection, key ID routing)
    → independent regional prover generations
```

The stand-in serves `GET /v1/zolana/tee/v1/attestation`, `GET
/v1/zolana/proving-keys`, the health probe, `POST /v1/zolana/prove/{key}`,
`POST /v1/zolana/prove/{key}/indexed` and `GET
/v1/zolana/prove/{key}/status`. Everything else is refused. Indexer and private
wallet routes, GK billing, rate limiting and actual deployment configuration
are outside this harness.

It removes the single outer `api-key` query pair, preserves remaining query
bytes and the full gateway path, and forwards only explicitly allowed headers.
It does not follow redirects or retry upstream requests. Each encrypted
request must name an available recipient with `Zolana-Tee-Key-Id`; an unknown
key fails before the body is forwarded. No component here possesses a real
enclave key or decides which PCRs the SDK should trust.

## Run the tests

Requires Node 24 and the repository npm dependencies:

```sh
npm ci
npx playwright install chromium firefox webkit
npm run test:tee-fleet
```

To use an installed Chrome instead, set `ZOLANA_CHROME_EXECUTABLE` to its binary
path. Set `ZOLANA_TEST_BROWSER=firefox` or `webkit` to select another engine.
CI runs both suites with all three engines. The test launches a headless browser and closes its servers, browser and
temporary bundle directory in `finally`.

Tests exercise independent key pairs, quote verification, cached recipients,
POST bodies, encrypted GET headers, preserved query bytes, credential removal,
key loss, CORS preflights, unknown recipients, dropped protocol headers and
nonce mismatch. The browser scenario resolves an ephemeral signed TUF fleet
policy before attestation and exercises recipient failover. A separate policy
suite runs shared Rust/Node signed-repository vectors, reload/rollback, expiry,
root rotation, corrupt storage, cross-tab locking and cancellation against
real IndexedDB and Web Locks. The test bundle replaces the Nitro trust anchor with a freshly
generated synthetic CA; it still executes the SDK's signature, certificate,
nonce, measurement, policy and HPKE checks. The normal SDK artifact retains
the AWS root and has no test-root option. This qualifies the local transport
only: these processes are not AWS Nitro enclaves or three physical regions,
and the fixture responses do not generate or verify a ZK proof.

## Run against isolated test provers

Create a local configuration using the public keys from independently verified
attestations. Derive each `recipientId` according to
[the wire contract](../../prover/tee/WIRE_CONTRACT.md#recipient-routing).

```json
{
  "port": 3301,
  "allowedOrigins": ["http://localhost:5173"],
  "deployments": [
    {
      "id": "eu-test-1",
      "region": "eu-north-1",
      "origin": "https://test-prover.example",
      "recipientId": "<64 lowercase hex characters>"
    }
  ]
}
```

Add one entry for each independent recipient, then:

```sh
ZOLANA_MOCK_API_KEY=local-test-key node tools/tee-fleet/serve.mjs config.json
```

Configure the SDK with `http://127.0.0.1:3301/v1/zolana?api-key=local-test-key`
and its normal reviewed TEE policy/source. The mock binds only loopback;
configuration contains public identifiers and fixed origins. Do not use a
production API key. The CLI logs neither the key nor request contents.

Fault controls are JavaScript objects returned to the test runner, never
public HTTP endpoints. `gateway.faults.dropRequest` and `dropResponse` drop a
named header; `router.setAvailable(id, false)` removes a generation from both
attestation selection and ciphertext routing. The harness has no active health
discovery or shared routing state; a production router still needs those.

Real GK qualification must check the deployed route map, request allowlist
(including the new `Zolana-Tee-Key-Id`), response marker forwarding, browser
CORS, origin authentication and retry behavior. Passing this suite does not
establish real GK compatibility.
