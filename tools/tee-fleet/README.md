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
attestation selection and ciphertext routing. This in-process router uses
operator fault controls. The shared Go router is qualified separately below.

Real GK qualification must check the deployed route map, request allowlist
(including the new `Zolana-Tee-Key-Id`), response marker forwarding, browser
CORS, origin authentication and retry behavior. Passing this suite does not
establish real GK compatibility.

## Qualify the owned AWS test fleet

`live.mjs` accepts a public manifest with `network: "pri285-tee-test"`, a
relative `rootFile`, static `metadataUrl`/`targetsUrl`, and deployment entries
containing `id`, `region`, `stackName` and the independently verified
`recipientId`. It only accepts the operator-owned `zolana-nitro-pri285-*`
stacks in account 558215002830. Regional origin credentials are read from each
stack's exact Secrets Manager output and retained in process memory. They are
not placed in the manifest, browser configuration, reports or command line.

```sh
npm run build:ts
cargo build -p spr-client --features tee-tuf --example tee_policy_prove
ZOLANA_TEE_PROOF_VERIFIER="$PWD/target/debug/examples/tee_policy_prove" \
  node tools/tee-fleet/live.mjs manifest.json /absolute/qualification-output
```

The normal SDK artifact and AWS trust root are used. Node, native Rust and the
selected real browser load the actual signed CDN policy, attest and generate
an encrypted proof through one mock-GK URL for each region. Every proof is
verified against the committed on-chain Groth16 key. Generation removal tests
cached-recipient failover in all three clients, including a native Rust stdin
barrier between attestation and the first encrypted request. Public proof
exports and a qualification report are written to the output directory.

For persistent-client checks, add `--lifecycle`. After the `ready` line,
publish a higher signed policy and send an operator command on stdin:

```json
{"action":"policy","revision":2,"available":["us-east-1","ap-southeast-1"],"retired":"ap-southeast-1"}
```

The manifest must already contain every backend needed for the exercise.
The harness waits for the approved revision before proving and checks that
the retired generation receives no request. Once the actual signed metadata
has expired, send `{"action":"expiry"}`; Node, browser and a restarted native
Rust client must fail before forwarding any request. No test clock is used.
Publish renewed higher metadata and use another `policy` command to verify
recovery. Send `{"action":"finish"}` to close the browser and servers.
Control commands are available only on the operator's stdin, never as HTTP
routes. Publication still uses the separate reviewed conditional publisher.

`router.setDraining(id, true)` excludes a generation from new attestation
selection while retaining its ciphertext route. A lifecycle command's
`retired` entry is drained automatically. Keeping it in `available` proves
policy revocation rather than outage recovery: stale ciphertext could still
be served, and the test asserts that none is forwarded there. Successful
qualification also archives the public nonce, capture time and complete AWS
evidence beside each region's verified proof.

## Qualify shared routing and physical outages

Build the Go router and set `ZOLANA_TEE_ROUTER_BINARY` to its absolute path to
run two independent router processes behind round-robin mock GK. Both read one
private versioned object in the isolated test routing bucket provisioned by
`zolana-infra/infra/routing-registry`. The driver publishes complete revisions
conditionally and waits for both processes to observe them. Origin credentials
are resolved inside the Go processes. The driver archives per-replica
convergence observations, counters and the public routing configuration.

```sh
go -C prover/server build -o /absolute/tee-router ./cmd/tee-router
ZOLANA_TEE_ROUTER_BINARY=/absolute/tee-router \
ZOLANA_TEE_PROOF_VERIFIER="$PWD/target/debug/examples/tee_policy_prove" \
ZOLANA_TEE_REAL_OUTAGE=1 \
  node tools/tee-fleet/live.mjs manifest.json /absolute/qualification-output
```

`ZOLANA_TEE_REAL_OUTAGE=1` requires the separate operator identity's SSM access.
It stops and starts only `zolana-enclave@0.service` on the owned test stack's
instance. Both routers must observe health loss while its registry entry
remains enabled; Node, Rust and browser clients must recover without forwarding
to that unavailable recipient. The driver restores the service, checks its
sealed recipient key is unchanged, and verifies another proof. Cleanup restores
any stopped service. Production runtime identities must not receive SSM access.

Keep the qualification host awake. On macOS, wrap the Node invocation with
`caffeinate -i node tools/tee-fleet/live.mjs ...`; its assertion ends with that
command and changes no system sleep settings. Idle sleep suspends both routers
and the driver, invalidating wall-clock convergence deadlines. Preserve a
failed trace and correlate it with host sleep/wake events before attributing
such a timeout to S3 or routing. Choose an output directory per run and engine.
