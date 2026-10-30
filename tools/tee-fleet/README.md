# TEE fleet qualification

The harness connects Node, Rust and browser clients through one loopback URL:

```text
SDK → mock GK → recipient router → regional provers
```

Mock GK implements API-key authentication, CORS, header allowlists and the
[prover routes](../../prover/tee/WIRE_CONTRACT.md#recipient-routing). It strips
the outer API key while preserving the remaining query bytes authenticated by
HPKE. It never retries an upstream request. Indexer/wallet routes, billing and
rate limiting are outside the harness.

## Local tests

Requires Node 24 and the repository npm dependencies:

```sh
npm ci
npx playwright install chromium firefox webkit
npm run test:tee-fleet
ZOLANA_TEST_BROWSER=firefox node --test tools/tee-fleet/*.test.mjs
ZOLANA_TEST_BROWSER=webkit node --test tools/tee-fleet/*.test.mjs
```

`ZOLANA_CHROME_EXECUTABLE` selects an installed Chrome. CI runs all three
engines. Tests cover signed policy updates, persistent rollback protection,
IndexedDB/Web Locks, cancellation, attestation, HPKE, recipient failover and
transport faults. Synthetic Nitro certificates are injected only into the test
bundle; the shipped SDK retains AWS roots. These local fixtures generate no
ZK proofs.

## Live AWS qualification

`live.mjs` accepts a public manifest containing `network: "pri285-tee-test"`,
relative `rootFile`, `metadataUrl`, `targetsUrl`, and a `deployments` array with
`id`, `region`, `stackName` and `recipientId`. Only owned
`zolana-nitro-pri285-*` stacks in account 558215002830 are accepted. Obtain
recipient IDs from independently verified attestations, using the wire contract
linked above. Origin credentials come from the stacks' Secrets Manager outputs
and stay in memory.

```sh
npm run build:ts
cargo build -p spr-client --features tee-tuf --example tee_policy_prove
go -C prover/server build -o /absolute/tee-router ./cmd/tee-router
ZOLANA_TEE_ROUTER_BINARY=/absolute/tee-router \
ZOLANA_TEE_PROOF_VERIFIER="$PWD/target/debug/examples/tee_policy_prove" \
ZOLANA_TEE_REAL_OUTAGE=1 \
ZOLANA_TEE_CONTROL_PLANE_OUTAGE=1 \
  node tools/tee-fleet/live.mjs manifest.json /absolute/qualification-output
```

Use a fresh output directory for each run and browser engine. On macOS, run
`caffeinate -i node ...` to keep the qualification host awake through the real
freshness deadlines. Without `ZOLANA_TEE_ROUTER_BINARY`, the driver uses the
in-process recipient router instead of the Go service.

The managed run starts two independent Go routers behind round-robin mock GK.
It publishes identical, conditional revisions to three private S3 mirrors and
waits for both routers to converge. A temporary IAM role grants access only to
that run's registry objects and regional origin secrets. The operator identity
owns publication and fault injection; router processes receive read-only
credentials. Cleanup removes the temporary role.

Node, Rust and the selected browser load the signed CDN policy, verify AWS
attestations, and generate encrypted proofs in every region. All proof exports
are checked against the committed on-chain Groth16 verifying key. The driver
also verifies cached-recipient failover, including a Rust stdin barrier between
attestation and the first encrypted request.

- `ZOLANA_TEE_REAL_OUTAGE=1` stops and restarts `zolana-enclave@0.service` on
  the owned test instance through SSM. Both routers must observe health loss
  with the registry entry still enabled. Restoration checks the sealed key is
  unchanged and verifies another proof. Cleanup restores any stopped service.
- `ZOLANA_TEE_CONTROL_PLANE_OUTAGE=1` blocks US S3 and Secrets Manager
  connections through a loopback CONNECT proxy that preserves TLS. It waits
  past the actual five-minute credential lifetime, checks fresh mirror reads,
  cold-starts a router during the fault, and proves through the remaining
  regions without stale-recipient forwarding. It then restores access.

Reports contain proofs, public quotes/nonces, registry versions, role policies
and observations. They contain no credentials. The control-plane fault simulates
regional API connection loss, not a complete AWS-region outage. Production trust
custody, deployment and real GK integration require separate qualification.

## Policy renewal, revocation and expiry

Add `--lifecycle` to keep clients open after the initial qualification. After
`ready`, publish a higher signed policy through the infra publisher and send a
command on stdin (IDs must exist in the manifest):

```json
{"action":"policy","revision":2,"available":["eu-north-1","us-east-1","ap-southeast-1"],"retired":"ap-southeast-1"}
```

The retired generation stays routable for cached ciphertext but is excluded
from new attestations. Remove it from the signed policy. The harness waits for
the new revision, proves with all clients and checks that no request reaches
the retired recipient.

After the actual signed metadata expires, send `{"action":"expiry"}`. With
the CDN still serving the expired metadata, all clients must reject before
forwarding. Publish renewed metadata and send another `policy` command to
verify recovery. `{"action":"finish"}` closes the clients and services.

## Interactive mock gateway

`serve.mjs` accepts a JSON file with `port`, `allowedOrigins` and `deployments`.
Each deployment supplies `id`, `region`, HTTPS `origin` and `recipientId`.

```sh
ZOLANA_MOCK_API_KEY=local-test-key node tools/tee-fleet/serve.mjs config.json
```

Use `http://127.0.0.1:3301/v1/zolana?api-key=local-test-key` (or the configured
port) with a reviewed SDK policy. Never use a production API key. In tests,
`gateway.faults.dropRequest`/`dropResponse` remove headers, and
`router.setAvailable`/`setDraining` control generation selection. These controls
are JavaScript methods, not public HTTP routes.
