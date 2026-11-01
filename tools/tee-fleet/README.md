# TEE fleet qualification

Production recipient routing lives in Gatekeeper/Heimdall. The full local
integration runs real authentication, routing and health components with either
synthetic provers or the isolated live AWS fleet. The smaller mock and REST-only
harness remain available for focused SDK tests.

```text
SDK → test authentication/CORS proxy → Heimdall → regional provers
```

The outer test proxy strips the caller API key while preserving the remaining
query bytes authenticated by HPKE. It never retries an upstream request.
Heimdall selects the recipient and attaches its configured origin credential.
This older REST-only harness bypasses authentication, billing, rate limits,
Config Service delivery and the health controller. The full integration below
adds the real local auth and health components; neither harness is a GK deployment.

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

Prover images must serve `/attestation` (or `/v1/zolana/attestation` behind the
gateway). Rebuilt enclave images need reviewed measurements in the test policy
before qualification; the SDK does not try alternate attestation routes.

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
# In the companion monorepo checkout, from rust-services/gatekeeper:
# cargo build -p heimdall-proxy --features compat-harness --example tee_routing_harness
ZOLANA_TEE_GK_BINARY=/absolute/tee_routing_harness \
ZOLANA_TEE_PROOF_VERIFIER="$PWD/target/debug/examples/tee_policy_prove" \
  node tools/tee-fleet/live.mjs manifest.json /absolute/qualification-output
```

Use a fresh output directory for every run and browser engine. `live.mjs`
requires the real Heimdall binary. Credentials are read from the owned stacks
and passed over stdin, never command arguments or public artifacts. Loopback
observation proxies count forwarding but do not select recipients or retry.

Node, Rust and the selected browser load the signed CDN policy, verify AWS
attestations, and generate encrypted proofs in every region. Every proof is
checked against the committed on-chain Groth16 verifying key. Cached-recipient
failover includes a Rust stdin barrier between attestation and submission.
Availability changes update Heimdall's actual disabled-origin flags. This does
not qualify production health detection or control-plane outages; those need
a deployed GK test environment. The old standalone router's historical outage
evidence remains tied to its original commit.

For local SDK/browser coverage through the real frontend, run:

```sh
ZOLANA_TEE_GK_BINARY=/absolute/tee_routing_harness npm run test:tee-fleet
```

`gk.test.mjs` covers approved-key selection with all three origins live,
credential forwarding, cached requests while draining, failover and browser
CORS. It skips when the optional binary is absent. Other tests use the small
in-process mock and retain policy lifecycle, cancellation and transport fault
coverage. Synthetic attestations never qualify AWS roots or produce ZK proofs.

## Policy renewal, revocation and expiry

Add `--lifecycle` to keep clients open after the initial qualification. After
`ready`, publish a higher signed policy through the infra publisher and send a
command on stdin (IDs must exist in the manifest):

```json
{
  "action": "policy",
  "revision": 2,
  "available": ["eu-north-1", "us-east-1", "ap-southeast-1"],
  "retired": "ap-southeast-1"
}
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

## Combined auth and health integration

The monorepo `tee_integration` test can launch `gk-sdk-driver.mjs` with
`GK_SDK_TEST_DRIVER` set to its absolute path. The test supplies its authenticated
loopback URL and synthetic caller key; the driver supplies three IPv6 loopback
provers. Readiness failures go through the real checker, supervisor and admin
handler. Neither side writes disabled-origin flags for this SDK phase.

`run-gk.mjs /absolute/test-bundle /absolute/sdk-proof-tools` runs that test from a source/hash-checked bundle.
Build the SDK/CPU-prover tools using `python3 tools/tee-fleet/build-sdk-test.py /absolute/sdk-proof-tools`
(the output directory must be new). Build the GK bundle in a clean monorepo checkout with
`python3 scripts/build-tee-test-bundle.py /absolute/new-bundle` from
`rust-services/gatekeeper`, then review and pin that exact commit in
`gk-revision.txt`. The manifest detects accidental source/binary mismatches; obtain
bundles only from the reviewed checkout or its trusted CI build, not an
untrusted download. See [the CI guide](../../.github/CI.md#combined-sdk--gatekeeper-qualification)
for all three browser commands and coverage limits.

## Live AWS through local GK auth and health

Build the pinned GK bundle as above and the native verifier:

```sh
cargo build -p spr-client --features tee-tuf --example tee_policy_prove --locked
ZOLANA_TEE_PROOF_VERIFIER="$PWD/target/debug/examples/tee_policy_prove" \
  node tools/tee-fleet/run-gk.mjs /absolute/gk-test-bundle --live \
  /absolute/reviewed-test-manifest.json /absolute/new-output-directory
```

Repeat with `ZOLANA_TEST_BROWSER=firefox` and `webkit`, using new output directories.
This opt-in command reads credentials only from the owned test stacks. It never
publishes metadata, changes AWS resources or deploys GK. Renew expired test policy
separately with the reviewed publisher before running it.

Three authenticated loopback bridges forward ciphertext to the actual regional
provers. They translate the neutral fixture route prefix to the deployed prover
prefix and hold regional credentials only in memory. They preserve the encrypted
route/query contract and cannot decrypt payloads. `/ready` is forwarded to the
actual origins; injected local readiness failures go through GK's real checker,
supervisor and admin handler. No disabled flags are set by the driver.

The test verifies Node/Rust/browser proofs in every region, cached-recipient
failover, all-down refusal and recovery, draining, metering and no POST replay
when a bridge discards a completed upstream response. It exports public proofs,
quotes and a qualification report. Losing an encrypted response does not reveal
whether its plaintext contained a proof or a prover error.

For policy lifecycle tests in this mode, set `ZOLANA_TEE_LIFECYCLE_INPUT` to a
local FIFO carrying the same commands documented above. Keep its writer open
through the test; stdin is reserved for GK's controller. Progress is on stderr.
Clients retain their policy caches while higher revisions are published,
revocations are tested, signed metadata expires, and renewed metadata is served.

Deployment permissions, actual Config Service distribution, public edge/TLS,
distributed rate-limit convergence and downstream billing delivery remain
outside this local integration. Production signing custody is also separate.
