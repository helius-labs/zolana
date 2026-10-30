# Recipient router

This service sits behind GK's authentication, CORS, rate limits and billing.
It forwards the existing `/v1/zolana` prover routes without decrypting proof
inputs. Clients still verify the independently signed fleet policy and vendor
attestation; the routing registry cannot approve a prover key.

Each process reads the same private, versioned registry through its IAM role.
Up to three regions may hold byte-identical copies under the same object key.
Reads run independently with three-second deadlines. The highest valid reachable
revision wins; conflicting bytes at that revision reject the reload. A running
router never downgrades to an older mirror or renews freshness with a rollback.
Reloads are atomic and reject duplicate/unknown JSON members and invalid destinations.
After a restart the highest valid reachable copy is authoritative; there is no
local durable rollback floor or cross-region consensus. Use conditional publication,
version history and restricted operator access. A failed reload cannot renew the previous map's
one-minute freshness budget. Registry expiry closes admission too.

Regional origin credentials load independently with three-second deadlines.
An unavailable secret makes its endpoint ineligible rather than rejecting the
complete inventory. An unchanged endpoint may use its cached credential for
at most five minutes after the last successful read. Failure never renews that
age; a changed origin, secret ARN or recipient never receives a cached value.
Expired or unresolved credentials are used for neither health probes nor
forwarding. Other regions continue with fresh inventory and credentials.

Each replica checks readiness and the observed recipient public key every
five seconds. These observations expire after twenty seconds and do not replace
the client's vendor verification. A slow registry read does not stop health
checks. New attestations prefer healthy generations in the process's configured
region. Ciphertext routes only to healthy endpoints registered for its exact
`Zolana-Tee-Key-Id`, regardless of connection or router replica changes.

Freshness uses wall-clock observation timestamps so suspension counts against
both budgets; backward clock movement rejects admission until a new valid
observation. Go's elapsed-time clock can pause during host sleep.

`draining` excludes a generation from new attestations while keeping its
ciphertext route. `disabled` removes it from both paths without losing the
operator's inventory. An unavailable key gets pre-forward
`503 tee_generation_unavailable`. An origin failure after admission gets
`502 tee_upstream_unavailable`; proof submissions are never replayed. Router
overload has a separate bounded-admission error and does not request re-keying.
Plaintext origin successes on encrypted routes are refused.
An unmarked origin `503` also becomes `502 tee_upstream_unavailable`, so an
already forwarded request cannot impersonate pre-forward recipient loss.
Protocol-marked origin errors retain their status and opaque body.

## Run

Build with `go build ./cmd/tee-router` from `prover/server`, or build
`Dockerfile.router`. Its pinned image is a non-root static binary with dependency
licenses, no shell and no enclave secrets.

```sh
# Inject a distinct GK-to-router credential through the deployment's secret
# mechanism; never pass it in command-line arguments or the public API URL.
export ZOLANA_ROUTER_ORIGIN_KEY='<operator-injected credential>'
./tee-router \
  --registry-bucket '<private registry bucket>' \
  --registry-key registry.json \
  --registry-region us-east-1 \
  --registry-mirror eu-north-1/'<EU registry bucket>' \
  --registry-mirror ap-southeast-1/'<AP registry bucket>' \
  --registry-owner '<12-digit account ID>' \
  --preferred-region eu-north-1
```

Both listeners default to loopback. Explicitly bind the gateway listener when
running behind a private load balancer and restrict network ingress to that
gateway. The separate admin listener serves `/ready` and `/status`; do not expose
it through the public route map. Status includes only operator IDs, freshness,
health/drain/credential readiness, selected registry region/object version and
counters. It contains no API keys, raw AWS failures,
request bodies or query strings. SIGTERM stops admission and permits admitted
requests to finish within the configured ten-minute request budget.

The runtime role needs only `s3:GetObject` for the exact object in each mirror and
`secretsmanager:GetSecretValue` for its approved origin credential ARNs. S3
requests bind the expected bucket owner; origin secrets must belong to the same
account and their generation's region. No KMS seed/key, signing, S3 write or SSM
permission belongs to this runtime role. The test driver uses a separate operator identity for fault injection.

## Registry and rollout

```json
{
  "schema_version": 1,
  "revision": 1,
  "expires_at": 1800000000,
  "generations": [{
    "id": "eu-generation-1",
    "region": "eu-north-1",
    "recipient_id": "<SHA-256 recipient ID, 64 lowercase hex characters>",
    "draining": false,
    "disabled": false,
    "backends": [{
      "id": "eu-prover-1",
      "origin": "https://<regional-origin-host>",
      "api_key_arn": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:regional-origin"
    }]
  }]
}
```

The three-region fleet uses independently sealed recipient keys. Replicas
within one generation may share a key; register each distinct HTTPS origin
under that generation. Loopback HTTP is supported for hermetic tests. URLs
with credentials, paths, queries or fragments are rejected. A configured
origin never comes from a caller's request.

Publishing this registry is privileged deployment authority because it selects
credential destinations. Restrict it to reviewed operators with that authority;
it is separate from TUF policy approval. Prepare the complete new map, increase
its revision and use `If-Match` with the previous S3 ETag (`If-None-Match: *` for
bootstrap). Preserve object versions. Never restore an old revision in place:
publish the reviewed recovery configuration under a higher revision.

Write identical bytes to every mirror and verify convergence before selecting
new generations or publishing their client approvals. Cross-region publication
is not atomic: a partial publication must be repaired under the same bytes or a
higher reviewed revision. A stale mirror cannot override a newer running floor;
if no sufficiently new copy is reachable, that router closes admission. Preserve
old generation routes throughout staged rollout. Mirror availability does not
establish availability of the separate public signed-policy CDN or IAM control
plane; qualify those dependencies separately before a full-region rollout.

Register and qualify a new generation before selecting it. Keep the old
generation's exact-key routes while it drains, then disable it after admitted
work completes. Signer policy revocation and routing retirement are separate
operations. Static-pin clients need compatible initial attestation selection
or a retained regional endpoint until their announced retirement; retaining a
ciphertext route alone does not provide that compatibility.

`go test -race ./router ./cmd/tee-router ./tee` covers routing, atomic registry
changes, ingress/origin credentials, draining, health/key mismatch, stale state,
no replay, admission bounds and signed/bounded AWS reads. The [live harness](../../../tools/tee-fleet/README.md) qualifies S3 convergence,
regional outages and encrypted AWS proofs through mock GK.
