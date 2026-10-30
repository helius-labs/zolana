# Recipient router

This service sits behind GK's authentication, CORS, rate limits and billing.
It forwards the existing `/v1/zolana` prover routes without decrypting proof
inputs. Clients still verify the independently signed fleet policy and vendor
attestation; the routing registry cannot approve a prover key.

Each process reads the same private, versioned S3 object through its IAM role.
Registry reloads are atomic and reject older revisions, changed bytes under
the same revision, duplicate/unknown JSON members and invalid destinations.
After a restart S3's current object is authoritative; there is no claim of a
local durable rollback floor. Use conditional publication, version history and
restricted operator access. A failed reload cannot renew the previous map's
one-minute freshness budget. Registry expiry closes admission too.

Each replica checks readiness and the observed recipient public key every
five seconds. These observations expire after twenty seconds and do not replace
the client's vendor verification. A slow registry read does not stop health
checks. New attestations prefer healthy generations in the process's configured
region. Ciphertext routes only to healthy endpoints registered for its exact
`Zolana-Tee-Key-Id`, regardless of connection or router replica changes.

`draining` excludes a generation from new attestations while keeping its
ciphertext route. `disabled` removes it from both paths without losing the
operator's inventory. An unavailable key gets pre-forward
`503 tee_generation_unavailable`. An origin failure after admission gets
`502 tee_upstream_unavailable`; proof submissions are never replayed. Router
overload has a separate bounded-admission error and does not request re-keying.
Plaintext origin successes on encrypted routes are refused.

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
  --registry-owner '<12-digit account ID>' \
  --preferred-region eu-north-1
```

Both listeners default to loopback. Explicitly bind the gateway listener when
running behind a private load balancer and restrict network ingress to that
gateway. The separate admin listener serves `/ready` and `/status`; do not expose
it through the public route map. Status includes only operator IDs, freshness,
health/drain state and counters. It contains no API keys, raw AWS failures,
request bodies or query strings. SIGTERM stops admission and permits admitted
requests to finish within the configured ten-minute request budget.

The runtime role needs only `s3:GetObject` for the exact registry object and
`secretsmanager:GetSecretValue` for its approved origin credential ARNs. S3
requests bind the expected bucket owner; origin secrets must belong to the same
account and their generation's region. No KMS seed/key, signing, S3 write or SSM
permission belongs to this runtime role. The qualified test driver uses its
separate operator identity for fault injection.

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

Register and qualify a new generation before selecting it. Keep the old
generation's exact-key routes while it drains, then disable it after admitted
work completes. Signer policy revocation and routing retirement are separate
operations. Static-pin clients need compatible initial attestation selection
or a retained regional endpoint until their announced retirement; retaining a
ciphertext route alone does not provide that compatibility.

`go test -race ./router ./cmd/tee-router ./tee` covers routing, atomic registry
changes, ingress/origin credentials, draining, health/key mismatch, stale state,
no replay, admission bounds and signed/bounded AWS reads. The operator live
harness in `tools/tee-fleet` separately qualifies actual S3 convergence across
two processes and real encrypted AWS proofs through mock GK. Production
deployment, production trust custody and real GK configuration remain explicit
release gates.
