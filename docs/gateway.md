# Serving Zolana behind a gateway

A gateway in front of the prover, Photon and ring RPC authenticates callers,
routes each request by its path and bills it by the answer. The services keep
everything else: they check a request, run or refuse it, and report what it
cost. [`gateway.json`](gateway.json) lists the routes and the headers a gateway
forwards. `sdk-libs/ts/test/reference-gateway.ts` implements this page, and the
live TypeScript suite reaches every service through it.

## Routes

A route forwards to its origin with the path unchanged. The prover binds the
path into an encrypted request's authentication, and Photon and ring RPC run
only the method the path's last segment names, so a rewritten path fails to
decrypt or loses its method check. `{key}` is a proving key name and `{method}`
a JSON-RPC method; a gateway may list the methods it prices instead. There is no
`/prove/{key}/indexed` route: a client behind a gateway sends the proof data
itself.

## Credentials

The caller sends its key as the `api-key` query parameter. A query pair is a
credential when its name, decoded as `application/x-www-form-urlencoded`, is
`api-key`, so `api%2Dkey=...` is one too. The gateway removes every credential
pair and forwards every other pair byte for byte and in order. The origin then
authenticates the target the client encrypted to: for each `aad_cases` entry in
[`prover/tee/testdata/vectors.json`](../prover/tee/testdata/vectors.json), the
target the origin receives has that entry's `aad`.

## Headers and bodies

A gateway forwards bodies unchanged and only the headers `gateway.json` lists,
in each direction. An encrypted proof and its answer are octet-stream bodies
under the `Zolana-Tee` headers.

## Billing

A 2xx answer bills its route's price times its `X-Helius-Metering-Units`, a
positive integer, or one unit when the origin sends none. The prover reports a
proof's tier ([`TRANSFER_SERVICE.md`](../prover/server/TRANSFER_SERVICE.md)),
and ring RPC reports a `ringDeposits` page by the signatures it examines. Any
other status bills nothing: Photon and ring RPC answer 400 before a call runs
when the path and the body name different methods, or when the body is not one
JSON-RPC call.

A gateway does not retry a POST. A 5xx or lost answer does not prove that the
origin did no work: a proof may have run, and a signed ring call may have used
its nonce. The gateway returns the failure, `Retry-After` included, and the
caller decides.
