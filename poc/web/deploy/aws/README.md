# AWS browser demo

`template.yaml` creates a private S3 bucket and an HTTPS CloudFront distribution
with COOP/COEP headers on the document, worker scripts and runtime assets. It
also preserves the demo's existing same-origin devnet API proxies. No backend
service or Solana program is deployed by these scripts.

Build Mopro's `feat/gnark-web-arkworks` with the experimental accelerator enabled,
then provide the generated bindings, this checkout's pinned proving keys and a
captured **local test** transfer request. The staging script checks key hashes
and requires the transfer 2x3 key. Supply all transfer and merge keys to enable
the optional key benchmark. The request will be publicly downloadable; use the
synthetic localnet fixture, never a real user's transfer request.

Install the workspace dependencies with `npm ci` first. Node, Go, AWS CLI and an
AWS profile with CloudFormation/S3/CloudFront access are required.

```sh
# Run from the repository root. Set a new release ID for each deployment.
export AWS_PROFILE=dev AWS_REGION=eu-north-1
export MOPRO_REVISION=af2a243311f7d3fd85f46a2f235b7eff6f2ce4ef
release=arkworks-20260911-1
poc/web/deploy/aws/build.sh "$release" \
  /path/to/MoproWasmBindings /path/to/keys /path/to/local-test-transfer-2x3.json
# Check the generated production app before publishing.
poc/web/deploy/aws/deploy.sh "$release"
```

The default stack is `zolana-mopro-arkworks-demo` in `eu-north-1`; override with
`ZOLANA_DEMO_STACK` and `AWS_REGION`. The stack outputs its URL, bucket and
distribution ID. `build-info.json` inside each release records the source
revision, supplied Mopro revision and runtime/fixture hashes.

All assets live under `/releases/RELEASE_ID/` with immutable caching. The root
`index.html` is published last and revalidated; open tabs keep their original
runtime files. A deployment refuses to overwrite an existing release prefix.
If an upload fails, retry with a new release ID. Invalidation completion can be
checked using the ID returned by the deployment script.

For a rollback, copy a previous release's `index.html` to the bucket root with
`Cache-Control: no-cache,max-age=0,must-revalidate`, then invalidate `/` and
`/index.html`. Keep old release directories while users may have tabs open.
The bucket is retained if the CloudFormation stack is deleted.

Validation should generate and verify a sample proof in automatic and custom
thread modes, compare the Go fallback, reject an invalid witness and recover.
The browser must report `crossOriginIsolated === true` and load the recorded
Arkworks Wasm hash. Full devnet transfers are separate from this local proof
playground and depend on the deployed backend/program versions.
