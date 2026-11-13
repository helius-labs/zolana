# CI

Current behavior in this branch. Links contain the exact path filters and command arguments. PR filters consider the whole PR; changes to shared Cargo files can select broader checks.

Changes under `programs/` run every validation workflow.

Most validation jobs skip draft PRs. TypeScript and deployment-script checks also run on drafts.

1. [Protocol operations](workflows/protocol-ops.yml)

    **Triggered by:** PR/main changes to:

    1. `programs/`.
    2. `protocol-ops/`.
    3. `program-libs/`.
    4. `prover/server/`.
    5. `services/photon/`.
    6. Shared Cargo, toolchain, or CI setup files.

    **Runs:**

    1. Rust formatting: `cargo fmt`.
    2. Rust linting: `cargo clippy`.
    3. Go bridge: `go test ./...`.
    4. Remote-only build: `cargo check --no-default-features`.
    5. `forester`: `cargo test`.
    6. `spr-forester-prover`: `cargo test`.
    7. `spr-protocol-cli`: `cargo test`.
    8. `spr-protocol-instructions`: `cargo test`.
    9. `spr-smart-account-client`: `cargo test`.
    10. `spr-merkle-tree`: `cargo test`.
    11. Dependency boundaries: `just check-deps`.
    12. `spr-cli` consumer: `cargo check`.
    13. `spr-client` consumer: `cargo check`.
    14. `spr-program-test` consumer: `cargo check`.
    15. `spr-test-utils` consumer: `cargo check`.
    16. `shielded-pool-tests` consumer: `cargo check`.
    17. `spp-test-validator` consumer: `cargo check`.
    18. `ring-test-program` consumer: `cargo check`.
    19. `tree-bench` consumer: `cargo check`.
    20. `client-example` consumer: `cargo check`.
    21. `dynamic-swap-test` consumer: `cargo check`.
    22. `rfq-test` consumer: `cargo check`.
    23. `swap-test-validator` consumer: `cargo check`.
    24. `xtask` consumer: `cargo check`.
    25. `spr-tree`: `just test-tree`.
    26. Batch prover binary: `just build-prover-server`.
    27. Pinned 40×10 key: `target/prover-server download`.
    28. `spr-forester-prover` local 40×10 proof: `cargo test --test local_batch_proof -- --ignored`.
    29. `spr-forester-prover` Redis 40×10 proof: `cargo test --no-default-features --test remote_batch_proof -- --ignored`.

2. [Rust workspace](workflows/rust.yml)

    **Triggered by:** PR/main changes outside these ignored paths; `programs/**` and `docs/spec.md` (whose instruction tags `spr-event` tests against the code) override the exclusions:

    1. `protocol-ops/**`.
    2. `.github/workflows/protocol-ops.yml`.
    3. `prover/server/**`.
    4. `**/*.md`.
    5. `LICENSE*`.
    6. `.gitignore`.
    7. `sdk-libs/ts/**`.
    8. `sdk-tests/client/typescript/**`.
    9. `package.json`.
    10. `package-lock.json`.

    **Runs:**

    1. Rust formatting: `cargo fmt`.
    2. Test hygiene: `tools/check-test-hygiene.sh`.
    3. Unused dependencies: `cargo machete`.
    4. Rust linting: `just clippy`.
    5. Workspace compilation: `just check-all`.
    6. `spr-cli`: `cargo nextest run`.
    7. `xtask`: `cargo nextest run`.
    8. `spr-event` (spec instruction tags): `cargo nextest run`.
    9. `spr-interface`: `cargo nextest run`.
    10. `spr-instruction`: `cargo nextest run`.
    11. `spr-protocol-instructions`: `cargo nextest run`.
    12. `shielded-pool-program`: `cargo nextest run`.
    13. `shielded-pool-tests`: `cargo nextest run`.
    14. `spr-user-registry`: `cargo nextest run`.
    15. `user-registry-tests`: `cargo nextest run`.
    16. `swap-program`: `cargo nextest run`.
    17. `spr-program-test`: `cargo nextest run`.
    18. `spr-program`: `cargo nextest run`, `cargo test`.
    19. `spr-keypair`: `cargo nextest run`, `cargo test --doc`.
    20. `spr-event-parser`: `cargo nextest run`.
    21. `spr-transaction`: `cargo nextest run`.
    22. `spr-client`: `cargo nextest run`, `cargo test --doc`.
    23. `spr-test-utils`: `cargo nextest run`.
    24. `spr-rpc-http`: `cargo nextest run`.
    25. `spr-gnark-ffi-prover`: `cargo nextest run`.
    26. `swap-prover`: `cargo nextest run`.
    27. `dynamic-swap-program` and `dynamic-swap-sdk`: `cargo test --release`.
    28. `sdk-libs/gnark-sdk`: `go test`.
    29. `spr-zk-standalone-fixture`: `cargo test`.
    30. `spr-macros`: `cargo test`.
    31. `timelock-escrow-program`: `cargo test`.
    32. `zk-tests`: `cargo nextest run`.
    33. Wasm compilation: `just check-wasm`.
    34. Photon binary: `cargo build`.
    35. SBF test programs: `just build-test-programs`, explicitly enabling `confidential-eddsa`.
    36. Localnet tools: `just build-localnet-tools`.
    37. Localnet test archives: `just build-localnet-archives`.
    38. Localnet e2e: `just test-localnet-e2e-photon`.
    39. SPP lifecycle/decode: `just test-spp-validator-lifecycle-decode`.
    40. SPP merge: `just test-spp-validator-merge`.
    41. SPP randomized: `just test-spp-validator-randomized`.
    42. SPP proof CU: `just test-spp-validator-proof-cu`.
    43. Ring lifecycle: `just test-ring-validator`.
    44. Maximum transaction shapes: `just test-max-shapes-validator`.
    45. Swap and escrow: `just test-swap-and-escrow-validator`.
    46. Dynamic swap: `just test-dynamic-swap`.
    47. Compression: `just test-compression-validator`.
    48. RFQ settlement: `just test-rfq-validator`.
    49. Coverage: `just coverage`.

    `just test-spr-program-release` generates native escrow and dynamic-swap
    proving keys, checks the committed verifier modules, and runs their Rust
    circuit tests. It also runs the dynamic-swap SDK's checked-key loading smoke
    test. The localnet tools job uploads dynamic-swap `.pk` files and checksum
    sidecars as `dynamic-swap-zk-keys-${{ github.sha }}`; lifecycle jobs download
    them to `target/zk/dynamic-swap-program`.

    `just test-feature-gate` checks the feature-gate crate and shielded-pool
    admission with `confidential-eddsa` disabled and explicitly enabled, plus
    the protocol CLI's binary inspection. It is part of `test-hermetic`.
    Production `just build-programs` keeps the feature disabled by default.

3. [TypeScript](workflows/typescript.yml)

    **Triggered by:**

    1. PR/main changes, except changes limited to `protocol-ops/` and its workflow file.

    **Runs:**

    1. `@heliuslabs/spr`: `npm run check:ts`.
    2. API documentation: `npm run docs:ts`.
    3. Package smoke test: `npm pack`, `tsc`, `node`.
    4. `@heliuslabs/spr` under Bun 1.4.4: `npx bun@1.4.4 --bun x vitest run --exclude "test/e2e/**"`.
    5. SDK e2e: `just test-ts-e2e`.
    6. Escrow e2e: `just test-escrow-ts`.
    7. `spr-program-wasm-test-program`: `cargo test`.
    8. `sdk-libs/program/tests/wasm`: `npm test`.
    9. `spr-zk-standalone-fixture`: `cargo test`.
    10. Standalone Wasm: `node --test`.

    The SDK e2e job requires the repository secret `HELIUS_API_KEY`. Its live
    TEE test reaches the devnet prover through the Helius gateway with that
    key and attests it against the signed devnet policy the SDK pins. It
    receives `ZOLANA_TEE_PROVER_URL` separately from `ZOLANA_PROVER_URL`,
    which the localnet runner sets to its local prover. A missing secret
    fails before builds.

4. [Photon](workflows/photon.yml)

    **Triggered by:** PR/main changes to:

    1. Photon.
    2. Program libraries.
    3. `programs/`.
    4. Ring fixtures.
    5. Selected SDK dependencies.
    6. Shared build configuration.

    **Runs:**

    1. PostgreSQL migrations: `cargo run --bin photon-migration`.
    2. OpenAPI generation: `cargo run --bin photon-openapi`.
    3. OpenAPI drift: `git diff --exit-code`.
    4. `spr-indexer-api`: `cargo test`.
    5. `photon-indexer`: `cargo test`.

    Protocol-ops changes do not select this workflow.

5. [Prover server](workflows/prover-server.yml)

    **Triggered by:** PR/main changes to:

    1. `programs/`.
    2. `prover/`.
    3. This workflow.

    **Runs:**

    1. `prover/server/circuits`: `go test`.
    2. `prover/server/prover`: `go test`.
    3. `prover/server/prover-test`: `go test`.
    4. `prover/server/server`: `go test`.
    5. `prover/server/tee`: `go test`.
    6. TEE release tests: `python3 scripts/test_release_tee.py`.

6. [Async prover](workflows/async-prover.yml)

    **Triggered by:**

    1. Every PR.
    2. Main pushes outside its ignore list.

    **Runs:**

    1. Changed-file filter: `git diff`.
    2. `spr-client` async transfer: `cargo nextest run`.

    The path gate skips the test for ops-only, TypeScript-only, and Markdown-only PRs outside `programs/`.

7. [Verifying-key smoke test](workflows/xtask-verifying-keys.yml)

    **Triggered by:** PR/main changes to:

    1. `programs/`.
    2. `xtask/`.
    3. `prover/`.
    4. Shared Rust setup.
    5. This workflow.

    **Runs:**

    1. `xtask` verifying-key smoke test: `just xtask-create-verifying-keys-smoke`.

8. [Formal verification](workflows/formal-verification.yml)

    **Triggered by:** PR/main changes to:

    1. `programs/`.
    2. `prover/server/`.
    3. This workflow.

    **Runs:**

    1. Prover binary: `go build`.
    2. Circuit extraction: `light-prover extract-circuit`.
    3. Lean definition drift: `git diff --exit-code`.
    4. Lean proofs: `lake build`.

9. [Ring compatibility](workflows/ring-compat.yml)

    **Triggered by:**

    1. PR changes to Photon or prover.
    2. PR changes to programs or SDKs.
    3. PR changes to CLI.
    4. PR changes to shared build inputs or ring CI.
    5. Main changes to `programs/`.
    6. PR/main changes to `tools/ci/custom-rings-protocol-ops.patch`.
    7. Main changes to this workflow.

    **Runs:**

    1. Protocol-ops import migration: `git apply`.
    2. Custom-ring compatibility: `just test-ring-compat`.

    Uses the pinned custom-ring fixture at `9b6a50dd` and requires the private checkout key.

10. [Deployment scripts](workflows/gpu-deploy-scripts.yml)

    **Triggered by:** PR/main changes to:

    1. `programs/`.
    2. GPU, Nitro, or image tools.
    3. Selected prover build and release inputs.
    4. `justfile`.
    5. Their workflows.

    **Runs:**

    1. Deployment shell scripts: `shellcheck`.
    2. `tools/gpu`: `python3 -m unittest discover`.
    3. `tools/nitro`: `python3 -m unittest discover`.
    4. `tools/images`: `python3 -m unittest discover`.

11. [Service images](workflows/publish-image.yml)

    **Triggered by:**

    1. PR/main changes to `programs/`.
    2. PR/main changes to Photon or image build inputs.
    3. `photon-zolana-*` tags.
    4. Manual dispatch.

    **Runs:**

    1. Photon image: `docker/build-push-action`.
    2. Photon smoke test: `tools/check-photon-image.sh`.
    3. Service publication: `uses: ./.github/workflows/publish-service-image.yml` (tags/manual only).

12. [Reusable service publisher](workflows/publish-service-image.yml)

    **Triggered by:**

    1. A workflow call selecting a service, channel, and tag.

    **Runs:**

    1. Service image: `docker/build-push-action`.
    2. Photon smoke test: `tools/check-photon-image.sh`.
    3. Prover smoke test: `docker run`.
    4. Forester smoke test: `docker run`.
    5. Image publication: `docker push`.
    6. Provenance: `actions/attest-build-provenance`.

13. [GPU images](workflows/publish-gpu.yml)

    **Triggered by:**

    1. Main changes to prover, Photon, or image build inputs.
    2. Manual dispatch.

    **Runs:**

    1. GPU prover and Photon images: `docker/build-push-action`.
    2. GPU prover smoke test: `docker run`.
    3. Photon smoke test: `tools/check-photon-image.sh`.
    4. Image publication: `docker push`.
    5. Provenance: `actions/attest-build-provenance`.

14. [Nitro images](workflows/publish-nitro.yml)

    **Triggered by:**

    1. Manual dispatch selecting a deployment and prover configuration.
    2. A workflow call selecting the same inputs.

    **Runs:**

    1. Nitro image: `docker/build-push-action`.
    2. Enclave build: `prover/server/nitro/build-eif.sh`.
    3. Measurement checks: `jq`.
    4. Enclave publication: `aws s3api put-object`.
    5. Provenance: `actions/attest-build-provenance`.

15. [TEE deployment](workflows/deploy-tee.yml)

    **Triggered by:**

    1. Manual dispatch selecting a Phala CVM and deployment options.

    **Runs:**

    1. Private TEE images: `docker/build-push-action`.
    2. Provenance: `actions/attest-build-provenance`.
    3. CVM deployment: `prover/server/scripts/release_tee.sh`.
    4. Caller-supplied TEE policy artifact: `prover/tee/deployments/<cvm_name>.json`;
       SDK source files are not rewritten by deployment.

16. [TypeScript documentation](workflows/typescript-docs.yml)

    **Triggered by:**

    1. `ts-sdk-v*` tags.
    2. Manual dispatch.
    3. A workflow call.

    **Runs:**

    1. API documentation: `npm run docs:ts`.
    2. Versioned site: `node sdk-libs/ts/scripts/assemble-api-docs-site.mjs`.
    3. Published versions: `git push` (push events only).
    4. GitHub Pages: `actions/deploy-pages` (push events only).

    Reusable calls inherit the caller's event.

    In repository Settings → Pages, set the build and deployment source to
    **GitHub Actions**; otherwise `actions/deploy-pages` fails with HTTP 404.
    The `github-pages` environment must allow the `ts-sdk-v*` tag pattern.

17. [PR-only enforcement](workflows/enforce-pr-only.yml)

    **Triggered by:**

    1. Pushes to `main`.
    2. Pushes to `release/**`.
    3. A workflow call.

    **Runs:**

    1. PR-only push policy: `bash`.
