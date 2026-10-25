# CI

Current behavior in this branch. Links contain the exact path filters and command arguments. PR filters consider the whole PR; changes to shared Cargo files can select broader checks.

Changes under `programs/` run every validation workflow.

Most validation jobs skip draft PRs. TypeScript and deployment-script checks also run on drafts.

1. [Protocol operations](.github/workflows/protocol-ops.yml)

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
    6. `zolana-forester-prover`: `cargo test`.
    7. `zolana-protocol-cli`: `cargo test`.
    8. `zolana-protocol-instructions`: `cargo test`.
    9. `zolana-smart-account-client`: `cargo test`.
    10. `zolana-merkle-tree`: `cargo test`.

2. [Rust workspace](.github/workflows/rust.yml)

    **Triggered by:** PR/main changes outside these ignored paths; `programs/**` overrides the exclusions:

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
    6. `zolana-cli`: `cargo nextest run`.
    7. `xtask`: `cargo nextest run`.
    8. `zolana-interface`: `cargo nextest run`.
    9. `zolana-instruction`: `cargo nextest run`.
    10. `zolana-protocol-instructions`: `cargo nextest run`.
    11. `shielded-pool-program`: `cargo nextest run`.
    12. `shielded-pool-tests`: `cargo nextest run`.
    13. `zolana-user-registry`: `cargo nextest run`.
    14. `user-registry-tests`: `cargo nextest run`.
    15. `swap-program`: `cargo nextest run`.
    16. `zolana-program-test`: `cargo nextest run`.
    17. `zolana-program`: `cargo nextest run`, `cargo test`.
    18. `zolana-keypair`: `cargo nextest run`, `cargo test --doc`.
    19. `zolana-event-parser`: `cargo nextest run`.
    20. `zolana-transaction`: `cargo nextest run`.
    21. `zolana-client`: `cargo nextest run`, `cargo test --doc`.
    22. `zolana-test-utils`: `cargo nextest run`.
    23. `zolana-rpc-http`: `cargo nextest run`.
    24. `zolana-gnark-ffi-prover`: `cargo nextest run`.
    25. `swap-prover`: `cargo nextest run`.
    26. `dynamic-swap-prover`: `cargo nextest run`.
    27. `sdk-libs/gnark-sdk`: `go test`.
    28. `zolana-zk-standalone-fixture`: `cargo test`.
    29. `zolana-macros`: `cargo test`.
    30. `timelock-escrow-program`: `cargo test`.
    31. `zk-tests`: `cargo nextest run`.
    32. Wasm compilation: `just check-wasm`.
    33. Photon binary: `cargo build`.
    34. SBF programs: `just build-programs`.
    35. Localnet tools: `just build-localnet-tools`.
    36. Localnet test archives: `just build-localnet-archives`.
    37. Localnet e2e: `just test-localnet-e2e-photon`.
    38. SPP lifecycle/decode: `just test-spp-validator-lifecycle-decode`.
    39. SPP merge: `just test-spp-validator-merge`.
    40. SPP randomized: `just test-spp-validator-randomized`.
    41. SPP proof CU: `just test-spp-validator-proof-cu`.
    42. Ring lifecycle: `just test-ring-validator`.
    43. Maximum transaction shapes: `just test-max-shapes-validator`.
    44. Swap and escrow: `just test-swap-and-escrow-validator`.
    45. Dynamic swap: `just test-dynamic-swap`.
    46. Compression: `just test-compression-validator`.
    47. RFQ settlement: `just test-rfq-validator`.
    48. Coverage: `just coverage`.

3. [TypeScript](.github/workflows/typescript.yml)

    **Triggered by:**

    1. PR/main changes, except changes limited to `protocol-ops/` and its workflow file.

    **Runs:**

    1. `@heliuslabs/zolana`: `npm run check:ts`.
    2. API documentation: `npm run docs:ts`.
    3. Package smoke test: `npm pack`, `tsc`, `node`.
    4. SDK e2e: `just test-ts-e2e`.
    5. Escrow e2e: `just test-escrow-ts`.
    6. `zolana-program-wasm-test-program`: `cargo test`.
    7. `sdk-libs/program/tests/wasm`: `npm test`.
    8. `zolana-zk-standalone-fixture`: `cargo test`.
    9. Standalone Wasm: `node --test`.

4. [Photon](.github/workflows/photon.yml)

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
    4. `zolana-indexer-api`: `cargo test`.
    5. `photon-indexer`: `cargo test`.

    Protocol-ops changes do not select this workflow.

5. [Prover server](.github/workflows/prover-server.yml)

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

6. [Async prover](.github/workflows/async-prover.yml)

    **Triggered by:**

    1. Every PR.
    2. Main pushes outside its ignore list.

    **Runs:**

    1. Changed-file filter: `git diff`.
    2. `zolana-client` async transfer: `cargo nextest run`.

    The path gate skips the test for ops-only, TypeScript-only, and Markdown-only PRs outside `programs/`.

7. [Verifying-key smoke test](.github/workflows/xtask-verifying-keys.yml)

    **Triggered by:** PR/main changes to:

    1. `programs/`.
    2. `xtask/`.
    3. `prover/`.
    4. Shared Rust setup.
    5. This workflow.

    **Runs:**

    1. `xtask` verifying-key smoke test: `just xtask-create-verifying-keys-smoke`.

8. [Formal verification](.github/workflows/formal-verification.yml)

    **Triggered by:** PR/main changes to:

    1. `programs/`.
    2. `prover/server/`.
    3. This workflow.

    **Runs:**

    1. Prover binary: `go build`.
    2. Circuit extraction: `light-prover extract-circuit`.
    3. Lean definition drift: `git diff --exit-code`.
    4. Lean proofs: `lake build`.

9. [Ring compatibility](.github/workflows/ring-compat.yml)

    **Triggered by:**

    1. PR changes to Photon or prover.
    2. PR changes to programs or SDKs.
    3. PR changes to CLI.
    4. PR changes to shared build inputs or ring CI.
    5. Main changes to `programs/`.

    **Runs:**

    1. Custom-ring compatibility: `just test-ring-compat`.

    Requires the private checkout key.

10. [Deployment scripts](.github/workflows/gpu-deploy-scripts.yml)

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

11. [Service images](.github/workflows/publish-image.yml)

    **Triggered by:**

    1. PR/main changes to `programs/`.
    2. PR/main changes to Photon or image build inputs.
    3. `photon-zolana-*` tags.
    4. Manual dispatch.

    **Runs:**

    1. Photon image: `docker/build-push-action`.
    2. Photon smoke test: `tools/check-photon-image.sh`.
    3. Service publication: `uses: ./.github/workflows/publish-service-image.yml` (tags/manual only).

12. [Reusable service publisher](.github/workflows/publish-service-image.yml)

    **Triggered by:**

    1. A workflow call selecting a service, channel, and tag.

    **Runs:**

    1. Service image: `docker/build-push-action`.
    2. Photon smoke test: `tools/check-photon-image.sh`.
    3. Prover smoke test: `docker run`.
    4. Forester smoke test: `docker run`.
    5. Image publication: `docker push`.
    6. Provenance: `actions/attest-build-provenance`.

13. [GPU images](.github/workflows/publish-gpu.yml)

    **Triggered by:**

    1. Main changes to prover, Photon, or image build inputs.
    2. Manual dispatch.

    **Runs:**

    1. GPU prover and Photon images: `docker/build-push-action`.
    2. GPU prover smoke test: `docker run`.
    3. Photon smoke test: `tools/check-photon-image.sh`.
    4. Image publication: `docker push`.
    5. Provenance: `actions/attest-build-provenance`.

14. [Nitro images](.github/workflows/publish-nitro.yml)

    **Triggered by:**

    1. Manual dispatch selecting a deployment and prover configuration.
    2. A workflow call selecting the same inputs.

    **Runs:**

    1. Nitro image: `docker/build-push-action`.
    2. Enclave build: `prover/server/nitro/build-eif.sh`.
    3. Measurement checks: `jq`.
    4. Enclave publication: `aws s3api put-object`.
    5. Provenance: `actions/attest-build-provenance`.

15. [TEE deployment](.github/workflows/deploy-tee.yml)

    **Triggered by:**

    1. Manual dispatch selecting a Phala CVM and deployment options.

    **Runs:**

    1. Private TEE images: `docker/build-push-action`.
    2. Provenance: `actions/attest-build-provenance`.
    3. CVM deployment: `prover/server/scripts/release_tee.sh`.

16. [TypeScript documentation](.github/workflows/typescript-docs.yml)

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

17. [PR-only enforcement](.github/workflows/enforce-pr-only.yml)

    **Triggered by:**

    1. Pushes to `main`.
    2. Pushes to `release/**`.
    3. A workflow call.

    **Runs:**

    1. PR-only push policy: `bash`.
