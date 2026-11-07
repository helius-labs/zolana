# Rust crate releases

Use the [shared checklist](README.md). A Rust SDK release uses
`rust-sdk-v<version>` and lists every published crate and its actual version.
Crate versions are declared in individual manifests; do not assume the whole
workspace or the TypeScript SDK shares a version.

## Prepare and verify

1. Select the exact crate batch from the current Cargo manifests. Respect
   `publish = false` and allowed registries. Eligibility does not mean every
   crate belongs in the release. Record source commits for companion crates
   from other repositories, including ZK crates from `helius-labs/zk-tools`.
2. Update selected package versions, dependency requirements, lockfiles, and
   release notes in the release PR. Include migration steps. Resolve path and
   workspace dependencies to their registry versions; published packages must
   not depend on unpublished or git-only dependencies.
3. Derive dependency-first publication order from those manifests. Check each
   selected name/version against crates.io before publishing. Account for
   companion-repository dependencies in the same order.
4. Use the repository toolchain and prerequisites. Run `just check-all` and
   `just test-hermetic`, plus checks for the affected features and proof paths.
   A bare `cargo check` covers only the default members. Record CI and local
   results for the exact source commit.
5. From the repository root, set `release_crate` to one selected package and run:

   ```bash
   cargo package -p "$release_crate" --list --locked
   cargo publish -p "$release_crate" --dry-run --locked
   ```

   Inspect the packaged manifest, source, and license files in `target/package`.
   Test a separate consumer with the supported feature combinations, outside
   workspace path dependencies and `[patch]` overrides. A dry run may need an
   earlier dependency published first; record that pending check and run it
   successfully before publishing the dependent crate. Do not use `--no-verify`
   or `--allow-dirty` to bypass release failures.

## Publish and verify

After authorization for the selected batch, publish one crate at a time in
dependency order:

```bash
cargo publish -p "$release_crate" --locked
```

Verify the exact version is available on crates.io before continuing. Compare
the downloaded `.crate` checksum and contents with the verified package, check
its source metadata, and install it in the registry consumer. If upload times
out, check registry state before retrying; the upload may have succeeded.

After every selected crate is verified, create and push the annotated
`rust-sdk-v<version>` tag at the released Zolana source commit when authorized.
Follow the [GitHub guide](github.md), listing the published crate versions,
companion source commits, and compatibility with the TypeScript SDK and deployed
programs. Do not claim a crate was published based only on packaging or CI.

References: [Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html),
[cargo publish options](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).
