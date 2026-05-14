# Vendored Light test-validator artifacts

These binaries are explicit test fixtures for `zolana test-validator`.
They replace the previously hidden dependency on the npm
`@lightprotocol/zk-compression-cli` package for stable programs that this
reduced workspace does not build from source.

- `spl_noop.so` comes from the upstream Light Protocol repository at
  `third-party/solana-program-library/spl_noop.so`.
- `light_system_program_pinocchio.so` comes from
  `@lightprotocol/zk-compression-cli@0.28.4`, which was generated from the
  upstream Light Protocol `programs/system` package.

The repo-owned programs are not vendored here. Build them into `target/deploy`
with `just build-light-programs`:

- `account_compression.so`
- `light_registry.so`
- `light_compressed_token.so`

Update `SHA256SUMS` whenever replacing one of these fixtures.
