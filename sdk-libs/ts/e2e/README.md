# TypeScript e2e suites

These suites boot a real validator, Photon, and prover through `@zolana/test-kit`'s
`startLocalStack`. CI builds the binaries first; a local `npm run test:e2e:*` / `npm run check:e2e`
does not.

Before running them on a developer machine:

```bash
just build-programs
just build-prover-server
just build-photon
npm run build
```

`startLocalStack` reads `CARGO_TARGET_DIR` when set, otherwise `<repo>/target`. A missing binary
fails immediately with `TEST_KIT_INVALID_CONFIG` and a `hint` naming the `just` recipe. A **stale**
`shielded_pool_program.so` (built before the current create-tree layout) is not detected up front:
create-tree then fails with `CLIENT_RPC_PROGRAM_ERROR` / `InvalidInstructionData`. Rebuild with
`just build-programs`.

Each suite pins its own `ZOLANA_PORT_OFFSET` (300 / 400 / 500 / 800). Leave `ZOLANA_LOCALNET_URL`,
`ZOLANA_INDEXER_URL`, and `ZOLANA_PROVER_URL` unset so the harness starts those services itself.

Opt-in live suites (`test:e2e:p4`, `test:e2e:p5`, `test:e2e:p5:hybrid`, `test:e2e:gate3`,
`test:e2e:user-registry`) also run on every pull request in the `typescript / e2e` job,
sequentially: P5 / Gate 3 assert offset 300, and the user-registry lifecycle hardcodes 500.
`test:e2e:p4` runs the full shape set (`ZOLANA_TEST_P4_FULL=1`). CI wraps each of those five in
`retry-once.sh` (one visible retry); `check:e2e` stays fail-closed.
