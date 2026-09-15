# Fresh local ring controls test

Run from `sdk-libs/ts` after `npm ci` and local builds. Use a dedicated local stack
with current SPP and user-registry programs, the generated localnet snapshots
(protocol config, tree and SPL asset counter), Photon with compressed-head indexing,
and the prover with the SPP and custom-ring keys `proving-keys.lock` pins. V1
transactions are required. Surfpool needs the explicitly opt-in local fixture
Photon build.

```sh
ZOLANA_LOCALNET_URL=http://127.0.0.1:8899 \
ZOLANA_INDEXER_URL=http://127.0.0.1:8784 \
ZOLANA_PROVER_URL=http://127.0.0.1:3001 \
ZOLANA_TREE=<tree address from the localnet snapshot> \
npm run test:ring-controls:live
```

A clone with `ZOLANA_PORT_OFFSET` set adds the offset to each port.

The runner uses `target/debug/zolana` and `target/deploy/custom_ring_program.so`.
Override with `ZOLANA_CLI_BIN` and `RING_PROGRAM_SO` when needed. It creates a
temporary CLI config and wallet, then calls the existing CLI to create, fund and
register fresh SPL and Token-2022 mints. It passes their returned mint/ATA addresses
to the test. Optional `ZOLANA_TEST_AUTHORITY_WALLET` selects an existing local
CLI wallet.

All endpoints must be loopback. The runner does not start, reset, or stop services.
Stop the stack through its own `ZOLANA_PROCESS_SCOPE_DIR` after the test. Temporary
wallet/config artifacts are retained at the printed path for debugging.
