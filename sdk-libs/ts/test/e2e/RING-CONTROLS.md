# Fresh local ring controls test

Run from `sdk-libs/ts` after `npm ci` and local builds. Use a dedicated local stack
with current SPP and user-registry programs, the generated localnet snapshots
(protocol config, tree and SPL asset counter), Photon with compressed-head indexing,
and the prover with current main SPP keys plus this branch's custom-ring keys.
V1 transactions are required. Surfpool needs the explicitly opt-in local fixture
Photon build. Production head checks must not be relaxed.

```sh
ZOLANA_LOCALNET_URL=http://127.0.0.1:28899 \
ZOLANA_INDEXER_URL=http://127.0.0.1:28784 \
ZOLANA_PROVER_URL=http://127.0.0.1:13002 \
ZOLANA_TREE=33KVhbT4QtdQDrrrGwwThqD47Dh4Q6tA443t9jMNcWFN \
npm run test:ring-controls:live
```

The runner uses `target/debug/zolana` and `target/deploy/custom_ring_program.so`.
Override with `ZOLANA_CLI_BIN` and `RING_PROGRAM_SO` when needed. It creates a
temporary CLI config and wallet, then calls the existing CLI to create, fund and
register fresh SPL and Token-2022 mints. It passes their returned mint/ATA addresses
to the test. No manually pre-funded wallet, mint or ring is needed. Optional
`ZOLANA_TEST_AUTHORITY_WALLET` selects an existing local CLI wallet instead.

The test deploys a fresh policy ring, enables its local authority rail, and exercises
registration, co-signing, public windows, compressed SOL/SPL/Token-2022 spending,
counter/auditor recovery, cap refusals, delegated multi-mint source change, and a full
sponsored Token-2022 withdrawal. Delegation must leave velocity counters unchanged.

All endpoints must be loopback. The runner does not start, reset, or stop services.
Stop the stack through its own `ZOLANA_PROCESS_SCOPE_DIR` after the test. Temporary
wallet/config artifacts are retained at the printed path for debugging.
