# Constraint counts before and after Xark

The comparison uses the existing timelock program with capacity five for escrow
and one state input for withdrawal. Counts are R1CS rows used for Groth16 setup,
before padding to the proving domain.

| Program | Original DSL | Xark | Change |
| --- | ---: | ---: | ---: |
| Timelock escrow, capacity 5 | 14,880 | 17,444 | +2,564 (+17.2%) |
| Timelock withdraw | 5,638 | 6,141 | +503 (+8.9%) |
| Browser escrow fixture, capacity 5 | 14,858 | 17,423 | +2,565 (+17.3%) |
| Browser withdraw fixture | 5,638 | 6,141 | +503 (+8.9%) |

Original counts were remeasured from repository revision
`ff04c625ceb43c688cd048549e00a5dabc0c6ee6` in a detached worktree. The temporary
measurement executable constructs `Groth16Prover::<P>::new_with_test_setup()`
for each original program and reads `constraint_count()`. Output is saved in
`constraint-counts-before.log`. Original zk-tools revision:
`56d6e53616c26a69130c51f9a9084829eef514bd`.

Post-migration Xark revision:
`b443d83ea8ec7f2253610887e9690623ad048aef`, with the SDK arithmetic and equality
optimizations recorded in `.claude/perf-loop/xark/artifacts/e05-report.json`.
Timelock escrow has 17,946 raw compiler rows and 17,444 setup rows. Timelock
withdraw has 6,310 raw compiler rows; its circuit digest
`6185579ddef3ed92824b2255ffd39fda` matches the browser withdraw artifact with
6,141 setup rows. Compilation is recorded in `escrow-in-place-compile.log`.
Browser setup counts come from the respective `metadata.json` under
`target/zk/zolana-program-wasm-test-program/`.

A fresh build before committing the snapshot reproduced the timelock setup
counts of 17,444 and 6,141 directly in their respective `metadata.json` files
under `target/zk/timelock-escrow-program/`. All four timelock functional tests
passed against those artifacts.

The earlier `native-before.md` scenario table reports 8,660 for escrow and
5,620 for withdrawal. Those scenarios have different inputs and public
bindings; the escrow scenario has only two input slots. They are not the
baseline for the five-slot timelock program.

The initial Xark port had 101,077 escrow setup rows (102,691 raw). The current
optimized port has reduced that to 17,444 setup rows. This is a reduction
within the migration; the original DSL is still smaller as shown above.

Constraint counts alone do not establish proving time or memory use. Timelock
escrow crosses from a 16,384-point radix-2 domain to 32,768; withdrawal stays
within an 8,192-point domain.
