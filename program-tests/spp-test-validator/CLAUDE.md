### Description
gherkin tests with local test validator and photon.


### File Layout

Run: `just test-spp-validator`.

```
tests/
  lifecycle.rs   # cucumber runner: module decls + main(); only [[test]] target
  world.rs       # LifecycleWorld: handles, actor map, per-scenario new() setup, accessors
  actor.rs       # Actor: one participant (keypair, wallet, spendable + expected UTXOs)
  localnet.rs    # validator/prover/indexer harness + constants (no asserts)
  features/      # one .feature per scenario group
  steps/
    common.rs        # background
    <instruction>.rs # per instruction: cucumber steps + impl LifecycleWorld (action + assert)
    wallet_sync.rs   # wallet sync + UTXO asserts (not an instruction)
```

- `lifecycle.rs` is the only `[[test]]`; `autotests = false` makes the rest its
  modules. Runner uses `futures::executor` because the SDK clients are blocking;
  `max_concurrent_scenarios(1)`.
- `world.rs::new()` runs per scenario: fresh validator + Photon, persistent prover,
  protocol config + tree. Fields/accessors are `pub(crate)` for the step modules.
- Actions go through the client SDK (`actions::Deposit`), not hand-built instructions.
- Functional asserts live in `program-tests/test-utils/src/test_validator_asserts`.

### Style
1. features, contains test scenarios
2. steps, contain 1 file per instruction, separate action function, separate assert function
3. failing asserts must use assert rpc error function
4. functional asserts must use assert function implemented in program-tests/test-utils/src/test_validator_asserts
5. asserts must use full structs for structs that are 100% derministic, some values are random eg blinding for that we can use partial asserts but must take care that we assert the full state transition
6. naming must match naming in spec.md
7. use text review skill
8. minimal duplicate code
9. no dead code
