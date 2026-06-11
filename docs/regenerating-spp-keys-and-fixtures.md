# Regenerating SPP keys, verifying keys, and fixtures

The shielded-pool transact proofs are pinned by three kinds of committed
artifact that must stay a matched set:

- **proving keys** — `target/spp/spp_<in>_<out>{,_solana}.key` (gitignored; the
  prover signs with them).
- **verifying keys** — `programs/shielded-pool/src/instructions/transact/verifying_keys/spp_*.rs`
  (the program embeds and verifies against them). On branch **spp/3-program**.
- **fixtures** — `program-tests/shielded-pool/tests/fixtures/spp_e2e.json` and
  `batch_update.json` (e2e proofs the program verifies on-chain). On branch
  **spp/6-e2e**.

A fixture proof only verifies against the verifying key from the *same* setup
run, so when the circuit changes you must regenerate keys → vkeys → fixtures
together.

## Recipes

Run from the **tip branch (spp/7-demo)** — that is the only branch where the
prover's `spp` subcommand, the vkey output dir, and the fixture output dir all
exist at once.

```sh
just regen-spp-transact-fixtures      # setup all 10 circuits → vkeys (.rs) + spp_e2e.json
just regen-spp-batch-update-fixture   # the forester batch-update (address-append) fixture
just build-spp-keys                   # just the 1-2 proving key, for the zolana demo
```

`regen-spp-transact-fixtures` runs Groth16 setup for all 10 (shape, rail)
circuits, so it is slow (minutes). The hardcoded keypair/account hex in
`scripts/regen-spp-transact-fixtures.sh` mirrors the litesvm test's fixtures;
if that test changes its keys, update the script.

## When to run what

- **Circuit changed** (anything under `prover/.../spp/circuit/`, e.g. the
  public-input set or a hash preimage): both recipes — vkeys *and* fixtures
  change.
- **Scenario/fixture set changed** (only `fixtures_scenario.go`): just the
  fixture recipes; the vkeys are unchanged, and `git status` on the
  `verifying_keys/` dir should stay clean.
- **A hash byte-order or formula changed** (external_data_hash, private_tx_hash,
  public_input_hash): also update the known-answer vectors —
  `prover/server/prover/spp/testdata/field_derivation_vector.json` and the
  `const want` literals in `proof.rs` / `proof_bundle_test.go` tests. Run the
  failing test once to read the new value.

## Landing the artifacts on the stack

The recipes write everything into the tip's working tree, but the artifacts are
owned by lower branches, and **spp/6's e2e needs the new vkeys to be at or below
spp/6** (the program it builds embeds them). So distribute them:

1. On the tip, regenerate with the recipes above.
2. `git stash push -- program-tests/shielded-pool/tests/fixtures/*.json` to set
   the fixtures aside.
3. `git switch spp/3-program` (carries the vkey changes — same paths), commit
   the `verifying_keys/` changes there.
4. Rebase spp/4 → spp/5 → spp/6 onto the new spp/3.
5. On spp/6, `git stash pop` and commit the fixtures.
6. Rebase spp/7 onto spp/6, then `cargo build-sbf … shielded-pool` and run
   `cargo test -p shielded-pool-tests` + `-p light-program-test`.
