# shielded-pool fuzz harness

A stateful [crucible](https://github.com/asymmetric-research/crucible) harness for
`programs/shielded-pool`, submitted to FuzzCorp on every push to `main` by
`.github/workflows/fuzz-submit.yml`.

Each action drives one instruction through LiteSVM; the invariants in `src/main.rs`
assert properties across them. `PROPERTIES.md` is the ledger: what each property
claims, why it is not simply restating a check the program already makes, and what
had to be built to reach it.

## Layout

```
src/main.rs        actions, fixtures, invariants
PROPERTIES.md      the property ledger
idls/              instruction and account layouts the harness builds calls from
build-bundle.sh    assembles the FuzzCorp bundle
```

## Running locally

```bash
just build-programs
mkdir -p fuzz/shielded-pool/programs fuzz/shielded-pool/fixtures
cp target/deploy/shielded_pool_program.so fuzz/shielded-pool/programs/
cp target/deploy/ring_test_program.so fuzz/shielded-pool/fixtures/

cd fuzz/shielded-pool
cargo test --features invariant_test     # the fixture and property tests
./build-bundle.sh                        # assemble a bundle
```

The program `.so` files are built, never committed — a checked-in binary would keep
fuzzing whatever it was built from while the program moved on.

## Keeping it working

The harness builds its calls from `idls/shielded_pool.json`. Change an instruction's
tag, account order, or payload layout and the matching action stops reaching the
handler: it fails at account validation instead, which looks like a passing fuzz run
rather than a broken one. Update the IDL in the same change, and check the action
still succeeds.

## Adding a property

Add it to `PROPERTIES.md` with a statement of what a violation would mean, implement
it as a `SCOUT:INVARIANT` block in `src/main.rs`, and add a test that makes it fire
on the corruption it is meant to catch. A property that has never been seen to fail
is indistinguishable from one that cannot.
