Public audited-deposit instructions from the Rust ring SDK and Go prover.

The program tests verify each proof and forward to an SPP recorder. They do
not execute SPP settlement. Both fixtures fit the 4,096-byte v1 limit with
policy accounts, a co-signer and a separate fee payer. The files omit the key
registry root index byte after the proof; `proven_fixture` inserts it.

Keep private keys and witness openings out of the fixtures. Regenerate both
fixtures when the SPP ring deposit layout or the deposit proving and verifying
keys change:

    just dump-deposit-audit-fixtures

The recipe installs the pinned custom-ring proving keys, including
`custom_ring_deposit.key`, starts this clone's prover and runs the ignored `dump_deposit_audit_fixtures` test in
`custom-rings/sdk/tests/deposit_audit_fixtures.rs`, which rewrites `2.bin` and
`8.bin`. Then run `cargo nextest run -p custom-ring-program --tests`.
