Public audited-deposit instructions from the TypeScript SDK and Go prover.

The program tests verify each proof and forward to an SPP recorder. They do
not execute SPP settlement. Both fixtures fit the 4,096-byte v1 limit with
policy accounts, a co-signer and a separate fee payer.

Keep private keys and witness openings out of the fixtures. Regenerate both
fixtures when the deposit proving and verifying keys change.
