1. this package contains only circuits no other logic
2. this package must not depend on other packages in zolana/prover/server other packages may depend on it
3. every circuit should have its own directory, or file if the directory would only contain one file
4. zolana/prover/server/prover defines marshall and proving system glue code
5. prover/server/server implements the prover server that clients call to get proofs
6. non _test.go files must not contain any code that is only used in tests
7. circuit should have a single public input hash as public input because it is cheaper in the solana program to do a poseidon hash chain or hash than to do individual public inputs.
