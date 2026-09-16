# Cache proof fixtures

`generate.sh` creates the new verifying keys and real merge/transfer proofs using the circuit test fixtures. It requires `target/debug/xtask` and the existing `merge_8_1.key`.

New setup artifacts stay in `prover/server/proving-keys/cached/` (`.pk`, `.vk`, `.r1cs`). Cached keys must match the compiled circuit. `keys.sha256` pins the reviewed artifacts; SDK/server loading and distribution belong to phase 3.

The temporary Go test files are removed on exit. Program tests consume the committed JSON proofs without starting a prover.
