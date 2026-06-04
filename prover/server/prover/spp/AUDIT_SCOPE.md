# SPP Audit Scope

Circuit constraints:

- `circuit/transaction`: transaction circuit and in-circuit gadgets.
- `circuit/nullifier_batch_update`: nullifier indexed-tree batch update circuit.
- `circuit/gadget`: shared circuit primitives used by SPP circuits.

Support code:

- `model`: native hashes, trees, shapes, and public input hashing.
- `parse`: field, hex, and scalar decoding.
- `prover/transaction`: transaction proving and bundle IO.
- `prover/nullifier_batch_update`: nullifier batch proving and bundle IO.
- `tests`: public API and end-to-end tests.

Package-local unit tests stay beside the code they exercise.
