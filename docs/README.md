# Documentation

What each document in this directory answers.

| Document | Question it answers |
|---|---|
| [DELTA.md](DELTA.md) | what this branch adds on top of `main`, stream by stream, and the tier that proves each |
| [spec.md](spec.md) | what the protocol is. Keys, UTXO layout, accounts, every instruction, and the RPC surface. The source of truth |
| [properties.md](properties.md) | what must hold, per circuit and per program instruction |
| [RECURSION.md](RECURSION.md) | what each recursive circuit proves, which width cap it lifts, and what its key costs |
| [SQUADS.md](SQUADS.md) | how the Squads policy zone owns UTXOs and settles them through the pool |
| [vk_registry.md](vk_registry.md) | how registry-backed verification is trusted, initialized, and refused |
| [registry_program.md](registry_program.md) | how a Solana address maps to a shielded address |
| [detailed_user_flows.md](detailed_user_flows.md) | what the wallet, the RPC, and the prover exchange in each user flow |
| [SPEC_GUIDE.md](SPEC_GUIDE.md) | the checklist a specification in this tree must pass |
| [alt-designs/](alt-designs) | designs that were considered and not built |

Test and prover documentation lives beside the code it describes.
[`program-tests/TESTING.md`](../program-tests/TESTING.md) holds the test tiers
and what each one needs,
[`program-tests/shielded-pool/invariants/`](../program-tests/shielded-pool/invariants/)
holds the per-instruction invariant register and its coverage,
[`prover/server/docs/gpu-prover.md`](../prover/server/docs/gpu-prover.md) holds
the GPU backend contract, and
[`prover/server/BENCHMARKS.md`](../prover/server/BENCHMARKS.md) holds the
prove-time tables.
