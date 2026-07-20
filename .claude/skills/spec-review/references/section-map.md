# Spec Section → Code Map

Maps `docs/spec.md` top-level sections to the code that implements them. Used
for the verification fan-out (one subagent per group) and for scoping `diff`
mode (a changed file selects every group that lists its directory).

## Group 1 — Keys & addresses

Sections: `# Shielded Address`, `# Signing Key`, `# Nullifier Key`,
`# ViewingKey`

Code: `sdk-libs/keypair/`, `sdk-libs/transaction/` (key derivation, view tags,
encryption key handling), `prover/server/circuits/` (ownership/derivation
constraints)

## Group 2 — UTXO model & serialization

Sections: `# UTXO` (hash, nullifier, empty UTXO),
`# Output UTXO Serialization` (AES key derivation, UTXO data, Transfer,
Plaintext Transfer, UTXO Split, Merge)

Code: `sdk-libs/transaction/` (UTXO, wincode layouts, encryption),
`program-libs/interface/src/instruction/instruction_data/`,
`services/photon/` (decode side)

## Group 3 — Proof systems

Sections: `# SPP Proof - Solana Privacy ZK Proof`,
`# Merge Proof - Merge ZK Proof`

Code: `prover/server/circuits/spp_transaction/`, `prover/server/` (shapes,
lazy key manager), `prover/client/`, `sdk-libs/client/src/shape.rs`,
`program-libs/interface/src/verifying_keys/`

## Group 4 — SPP program

Sections: `# SPP - Solana Privacy Program` (Accounts, Instructions)

Code: `programs/shielded-pool/src/`, `program-libs/interface/src/`
(tags, builders, instruction data, state, error), `program-libs/` support
crates (tree, event, account-checks)

## Group 5 — Zone & ZK program interfaces

Sections: `# Zone Program Interface`, `# ZK Program Interface`, the zone
subsections of Architecture (`## Default Zone`, `## Policy Zones`)

Code: `programs/shielded-pool/src/` (zone/CPI paths),
`program-libs/interface/`, `sdk-tests/` zone/swap test programs

## Group 6 — RPC & services

Sections: `# RPC` (Indexer, Prover, Relayer, Zone RPC, Merge Service,
Registry, Sync Delegate)

Code: `services/photon/`, `prover/server/`, `prover/client/`, `forester/`,
`sdk-libs/client/`, `sdk-libs/program-test/` (local harness behavior)

## Cross-cutting (checked by the orchestrator, not fanned out)

Sections: `# Architecture`, `# Glossary`, `# User Flows`, and any
Constants / Trust Assumptions / Permission Matrix sections

Code: whole workspace; constants live in `program-libs/interface/src/`
(`constants`, tree parameters) and `prover/server/`
