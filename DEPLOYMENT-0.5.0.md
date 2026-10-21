# Devnet 0.5.0 fresh deployment

## Selected program IDs

This release uses the following new program IDs in its source constants, SDKs
and deployment tooling:

| Program | Program ID |
|---|---|
| Shielded pool (SPP) | `spp3CfN2Y7se74A27bBpnAkmjXyEb2YmmZafhFrC9xt` |
| User registry | `regy3WAeRXMYuMYxr5iK3Bf9Arr3PcxGxyzAddbiqDQ` |

The old program IDs are retained below only as historical references. Deployment
to the new IDs is pending.

## Deployment phases

### Phase 1: Close big tree 1 — completed

Tree 1 has already been closed by the operator. Retain its closure transaction
and recovered-funds record for the deployment log. No further tree-maintenance
or migration transaction is planned against the old deployment.

### Phase 2: Deploy to new program IDs

1. **Use the selected program IDs:** deploy the shielded pool at
   `spp3CfN2Y7se74A27bBpnAkmjXyEb2YmmZafhFrC9xt` and the user registry at
   `regy3WAeRXMYuMYxr5iK3Bf9Arr3PcxGxyzAddbiqDQ`. Their deployment keypairs
   already exist outside the repository in
   `/Users/jorrit/dev/zolana-devnet-keys/program-id/`.
2. **Prepare the release:** update program IDs, derived addresses, SDK constants,
   deployment tooling and service configuration together. Build and test the
   exact artifacts that will be deployed. Leave the unused migration prototype
   out of the fresh release.
3. **Deploy fresh programs:** deploy both programs at their new addresses and
   initialize a new protocol config with the intended authorities. Complete
   initialization before handing off or renouncing upgrade authority.
4. **Initialize fresh accounts and funding:** create a new tree and the required
   SOL/SPL interfaces under the new shielded-pool program. Fund the new tree for
   its queue configuration and forester fees. Recovered tree-1 funds can be
   transferred explicitly to the new deployment.
5. **Deploy services:** deploy matching Photon, prover and forester versions
   configured for the new program IDs and accounts. Use a fresh indexer database
   or an explicitly isolated namespace. Discard proof jobs and service caches
   associated with the old deployment.
6. **Reset test clients:** point clients at the new deployment, clear or namespace
   their local test-wallet state, and register users afresh with the new
   user-registry program and X25519 viewing keys. Test balances and history start
   afresh; old ciphertexts and records are not imported.
7. **Verify and enable:** verify fresh registration, deposit, private transfer,
   withdrawal, wallet synchronization, a 4,999-nullifier proof and PDA cleanup.
   Confirm clients, SDKs and services resolve the same new program IDs before
   opening the new devnet deployment to test users.

## Scope

This is a clean deployment for test users. Tree 0 and all remaining accounts
under the old program IDs are left as they are. There is no tree-0 migration,
nullifier-PDA conversion, user-record migration or bulk registry-account closure.
The fresh registry program ID gives users a separate registration namespace.
Custom rings remain outside this plan.

The prior account-migration prototype is superseded by this plan. Its local
migration tests do not validate a fresh deployment under newly selected IDs.

## Address record

| Component | Old deployment | New deployment |
|---|---|---|
| Shielded-pool program | `sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6` | `spp3CfN2Y7se74A27bBpnAkmjXyEb2YmmZafhFrC9xt` |
| User-registry program | `regyS5rkAcw2YzDJCmTwCTHs2s246FXxbmuRZ42u2PD` | `regy3WAeRXMYuMYxr5iK3Bf9Arr3PcxGxyzAddbiqDQ` |
| Tree 0 | `33KVhbT4QtdQDrrrGwwThqD47Dh4Q6tA443t9jMNcWFN` — leave unchanged | `C37FDLpLGLvAUpywCJBjeb9HhGF6YZamYZ6uNqW9XnVD` |
| Big tree 1 | `Cqu55AjGprSHJKs65Sw3P4zi1ZtJGy56jz91TyKmw3Cn` — closed | Not reused |

New deployment PDAs:

| Account | Address |
|---|---|
| Protocol config | `FKznFoeiRNwkMPSxywbQdbRCfBZc5JMa7kqCFzumHhHE` |
| SOL interface | `4u5xeYyt3s9iQWiSxLXbFD1XebTKJa3YduTwdecBF5ZG` |
| CPI authority | `GbAD545QqvKKigMT3YkSA1V5PQBmyPHuNyRiXQPBQfJn` |

Changing the shielded-pool program ID changes its protocol config, tree,
nullifier, vault and CPI-authority PDAs. Changing the registry program ID changes
its user-record PDAs. Derive and verify these addresses from the new IDs rather
than copying addresses from the old deployment.

## Preparation and validation

- Inventory hardcoded program IDs and derived addresses across Rust programs,
  SDKs, TypeScript, prover, Photon, forester, examples and deployment scripts.
  Source constants and deployment targets now use the selected IDs; captured
  historical transaction fixtures retain their original addresses.
- `tools/deploy-devnet.sh` targets the selected new programs. For their first
  deployment, set `ZOLANA_DEVNET_KEYS_DIR=/Users/jorrit/dev/zolana-devnet-keys`
  so the script can find their existing program keypairs. Review the Solana RPC,
  payer and upgrade authority before deployment.
- Build fresh SBF artifacts after updating IDs and record their hashes. Re-run
  the relevant SDK, program and service checks against the new addresses.
- Exercise a fresh local deployment and test-wallet lifecycle before devnet.
  Use new accounts and registrations throughout the test.
- Record deployed program IDs, derived account addresses, authorities, artifact
  hashes, service versions and transaction signatures in the deployment log.

## Current execution status

Tree-1 closure is reported complete by the operator. The selected program IDs
and their derived-address constants have been updated in this worktree. No
fresh deployment has been performed by this implementation task. The separate
`codex/close-unused-devnet-tree` worktree contains the isolated close instruction
and is independent of this fresh rollout.
