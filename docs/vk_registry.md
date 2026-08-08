# VK Registry

Registry-backed Groth16 verification over the stateless prepared-operand
syscalls of the agave fork branch `local/bn254-prepared-stateless`. Everything
here is behind default-off cargo features (`vk-registry`); the default program
build references none of the fork syscalls and loads on a stock validator.

## Trust model

The syscalls are stateless math primitives. `sol_alt_bn128_g2_prepare` fully
validates one canonical G2 point (curve, r-order subgroup) and emits a
16,712-byte wire blob (8-byte header plus the scalar-Montgomery Miller line
schedule; the radix-52 IFMA form is derived on restore so two limb domains
can never disagree across a mixed fleet). `sol_alt_bn128_pairing_check_prepared`
and `sol_alt_bn128_pairing_map_prepared` consume such blobs alongside full
pairs, skip the subgroup check and line preparation for them, and validate
only encodings. Provenance is the calling program's own obligation: a wrong
blob can only fail the caller's own verification.

The program's trust decision is one address compare. A registry account's PDA
seeds are `[b"vk_registry", keccak(domain || version || backend || g2_count
|| sources || alpha || beta)]` under the consumer program id, so the address
is a commitment to the key material. Digest, address, and bump are emitted at
codegen time (`cargo xtask vk-registry-consts`) from the committed
`VERIFYINGKEY` constants; the hot path compares the passed account's address
against the const and does no runtime hashing. Owner, discriminator, and
`finalized` checks are defense in depth.

## Account layout

`program-libs/interface/src/verifying_keys/registry_spec.rs` owns the layout:
8-byte header (`state/vk_registry.rs`), then `g2_count` entries of 128-byte
canonical source plus 16,712-byte prepared blob, then the 384-byte cached
`e(alpha, beta)` target. Sources are stored so a validator backend bump only
needs re-preparation in place. Sizes: 50,912 bytes for the 26 three-G2 VKs,
84,592 bytes for the 10 five-G2 BSB22 VKs.

## Init

`INIT_VK_REGISTRY` (tag 18) is permissionless and idempotent per step. The
account exceeds the 10,240-byte per-transaction allocation cap, so clients
resend one instruction until finalized: create at the cap, one resize per
transaction with rent top-up, then a final step that runs `g2_prepare` per
source and `sol_alt_bn128_pairing_map([(alpha, beta)])` for the GT target and
sets `finalized`. Contents need no authority: they derive only from
compile-time constants and deterministic syscalls, and no write path exists
after finalize. `InitVkRegistry::transaction_count()` gives the send count
(6 for three-G2, 10 for five-G2 shapes).

## Verified paths

Every proof-bearing instruction takes one optional trailing read-only
registry account; absent keeps today's path byte for byte.

- `transact` and merge: trailing-account detection after the settlement run.
- `batch_update_nullifier_tree`: spec selected by the tree account's
  `zkp_batch_size`, not instruction data.
- sdk-test programs (`zk-program-swap`, `dynamic-swap`, `timelock-escrow`):
  the registry account precedes the SPP CPI account run and is recognized by
  address; each program owns registries for its own VKs under its own id and
  has its own init tag.

The main check uses the cached GT target: `e(A,B) e(-L,gamma) e(-C,delta) ==
e(alpha,beta)` with gamma and delta prepared, dropping the alpha-beta pair.
The BSB22 PoK check stays a separate 2-pair prepared call; the two ==1 checks
are never folded into one product without randomization.

## Cost

Measured end to end with a real (2,3) confidential proof under the fork lane
tariff (`program-tests/vk-registry/tests/transact_e2e.rs`): transact drops
from 162,606 to 102,650 CU. The tariff credits are measured per regime
(sub-lane vs lane-filling) and pinned in
`syscalls/tests/bn254_charge_schedule.rs` on the fork branch; fleet
calibration is still pending there.

## Workflows

```bash
just build-programs-vk-registry   # registry-enabled .so into target/deploy-vk-registry
just test-vk-registry             # init flows + proof e2e (needs the agave fork worktree)
cargo xtask vk-registry-consts    # regenerate all spec consts after any VK change
```

Spec staleness is pinned: `program-libs/interface/tests/vk_registry_spec.rs`
and each sdk-test program's `tests/vk_registry_specs.rs` re-derive every
digest, address, and bump from the committed VKs.
