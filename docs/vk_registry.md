# VK Registry

Registry-backed Groth16 verification over the prepared-operand
syscalls of the agave fork branch `helius/alex/bn254-prepared`. Everything
here is behind default-off cargo features (`vk-registry`). The default program
build references none of the fork syscalls and loads on a stock validator.

## Trust model

The syscalls are pure math primitives. `sol_alt_bn128_g2_prepare` fully
validates one canonical G2 point for curve and r-order subgroup membership, and
emits a 16,712-byte prepared blob. The blob is an 8-byte header plus the
scalar-Montgomery Miller line schedule. The radix-52 IFMA form is derived on
restore, so two limb domains can never disagree across a mixed fleet.
`sol_alt_bn128_pairing_check_prepared`
and `sol_alt_bn128_pairing_map_prepared` consume such blobs alongside full
pairs, skip the subgroup check and line preparation for them, and validate
only encodings. Provenance stays the calling program's own obligation. A wrong
blob can only fail the caller's own verification.

The program's trust decision is one address compare. A registry account's PDA
seeds are `[b"vk_registry", keccak(domain || version || backend || g2_count
|| sources || alpha || beta)]` under the consumer program id, so the address
is a commitment to the key material. Digest, address, and bump are emitted at
codegen time (`cargo xtask vk-registry-consts`) from the committed
`VERIFYINGKEY` constants, and the hot path compares the passed account's
address against the const and does no runtime hashing. Owner, discriminator, and
`finalized` checks are defense in depth.

## Account layout

`program-libs/interface/src/verifying_keys/registry_spec.rs` owns the layout.
An 8-byte header (`state/vk_registry.rs`), then `g2_count` entries of a
128-byte canonical source plus a 16,712-byte prepared blob, then the 384-byte
cached `e(alpha, beta)` target. Sources are stored so a validator backend bump only
needs re-preparation in place. A key with no BSB22 commitment has three
canonical sources and a 50,912-byte account, a key with one has five sources
and 84,592 bytes. `registry_account_layout_is_pinned` in
`program-libs/interface/tests/vk_registry_spec.rs` pins both lengths and the
blob size, and `committed_registry_specs_match_rederivation` pins that the
source count follows the key's commitment.

## Init

`INIT_VK_REGISTRY` (tag 21) is permissionless and idempotent per step. The
account exceeds the 10,240-byte per-transaction allocation cap, so clients
resend one instruction until it finalizes. Create at the cap, one resize per
transaction with rent top-up, then a final step that runs `g2_prepare` per
source and `sol_alt_bn128_pairing_map([(alpha, beta)])` for the GT target and
sets `finalized`. Contents need no authority, because they derive only from
compile-time constants and deterministic syscalls, and no write path exists
after finalize. `InitVkRegistry::transaction_count()` derives the send count
from the target length, and `program-tests/vk-registry/tests/init_flow.rs`
drives exactly that many steps and then asserts the finalized account bytes.

## Verified paths

Every proof-bearing instruction takes one optional trailing read-only
registry account. An absent account keeps today's path byte for byte.

- `transact` and merge: trailing-account detection after the settlement run.
- `batch_update_nullifier_tree`: spec selected by the tree account's
  `zkp_batch_size`, not instruction data.
- sdk-test programs (`zk-program-swap`, `dynamic-swap`, `timelock-escrow`):
  the registry account precedes the SPP CPI account run and is recognized by
  address, and each program owns registries for its own VKs under its own id
  and has its own init tag.

The main check uses the cached GT target, `e(A,B) e(-L,gamma) e(-C,delta) ==
e(alpha,beta)` with gamma and delta prepared, dropping the alpha-beta pair.
The BSB22 PoK check stays a separate 2-pair prepared call. The two ==1 checks
never merge into one product without randomization.

## Failure modes

Every init step and every registered verification fails closed. The error names
carry their codes in the [spec error table](spec.md#errors).

| Failure | Where | Result |
|---|---|---|
| the catalog index names no key | init | `InvalidVkRegistryIndex`, no account is touched |
| the passed account is not that key's PDA | init and the verified path | `InvalidVkRegistryAccount`, before any syscall runs |
| the header names another layout, backend, or source count | init and the verified path | `InvalidVkRegistryAccount`. A backend bump invalidates every stored blob at once |
| an init step runs against a finalized account | init | `VkRegistryAlreadyInitialized`, the finalized bytes stay as they are |
| a proof-bearing instruction is passed an unfinalized account | the verified path | `VkRegistryNotReady`, so nothing verifies against partial contents |
| a prepare syscall rejects a source or the alpha-beta pair | the final init step | `VkRegistryInitFailed`, the account stays unfinalized |

## Recovery

A run stopped between resize steps leaves an unfinalized account of some
intermediate length, and that state needs no repair path. The step machine
reads its next step from the account's own length, so anyone resends the same
instruction and it resumes. Length zero creates, a length below the target
grows by one step with a rent top-up, and the target length finalizes. Until it
finalizes, the verified path refuses the account with `VkRegistryNotReady` and
every caller keeps the plain path.

The account has no close instruction and no write path after `finalized`. A key
whose material changes commits to a different address, so a rotation creates a
new account and leaves the old one in place.

## What the permissionless init does not enforce

- No authority. Any account may create, grow, and finalize any catalogued
  registry, and the bytes are the same whoever pays. The address commitment
  makes the contents usable, not the caller.
- No refund. The payer's rent is not recoverable, because nothing may write the
  account or close it after finalize.
- No requirement to use a registry. The trailing account stays optional at
  every verification site, so a caller that omits it takes the plain path.
- No external provenance check. The compile-time constants are the source and
  `g2_prepare` is the only validation, so provenance stays the calling
  program's own obligation.

## Cost

A registered transact costs strictly fewer compute units than the plain path
for the same real (2,3) confidential proof under the fork lane tariff, because
it drops the alpha-beta pair and skips the subgroup check and line preparation
on gamma and delta. `registered_transact_verifies_and_undercuts_the_plain_path`
in `program-tests/vk-registry/tests/transact_e2e.rs` pins that direction and
nothing else. The tariff credits are pinned per regime, sub-lane and
lane-filling, in `syscalls/tests/bn254_charge_schedule.rs` on the fork branch.

## Workflows

```bash
just build-programs-vk-registry   # registry-enabled .so into target/deploy-vk-registry
just test-vk-registry             # init flows + proof e2e (needs the agave fork worktree)
just test-vk-registry-aggregate   # a real batch settling its outer pairing through one registry
cargo xtask vk-registry-consts    # regenerate all spec consts after any VK change
```

Spec staleness is pinned. `program-libs/interface/tests/vk_registry_spec.rs`
and each sdk-test program's `tests/vk_registry_specs.rs` re-derive every
digest, address, and bump from the committed VKs.
