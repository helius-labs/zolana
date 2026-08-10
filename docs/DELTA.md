# Branch scope

What this branch adds on top of `main`, and the tier that proves each part. The
standing test strategy is in
[`program-tests/TESTING.md`](../program-tests/TESTING.md).
[`README.md`](README.md) indexes the reference documents.

Read [Open questions](#open-questions) before planning a release. Several
decisions on this branch are provisional and need the team.

## What changes in the pool

The pool gains four instructions, and every existing one settles as it did.

Tags 18 to 21 are new. `aggregate_transact` settles a batch of transact legs
against one recursive proof. `batch_update_nullifier_tree_folded` settles a run
of address-tree appends against one proof. `merge_chain_transact` chains merge
levels inside the proof. `init_vk_registry` builds a registry account and is
default-off.

The existing instructions change in three ways, all of them shape rather than
behaviour. The Groth16 call moved behind one operation struct, with a
feature-gated branch that picks the registered verifier. Transact, merge and
merge-ring accept an optional trailing registry account, which a default build
never sees. The merge core became an operation struct, so the chain reuses its
output append instead of copying it.

Nothing else moves. The UTXO format, the tree layout, the nullifier derivation
and every existing circuit are unchanged, so a proof that verifies today still
verifies against the same key. No account layout and no instruction-data layout
changes. The merge and merge-ring parsers now refuse trailing bytes they used to
ignore, which tightens an encoding without altering it.

Two additions reach outside the program. Thirteen error codes join the 7000
space, and the sequential nullifier path trades a catch-all for named causes, so
a forester can tell a run that is not ready from a proof that is invalid. The
folded nullifier payload carries the run length ahead of the existing shape,
which is the one change a consumer must decode.

## Recursion core

BN254-in-BN254 verification in gnark, with the inner verifying key compiled in
as a constant. The `gadget.OpenPublicInput` gadget opens a leg's public-input
hash to its preimage, so the outer circuit can constrain the fields inside.
Three continuity shapes build on it, which are order-only chaining,
produced-then-consumed state chains, and equality across legs. The catalogue is
in [`RECURSION.md`](RECURSION.md).

### E2E

Every outer circuit has one Go rejection test per guard, under
`prover/server/circuits/{spp_aggregate,nullifier_fold,spp_merge_chain,squads/*_fold}`.
They cover a wrong preimage, reordered legs, a proof under another key, and a
claimed statement the fold did not prove. Constraint-count pins run under
`go test -short`. The proving tests run in the key-gated tiers below.

## Aggregate transact, tag 18

One recursive proof settles a batch of `transact` legs. Per leg the program runs
the full transact pipeline without its own pairing, chains the public-input
hashes, and verifies one outer proof. A batch may mix inner kinds as an ordered
slot list with one inner key per slot, so a swap-take proof can share one outer
proof with the SPP legs it settles.

### E2E

`just test-aggregate` generates the local key catalogue, rewrites the constants
they pin, rebuilds, and runs three suites. The `ring-test-program` `aggregate_cu`
target runs against a validator, Photon, and the prover on the confidential,
ring, and P256 rails, and reports the compute each rail spends. The swap
`take_batch` suite runs under LiteSVM, because a batch exceeds the 1232-byte
transaction limit and needs the 4096-byte transaction of SIMD-0296. The Go
proving tests run under `-tags aggregate_keys`. The pre-pairing guards, the
outer-proof rejection tests, and the invariant ledger
([`invariants/aggregate.md`](../program-tests/shielded-pool/invariants/aggregate.md))
run in the fast tier with no keys.

## Merge chain, tag 20

Plain `merge` is capped at 8-to-1, and consolidation rounds are sequential
because round two needs round one's outputs in the tree. The chain feeds an
intermediate merge output straight into the next level inside the proof. A chain
of L legs spends 7L+1 UTXOs, and only the top output appends. The event carries
the chain shape, so a wallet can rebuild the merged output from the log.

### E2E

`merge_chain_collapses_fifteen_utxos_in_one_transaction` deposits fifteen UTXOs,
collapses them with two legs and one proof, and asserts that fifteen nullifiers
queue, one output appends, and the packet fits 1232 bytes. Rejection tests cover
an unsupported level shape, a tampered chain proof, and a nullifier spent twice
across legs. Run them with `cargo nextest run -p shielded-pool-tests --features
aggregate --test merge_chain_functional`, with keys from
`generate_keys_aggregate.sh`.

## Nullifier fold, tag 19

Address-tree appends are strictly sequential on chain, one transaction per zkp
batch. The fold proves a whole run advanced the root correctly, with root and
index continuity per adjacent pair, and settles it in one transaction. The
forester gains `--fold-run N` with fallback to single appends. A folded run
appends one root for several batches, so a consumer must read the update count
on the event rather than count roots.

### E2E

`just test-nullifier-fold` generates the fold keys, then
`nullifier_tree_folded_run_matches_sequential_appends` drives a real tree
account and asserts the folded run ends in the root a sequential forester
produces. Photon reconstructs the whole run before it checks the root, pinned by
`folded_run_reaches_the_root_of_the_whole_run`. The span planner and the two
rejection causes have their own pins.

## Squads policy zone and folds

A complete zone program in `zones/squads`, its own nested workspace. Viewing-key
accounts carry auditor and recovery ciphertexts. Spends settle on the P256 rail,
or on the smart-account rail where a Squads vault with no signing key settles
through crank-executed proposals. Deposits derive the recipient on chain, and
key rotation replaces the encrypted key material without touching the nullifier
public key that earlier UTXOs bind. Two fold circuits lift its width caps,
`fold_transact` (tag 17) for up to six UTXOs in one spend, and the
key-encryption folds for up to nine recipient keys. The protocol description is
[`SQUADS.md`](SQUADS.md).

### E2E

`just test-squads` builds the zone program and runs the unit and LiteSVM suites.
The lifecycle suites boot a fresh validator and Photon, because the SPP protocol
config is a singleton. They prove the product property directly, which is that
the auditor recovers every balance from on-chain data plus its own secret, with
no user secrets. Guard coverage includes every missing-signature path, the
co-signer mismatch on each spend, a blocked account, an expired transaction, and
a proof shape that disagrees with the operation. Keys come from
`generate_keys_squads.sh`.

## VK registry

Per-VK registry accounts cache the prepared G2 Miller line schedules and the
`e(alpha, beta)` GT target. Addresses are commitments, init is permissionless
and spans several transactions, and the registered verify path is wired at every
verification site across the four programs, the recursive settlement
instructions included. The catalog covers all 48 verifying keys. Everything sits
behind the default-off `vk-registry` feature, because the prepared-operand
syscalls it calls are not upstream. Trust model and layout are in
[`vk_registry.md`](vk_registry.md).

### E2E

`just test-vk-registry` runs LiteSVM with the fork syscalls registered at the
runtime tariff. It covers the init flow to finalized account bytes, then one
real proof settling through the registered path and the same proof through the
plain path, asserting the registered path costs less. A wrong-shape registry, an
index past the catalog, a re-init after finalize, and an unfinalized account all
fail closed. Registry spec derivation, layout offsets, error codes, and the VK
fingerprint are pinned host-side in the always-on interface suites.
`just test-vk-registry-aggregate` runs the registry and recursion cross product,
where a two-leg batch settles its outer pairing through one registry account and
a registry for another key is rejected by the address compare.

## Prover serving and GPU dispatch

The prover server grows a setup command per proving system, lazy loading for all
of them, name-based key download, and self-provisioning test tiers. Each recipe
generates missing keys and rewrites the constants they pin.

Every prove call site routes through `prover/gpuprove`, which picks the backend
at run time. The default build carries only the CPU prover. A `cuda icicle`
build adds gnark's accelerated prover and follows `PROVER_GPU`, where `auto`
routes circuits at or above `PROVER_GPU_MIN_CONSTRAINTS` to the device, `on`
requires one, and `off` forces CPU. The device route adds the ICICLE witgen
backend, streamed MSMs, batched NTTs, and a tape-based witness solve, difftested
bit-identical against the CPU witness. The contract is in
[`gpu-prover.md`](../prover/server/docs/gpu-prover.md).

The dispatch layer gets O(1) status and dedup lookups, a queue-depth gauge for
autoscaling, queue-wait and delivered-edge gauges, and one count per proof
request. Default worker concurrency derives from the CPU count. Job completion
pushes the result to a per-job reply key, and `GET /prove/wait` blocks on it with
the status poll unchanged as the fallback. Prove-time tables are in
[`BENCHMARKS.md`](../prover/server/BENCHMARKS.md).

### E2E

Queue and dispatch suites run against in-process redis in the always-on tier.
The concurrency derivation, the reply delivery and its poll fallback, and the
`auto` routing threshold each have a dedicated test. A job that cannot enter the
processing queue lands in the failed queue with a reply, and a worker that
panics recovers instead of stranding the caller. `PROVER_LOAD_TEST=1` runs
concurrent mixed-shape proves that verify every proof on either backend.

## Indexer

Photon parses and persists the new settlement shapes and the Squads key-material
log. A rotation destroys the previous key material on chain, so an offline
recovery or auditor key holder has no other source for it. The log is served by
`get_squads_key_events`. An event this build cannot decode is stored with its raw
bytes rather than halting ingestion, because the data exists nowhere else.

### E2E

Parser and persist tests run on in-memory SQLite in the always-on tier. The
folded-run test settles two batches one at a time to build a reference root,
then drives one folded update and asserts both the root and its sequence number
match.

## TypeScript SDK

The instruction tags, error codes, account discriminators, shape table and
account sizes are generated from the Rust definitions by
`cargo xtask ts-interface-consts`. Its check mode is wired into `just check-all`,
so a Rust variant added without regenerating fails the build. This closed a gap
where the shipped table carried twenty-nine error codes against the Rust enum's
fifty-three, omitted all four new instruction tags, and named six codes that Rust
had retired or renamed.

## What is missing on chain

The code settles, but a cluster cannot run all of it yet. These are protocol
gaps, not work items.

**Verifying keys are program constants.** Every key the branch adds is compiled
in, including the aggregate outer keys, the nullifier fold key, and the zone
keys. Rotating any circuit is a program upgrade of every program that embeds its
key, which is the pool, the zone, and the three example programs. The registry
caches prepared operands for a key that is still a constant, so it does not make
keys swappable. Nothing on chain lets an operator move to a new circuit without
redeploying.

**A registry account can only be created.** There is no close and no resize. Its
rent is locked for the life of the program, and rotating a key orphans every
account derived from the old digest with no way to reclaim them. Tag 21 is the
init, and no tag pairs with it.

**The new settlement paths have no switch of their own.** The protocol config
carries authorities and three permissionless flags, and nothing else. A ring can
be paused and a tree can be paused, and both cover the new paths correctly, but
an operator who wants to stop aggregate batches or folded runs while leaving
ordinary spends alive has no way to do it.

**A zone is inert until it holds a ring config.** Before any Squads settlement,
someone must create the ring config for the zone program, which needs the
ring-creation authority to sign or the permissionless flag set. Deploying the
zone program is not enough.

A folded nullifier update needs the forester authority, the same gate a
sequential update needs, so the fold asks for no new permission.

## Tier order

| Tier | Command | Needs |
|---|---|---|
| Static, units, pins | `just check-all`, `just clippy`, `just test-program-fast` | nothing |
| Proof integration, all rails | `just test-programs` | prover build |
| Squads zone | `just test-squads` | zone program build |
| Validator and Photon | `just test-spp-validator`, `just test-ring-validator`, `just test-swap-validator` | photon, smart-account fixture |
| VK registry | `just test-vk-registry` | git-pinned agave crate |
| Aggregate, mixed, swap batch | `just test-aggregate` | local key generation |
| Merge chain | `nextest -p shielded-pool-tests --features aggregate --test merge_chain_functional` | same keys |
| Nullifier fold and forester | `just test-nullifier-fold` | local fold keys |
| Squads proof-backed and lifecycle | `just test-squads` after `generate_keys_squads.sh` | zone keys, validator, photon |
| Device route | `go test -tags "cuda icicle cudawitgen" ./prover/aggregate/...` | CUDA box with ICICLE |
| GPU dispatch, load, bench | `PROVER_LOAD_TEST=1 go test -tags "cuda icicle" ./circuits/...` | CUDA box with ICICLE |

The key-gated tiers are local by design. Their keys are unpublished, and each
recipe reproduces them from scratch, so every run exercises the key-provisioning
path.

## Open questions

Strategic decisions for the team. Each one shapes what can ship and where.

### What the forks gate

Three dependencies point at forks, and each gates a different capability.

The gnark fork adds the recursion verifier options the outer circuits need.
Stock gnark derives the BSB22 challenge with a different hash and rejects every
P256 proof the prover sends, so the whole recursive rail depends on it. The
groth16-solana fork reduces the BSB22 hash-to-field buffer in halves, which is
what brings a committed verify inside the compute budget, and it carries the
prepared-operand path the registry uses. The agave fork is narrower, and only
the `vk-registry` test crate builds against it.

### What the Solana runtime does not offer yet

Two capabilities depend on runtime features a stock validator does not have, so
neither can reach mainnet until the runtime moves.

Registry-backed verification calls prepared-operand BN254 syscalls that have no
filed SIMD. That is why `vk-registry` is default-off, and the question for the
team is whether to pursue the SIMD or to treat the registry as a research path.

Aggregate batches and the swap take-batch do not fit the 1232-byte transaction
and need the 4096-byte transaction of SIMD-0296. Ship dates depend on that being
active on the target cluster.

### Where the zone boundary sits

`zones/squads` is excluded from the root workspace and carries its own lockfile,
while Photon depends on its interface crate across that boundary. The crate
resolves twice, and nothing forces the two resolutions to agree. Either the
interface crate joins the root workspace, or Photon gets a decoder that lives
there. The wider question is whether a policy zone is a nested workspace at all,
because the next zone inherits whatever is decided here.
