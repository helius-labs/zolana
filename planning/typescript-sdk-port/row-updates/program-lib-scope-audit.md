# Program-library scope audit

**Of the 171 lines this branch added under `program-libs/`, exactly 5 were compiled into the deployed program. Another 3 were compiled into a protocol library the program never loads. The remaining 163 sit inside `#[cfg(test)]` blocks and reach no binary at all.** Both compiled hunks are now reverted. The 5-line hunk was a redundant check that replaced a precise program error with a generic one and is gone for good; the 3-line hunk is a real fix and moved to `fix/indexed-array-exclusive-highest-value` off main.

Two premises behind the audit turned out to be wrong, and both matter for how the residue is read:

- **The `bc55a9b9` revert was not incomplete.** `b416a64f` removed every compiled line `bc55a9b9` had added to `transact.rs`; the file's non-test code is byte-identical to base. The +38 that remains is an unrelated golden vector from `abaa9984`, which is test-only.
- **`program-libs/indexed-array` is not compiled into the program.** It is absent from the shielded-pool dependency tree. Its only normal-dependency consumer is `sdk-libs/merkle-tree`, and through it the forester. `program-libs/batched-merkle-tree` lists it as a *dev*-dependency only.

## Category counts

| Category | Hunks | Insertions | Disposition |
| --- | --- | --- | --- |
| 1. Additive, SDK-only new API | 0 | 0 | Nothing to recommend; see [Category 1 is empty](#category-1-is-empty) |
| 2. Behaviour-changing on a program path | 1 | 5 | Reverted, not relocated |
| 2b. Behaviour-changing off the program path | 1 | 3 | Reverted here, relocated to its own branch |
| 3. Test or fixture only | 6 | 163 | Left alone, except two that only existed to serve hunk 2 |

Category 2b is not one of the three categories asked for. It exists because a hunk can change what a `program-libs/` crate does while sitting outside the shielded-pool dependency tree. Calling it category 2 would claim the deployed program behaves differently, which it does not. Calling it category 1 would claim nothing executes the code, when the forester does.

## Per-hunk findings

| # | Location | Lines | Commit | Category | Compiled into the program | Correct | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `indexed-array/src/array.rs:366-368` | +3 | `975783aa` | 2b | No | Yes | Reverted; relocated |
| 2 | `interface/.../merge_transact.rs:97-101` (`validate_shape`) | +5 | `484ac5ed` | 2 | **Yes** | No | Reverted; discarded |
| 3 | `interface/.../merge_transact.rs` `data()` fixture | +5 / -3 | `484ac5ed` | 3 | No | n/a | Reverted with hunk 2 |
| 4 | `interface/.../merge_transact.rs` `rejects_wrong_encrypted_utxo_type_prefix` | +10 | `484ac5ed` | 3 | No | n/a | Reverted with hunk 2 |
| 5 | `interface/.../merge_zone.rs` test fixture | +10 / -2 | `14ad3001` | 3 | No | n/a | Left alone |
| 6 | `interface/.../transact.rs` `external_data_hash_vector_is_stable` | +38 | `abaa9984` | 3 | No | n/a | Left alone |
| 7 | `interface/src/merge_utils.rs` `ciphertext_hash_chunk_boundaries_are_stable` | +40 | `d7d228c6` | 3 | No | n/a | Left alone |
| 8 | `interface/src/pda.rs` `current_pda_vectors_are_stable` | +60 | `a41b85f8` | 3 | No | n/a | Left alone |

Hunks 3 and 4 are test-only in isolation, but they exist solely to serve hunk 2: the fixture was rewritten to satisfy the new check, and hunk 4 asserts the rejection. Reverting hunk 2 without them would leave a failing test. They came in on the same single-file commit and went out with it.

## Hunk 2: the merge ciphertext prefix check

This was the branch's only edit to code the deployed program executes, and it bought nothing while costing error precision.

The program already rejects a wrong `encrypted_utxo[0]`, in both merge instructions, and has since before this branch:

| Site | Base behaviour |
| --- | --- |
| `programs/shielded-pool/src/instructions/merge/processor.rs:32-34` | `InvalidMergeOutputScheme` (7020) |
| `programs/shielded-pool/src/instructions/merge_zone/processor.rs:39-41` | `InvalidMergeOutputScheme` (7020) |

The branch added the same comparison to `MergeTransactIxDataRef::validate_shape`, which runs inside `from_bytes`. Both processors map any `from_bytes` failure to `InvalidMergeShape` (7019). So the set of accepted instructions did not change; a wrong prefix was refused before and after. What changed is what the caller sees:

- A wrong-prefix merge returned 7020; on this branch it returned 7019.
- The program's own check became unreachable, which invites a later reader to delete a correct guard as dead code.
- 7020 is exported to SDK consumers as `InvalidMergeOutputScheme` in `sdk-libs/ts/interface/src/errors.ts:33`, so the substitution is observable outside the program, not just internally.

That is a behaviour change on a program path, and it is the wrong direction: the house rule is that every fallible path returns a specific named variant rather than a generic one. It is not a bug fix and has nothing to relocate.

No test asserted 7020 either way, which is why the substitution went unnoticed. Nothing in the circuit or the tests produces a wrong prefix: the one fixture that builds a merge instruction for the program, `program-tests/shielded-pool/tests/merge_user_record.rs:168`, sets the prefix explicitly.

## Hunk 1: the indexed-array highest-value bound

`IndexedArray` tracks `highest_value` as the next value of whichever element is currently the greatest. `append_with_low_element_index` checked the bounded branch, where a new value must fall below its next element, but the unbounded branch checked only the lower bound. Appending a value at or above `highest_value` therefore succeeded and built a range node whose next value did not exceed its own, which makes every non-inclusion proof landing in that range unsound. The added guard is correct, and its `is_zero()` escape preserves the `Default` array's unbounded meaning.

It is still out of scope here. `program-libs/` is not the SDK, and the crate is published. But it is off the program path, so nothing on chain was ever at risk either way:

```
zolana-indexed-array
└── zolana-merkle-tree (sdk-libs/merkle-tree)
    └── forester
```

Relocated to **`fix/indexed-array-exclusive-highest-value`**, branched off `43fde8e4` (main), commit `5fed6663`. It carries the guard plus two tests: a new unit test in the crate's own suite, and `custom_highest_value_is_an_exclusive_bound`, moved out of `sdk-libs/merkle-tree/tests/indexed.rs` where it would otherwise have failed after the revert. The branch is local and unpushed, matching how `fix/merge-user-record-binding` was handled.

The rest of `975783aa` is atomicity work in `sdk-libs/merkle-tree` and stays on this branch. Its coverage survives the move: `indexed_capacity_and_hash_errors_are_atomic` still exercises the atomicity fix through hashing and capacity failures.

## Category 1 is empty

No hunk added a function, constant, or type to `program-libs/`. Every symbol the new tests touch already existed at base: `MERGE_ENCRYPTED_UTXO_TYPE_PREFIX`, `zone_config_with_bump`, `zone_auth_with_bump`, `shielded_pool_program_id`, `ciphertext_hash`, `ExternalDataHash`. The SDK gained no program-library API from this branch, so there is no judgment call of the kind anticipated and nothing depends on anything that could be removed.

The nearest thing to a judgment call is the 163 lines of test-only residue in `program-libs/interface` (hunks 5 through 8), and **I recommend keeping all of it.**

Its cost in program binary size is exactly zero, not approximately zero. Every changed line in all four files sits after that file's `#[cfg(test)]` attribute, and `cargo build-sbf` does not set `cfg(test)`, so none of it reaches the artifact. The built `shielded_pool_program.so` is 343,968 bytes with the residue present.

Three of the four are golden vectors (a PDA set, a ciphertext-hash chunk-boundary sweep, an `ExternalDataHash` preimage) pinning exactly the Rust values the TypeScript port must reproduce. They are the anchors the port's parity claims rest on, and deleting them would remove the evidence at no saving. The fourth is a fixture correction.

The one argument against, worth recording rather than acting on: a golden vector in a protocol library is a tripwire aimed at protocol authors. If a future change legitimately alters the `ExternalDataHash` preimage, the author must update a vector that exists for a TypeScript port. The branch already has the more durable home for that in `sdk-libs/ts/vectors/`, fed by an xtask, as `poseidon-parity-v1.json` is. Moving them there later is a cleanup, not a scope violation, and not worth the churn now.

One orphan is left behind deliberately. Hunk 5 rewrote the `merge_zone` test fixture to carry a valid prefix, purely to satisfy the check in hunk 2. With that check gone the fixture is merely more realistic than the `merge_transact` fixture beside it, which the revert returned to a plain byte ramp. The inconsistency is cosmetic and test-only, so it was left alone.

## Verification

| Check | Result |
| --- | --- |
| `just build-programs` | Passes |
| `cargo check --workspace --all-targets` | Passes; no SDK code needed adjusting beyond the relocated test |
| `cargo test -p zolana-interface --features solana` | 35 passed |
| `cargo test -p shielded-pool-program --lib --tests` | 7 passed |
| `cargo test -p shielded-pool-tests` (bdd) | 33 scenarios, 151 steps passed |
| `cargo test -p shielded-pool-tests` (transact, double-spend, p256, shield/withdraw) | 14 passed |
| `cargo test -p shielded-pool-tests --test merge_user_record` | 3 failed, pre-existing |
| `cargo test -p zolana-user-registry --tests`, `-p user-registry-tests --test wire_layout` | 6 passed |
| `cargo test -p zolana-indexed-array -p zolana-merkle-tree` | 28 passed |
| `cargo test -p forester --lib` | 9 passed |
| Relocation branch: `cargo test -p zolana-indexed-array -p zolana-merkle-tree` | 24 passed, including both new tests |

The three `merge_user_record` failures are the documented `user_record` binding defect, not a regression from this audit. They are ruled in `authority-rulings.md` to move to `fix/merge-user-record-binding` and be dropped from this branch, and they belong to whoever holds `program-tests/`. Three independent facts place them outside this work: they expect `InvalidUserRecord` (7018) and get `TransactProofVerificationFailed` (7008), which is reached long after instruction-data parsing; their fixture sets a valid prefix, so `validate_shape` accepted it before and after the revert; and `484ac5ed` landed before `cbf197e7` wrote them, so they were already failing while the reverted check was in place.

## Commits

| Commit | Effect |
| --- | --- |
| `7060d2d5` | Reverts hunks 2, 3, 4; `merge_transact.rs` is byte-identical to base |
| `88728091` | Reverts hunk 1 and drops the test that depended on it |
| `5fed6663` | On `fix/indexed-array-exclusive-highest-value`: the relocated fix and its tests |
