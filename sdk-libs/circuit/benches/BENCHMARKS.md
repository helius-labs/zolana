# Circuit primitive constraint benchmarks

Each case profiles one primitive or public API operation implemented in `spr-circuit`, using `xark profile --json`.

## Snapshot

Recorded on 2026-10-28 with BN254.

- SDK revision: `aae7ddec275242f132e4c791ad0ae750856ee606` with working-tree circuit changes.
- Xark CLI: `xark 0.3.0 (e9dab1f74670)`.
- Xark checkout: `e9dab1f7467029087bf79322d6d3163ee689a30c`.
- Circuit source/dependency SHA-256: `605dc55ff921d2b5aa6a068c0dd310be3df22bd96055ea22a60a1f2c8a8814b8`.

Input rows are checks emitted at `#[circuit]`, including ranges and reconstruction. Each explicit field-output equality contributes one binding row (tagged Equality or Mul by Xark); deferred result materialization stays in the body cost. Body rows are `total - inputs - bindings`, including callees. These are compiler R1CS counts before proving-key setup.

## Controls

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `field_identity` | 0 | 0 | 1 | 1 |
| `u64_identity` | 0 | 65 | 1 | 66 |

## Equality controls

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `constant_scalar_equality` | 0 | 0 | 1 | 1 |
| `constant_asset_equality` | 0 | 0 | 1 | 1 |
| `same_wire_asset_equality` | 0 | 288 | 1 | 289 |

## Poseidon

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `poseidon_1` | 213 | 0 | 1 | 214 |
| `poseidon_2` | 240 | 0 | 1 | 241 |
| `poseidon_3` | 261 | 0 | 1 | 262 |
| `poseidon_4` | 297 | 0 | 1 | 298 |
| `poseidon_5` | 321 | 0 | 1 | 322 |
| `poseidon_6` | 354 | 0 | 1 | 355 |
| `poseidon_7` | 381 | 0 | 1 | 382 |
| `poseidon_8` | 402 | 0 | 1 | 403 |
| `poseidon_9` | 417 | 0 | 1 | 418 |
| `poseidon_10` | 459 | 0 | 1 | 460 |
| `poseidon_11` | 465 | 0 | 1 | 466 |
| `poseidon_12` | 504 | 0 | 1 | 505 |

## Byte hashing

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `hash_bytes_0` | 0 | 0 | 1 | 1 |
| `hash_bytes_1` | 0 | 9 | 1 | 10 |
| `hash_bytes_16` | 0 | 144 | 1 | 145 |
| `hash_bytes_31` | 0 | 279 | 1 | 280 |
| `hash_bytes_32` | 240 | 288 | 1 | 529 |
| `hash_bytes_33` | 240 | 297 | 1 | 538 |
| `hash_bytes_62` | 240 | 558 | 1 | 799 |
| `hash_bytes_63` | 480 | 567 | 1 | 1,048 |
| `hash_bytes_64` | 480 | 576 | 1 | 1,057 |
| `hash_bytes_96` | 720 | 864 | 1 | 1,585 |

## Nonzero hash chains

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `nonzero_chain_0` | 0 | 0 | 1 | 1 |
| `nonzero_chain_1` | 0 | 0 | 1 | 1 |
| `nonzero_chain_2` | 248 | 0 | 1 | 249 |
| `nonzero_chain_3` | 496 | 0 | 1 | 497 |
| `nonzero_chain_5` | 992 | 0 | 1 | 993 |
| `nonzero_chain_10` | 2,232 | 0 | 1 | 2,233 |

## Owners and UTXOs

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `signing_key_identity` | 240 | 297 | 1 | 538 |
| `owner_hash` | 481 | 297 | 1 | 779 |
| `shielded_address_hash` | 961 | 594 | 1 | 1,556 |
| `utxo_hash` | 1,587 | 703 | 1 | 2,291 |
| `utxo_hash_with` | 861 | 703 | 1 | 1,565 |
| `default_ring` | 2 | 0 | 1 | 3 |
| `public_transfer_hash` | 777 | 643 | 1 | 1,421 |

## State and addresses

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `data_output` | 237 | 65 | 1 | 303 |
| `unique_address` | 1,340 | 362 | 1 | 1,703 |
| `unique_output` | 1,598 | 362 | 1 | 1,961 |
| `unique_close` | 1,577 | 362 | 1 | 1,940 |

## State lifecycle

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `data_state_spend` | 2,184 | 768 | 4 | 2,956 |
| `data_state_update` | 2,421 | 833 | 4 | 3,258 |
| `data_state_close` | 2,118 | 1,056 | 4 | 3,178 |
| `unique_state_spend` | 2,205 | 768 | 4 | 2,977 |
| `unique_state_update` | 2,460 | 833 | 4 | 3,297 |
| `unique_state_close` | 2,980 | 1,056 | 4 | 4,040 |
| `unique_state_burn` | 2,139 | 1,056 | 4 | 3,199 |

## Bounded inputs

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `array_vec_u64_1` | 0 | 65 | 1 | 66 |
| `array_vec_u64_5` | 0 | 325 | 1 | 326 |

## Token aggregation

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `token_inputs_1` | 1,490 | 703 | 2 | 2,195 |
| `token_inputs_2` | 2,522 | 1,406 | 2 | 3,930 |
| `token_inputs_5` | 5,417 | 3,515 | 2 | 8,934 |

## Balances

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `balance_baseline` | 84 | 130 | 2 | 216 |
| `balance_deposit` | 168 | 130 | 2 | 300 |
| `balance_transfer` | 294 | 130 | 2 | 426 |
| `balance_transfer_all` | 97 | 130 | 2 | 229 |
| `balance_withdraw` | 152 | 130 | 2 | 284 |
| `balance_withdraw_all` | 88 | 130 | 2 | 220 |

## Balance arithmetic

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `balance_arithmetic_baseline` | 0 | 323 | 2 | 325 |
| `balance_arithmetic_deposit` | 274 | 323 | 2 | 599 |
| `balance_arithmetic_transfer` | 338 | 323 | 2 | 663 |
| `balance_arithmetic_transfer_all` | 339 | 323 | 2 | 664 |
| `balance_arithmetic_withdraw` | 72 | 323 | 2 | 397 |
| `balance_arithmetic_withdraw_all` | 8 | 323 | 2 | 333 |

## Balances with protocol outputs

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `balance_complete_baseline` | 1,656 | 130 | 5 | 1,791 |
| `balance_complete_deposit` | 1,980 | 130 | 5 | 2,115 |
| `balance_complete_transfer` | 1,884 | 130 | 5 | 2,019 |
| `balance_complete_transfer_all` | 1,669 | 130 | 5 | 1,804 |
| `balance_complete_withdraw` | 2,012 | 130 | 5 | 2,147 |
| `balance_complete_withdraw_all` | 1,930 | 130 | 5 | 2,065 |

## Private balances with protocol outputs

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `balance_private_baseline` | 2,623 | 1,300 | 5 | 3,928 |
| `balance_private_deposit` | 3,428 | 1,300 | 5 | 4,733 |
| `balance_private_transfer` | 3,332 | 1,300 | 5 | 4,637 |
| `balance_private_transfer_all` | 2,636 | 1,300 | 5 | 3,941 |
| `balance_private_withdraw` | 2,979 | 1,300 | 5 | 4,284 |
| `balance_private_withdraw_all` | 2,416 | 1,300 | 5 | 3,721 |

## Input ordering

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `input_order_1` | 0 | 21 | 4 | 25 |
| `input_order_2` | 18 | 42 | 8 | 68 |
| `input_order_5` | 180 | 105 | 20 | 305 |
| `input_order_10` | 810 | 210 | 40 | 1,060 |

## Token transactions

| Case | Body | Input rows | Binding rows | Constraints |
| --- | ---: | ---: | ---: | ---: |
| `token_transaction_1` | 3,215 | 722 | 1 | 3,938 |
| `token_transaction_2` | 4,505 | 1,425 | 1 | 5,931 |
| `token_transaction_5` | 8,311 | 3,534 | 1 | 11,846 |

## Incremental balance costs

Each column subtracts its own baseline. Amount-only cases include funding and balance-read checks; arithmetic cases initialize the real Balance implementation directly; complete cases retain protocol outputs, with constant or private owners/assets/accounts as labeled. Complete deltas include changes to output emptiness; an operation can reduce cost when its empty output skips owner/asset hashing.

| Operation | Amount-only delta | Arithmetic delta | Complete delta | Private complete delta |
| --- | ---: | ---: | ---: | ---: |
| `deposit` | 84 | 274 | 324 | 805 |
| `transfer` | 210 | 338 | 228 | 709 |
| `transfer_all` | 13 | 339 | 13 | 13 |
| `withdraw` | 68 | 72 | 356 | 356 |
| `withdraw_all` | 4 | 8 | 274 | -207 |

## Optimization comparison

Before: SDK `aae7ddec2`, Xark CLI `38c0de6fec56`. After: the snapshot above. Ordering and transaction cases were added before changing their implementations; ordering originally used the same function body from transaction.rs. All values below exclude input rows and output bindings.

| Case | Before body | After body | Saved |
| --- | ---: | ---: | ---: |
| `constant_asset_equality` | 32 | 0 | 32 |
| `balance_arithmetic_deposit` | 341 | 274 | 67 |
| `balance_arithmetic_transfer` | 504 | 338 | 166 |
| `balance_arithmetic_withdraw` | 138 | 72 | 66 |
| `token_inputs_5` | 6,622 | 5,417 | 1,205 |
| `token_transaction_5` | 9,863 | 8,311 | 1,552 |
| `input_order_5` | 526 | 180 | 346 |
| `input_order_10` | 274,130 | 810 | 273,320 |

Default-ring spending still validates both supplied ring fields, then hashes their known zero values. Native integer operations share an unconditional borrow/remainder proof in Xark; overflow, underflow and immediate u64 debit narrowing remain enforced. Stable input ordering swaps the records conditionally and updates dummy flags directly using AND/OR. It still performs a quadratic number of adjacent comparisons.

Explicit SDK owner/asset hash caches were tested and removed: they saved only one row in the five-input transaction after ring specialization. Xark already reuses identical Poseidon multiplication products across calls. No extra cache fields or public cache API are needed.


## Constraint kinds (total rows)

These totals include input checks and output bindings. Function call chains and source-line attribution are retained in each case's JSON.

| Case | Mul | RangeCheck | Equality | Comparison | Or |
| --- | ---: | ---: | ---: | ---: | ---: |
| `field_identity` | 0 | 0 | 1 | 0 | 0 |
| `u64_identity` | 0 | 65 | 1 | 0 | 0 |
| `constant_scalar_equality` | 0 | 0 | 1 | 0 | 0 |
| `constant_asset_equality` | 0 | 0 | 1 | 0 | 0 |
| `same_wire_asset_equality` | 0 | 288 | 1 | 0 | 0 |
| `poseidon_1` | 213 | 0 | 1 | 0 | 0 |
| `poseidon_2` | 240 | 0 | 1 | 0 | 0 |
| `poseidon_3` | 261 | 0 | 1 | 0 | 0 |
| `poseidon_4` | 297 | 0 | 1 | 0 | 0 |
| `poseidon_5` | 321 | 0 | 1 | 0 | 0 |
| `poseidon_6` | 354 | 0 | 1 | 0 | 0 |
| `poseidon_7` | 381 | 0 | 1 | 0 | 0 |
| `poseidon_8` | 402 | 0 | 1 | 0 | 0 |
| `poseidon_9` | 417 | 0 | 1 | 0 | 0 |
| `poseidon_10` | 459 | 0 | 1 | 0 | 0 |
| `poseidon_11` | 465 | 0 | 1 | 0 | 0 |
| `poseidon_12` | 504 | 0 | 1 | 0 | 0 |
| `hash_bytes_0` | 0 | 0 | 1 | 0 | 0 |
| `hash_bytes_1` | 0 | 9 | 1 | 0 | 0 |
| `hash_bytes_16` | 0 | 144 | 1 | 0 | 0 |
| `hash_bytes_31` | 0 | 279 | 1 | 0 | 0 |
| `hash_bytes_32` | 240 | 288 | 1 | 0 | 0 |
| `hash_bytes_33` | 240 | 297 | 1 | 0 | 0 |
| `hash_bytes_62` | 240 | 558 | 1 | 0 | 0 |
| `hash_bytes_63` | 480 | 567 | 1 | 0 | 0 |
| `hash_bytes_64` | 480 | 576 | 1 | 0 | 0 |
| `hash_bytes_96` | 720 | 864 | 1 | 0 | 0 |
| `nonzero_chain_0` | 0 | 0 | 1 | 0 | 0 |
| `nonzero_chain_1` | 0 | 0 | 1 | 0 | 0 |
| `nonzero_chain_2` | 248 | 0 | 1 | 0 | 0 |
| `nonzero_chain_3` | 496 | 0 | 1 | 0 | 0 |
| `nonzero_chain_5` | 992 | 0 | 1 | 0 | 0 |
| `nonzero_chain_10` | 2,232 | 0 | 1 | 0 | 0 |
| `signing_key_identity` | 240 | 297 | 1 | 0 | 0 |
| `owner_hash` | 480 | 297 | 2 | 0 | 0 |
| `shielded_address_hash` | 960 | 594 | 2 | 0 | 0 |
| `utxo_hash` | 1,586 | 703 | 2 | 0 | 0 |
| `utxo_hash_with` | 861 | 703 | 1 | 0 | 0 |
| `default_ring` | 0 | 0 | 3 | 0 | 0 |
| `public_transfer_hash` | 777 | 643 | 1 | 0 | 0 |
| `data_output` | 237 | 65 | 1 | 0 | 0 |
| `unique_address` | 1,338 | 362 | 3 | 0 | 0 |
| `unique_output` | 1,596 | 362 | 3 | 0 | 0 |
| `unique_close` | 1,575 | 362 | 3 | 0 | 0 |
| `data_state_spend` | 2,178 | 768 | 10 | 0 | 0 |
| `data_state_update` | 2,415 | 833 | 10 | 0 | 0 |
| `data_state_close` | 2,113 | 1,056 | 9 | 0 | 0 |
| `unique_state_spend` | 2,199 | 768 | 10 | 0 | 0 |
| `unique_state_update` | 2,454 | 833 | 10 | 0 | 0 |
| `unique_state_close` | 2,974 | 1,056 | 10 | 0 | 0 |
| `unique_state_burn` | 2,134 | 1,056 | 9 | 0 | 0 |
| `array_vec_u64_1` | 0 | 65 | 1 | 0 | 0 |
| `array_vec_u64_5` | 0 | 325 | 1 | 0 | 0 |
| `token_inputs_1` | 1,350 | 834 | 9 | 2 | 0 |
| `token_inputs_2` | 2,110 | 1,668 | 148 | 4 | 0 |
| `token_inputs_5` | 4,387 | 4,170 | 364 | 10 | 3 |
| `balance_baseline` | 9 | 198 | 4 | 4 | 1 |
| `balance_arithmetic_baseline` | 0 | 323 | 2 | 0 | 0 |
| `balance_complete_baseline` | 1,515 | 264 | 7 | 4 | 1 |
| `balance_private_baseline` | 2,481 | 1,434 | 8 | 4 | 1 |
| `balance_deposit` | 18 | 266 | 6 | 8 | 2 |
| `balance_arithmetic_deposit` | 6 | 585 | 3 | 4 | 1 |
| `balance_complete_deposit` | 1,830 | 266 | 9 | 8 | 2 |
| `balance_private_deposit` | 3,276 | 1,436 | 11 | 8 | 2 |
| `balance_transfer` | 11 | 397 | 6 | 10 | 2 |
| `balance_arithmetic_transfer` | 2 | 650 | 4 | 6 | 1 |
| `balance_complete_transfer` | 1,535 | 463 | 9 | 10 | 2 |
| `balance_private_transfer` | 2,981 | 1,633 | 11 | 10 | 2 |
| `balance_transfer_all` | 14 | 202 | 5 | 6 | 2 |
| `balance_arithmetic_transfer_all` | 5 | 651 | 3 | 4 | 1 |
| `balance_complete_transfer_all` | 1,520 | 268 | 8 | 6 | 2 |
| `balance_private_transfer_all` | 2,486 | 1,438 | 9 | 6 | 2 |
| `balance_withdraw` | 10 | 263 | 4 | 6 | 1 |
| `balance_arithmetic_withdraw` | 4 | 388 | 3 | 2 | 0 |
| `balance_complete_withdraw` | 1,804 | 329 | 7 | 6 | 1 |
| `balance_private_withdraw` | 2,770 | 1,499 | 8 | 6 | 1 |
| `balance_withdraw_all` | 13 | 198 | 4 | 4 | 1 |
| `balance_arithmetic_withdraw_all` | 7 | 323 | 3 | 0 | 0 |
| `balance_complete_withdraw_all` | 1,789 | 264 | 7 | 4 | 1 |
| `balance_private_withdraw_all` | 2,275 | 1,434 | 7 | 4 | 1 |
| `input_order_1` | 0 | 21 | 4 | 0 | 0 |
| `input_order_2` | 17 | 42 | 8 | 0 | 1 |
| `input_order_5` | 170 | 105 | 20 | 0 | 10 |
| `input_order_10` | 765 | 210 | 40 | 0 | 45 |
| `token_transaction_1` | 3,070 | 853 | 11 | 2 | 2 |
| `token_transaction_2` | 4,089 | 1,687 | 150 | 4 | 1 |
| `token_transaction_5` | 7,262 | 4,189 | 366 | 10 | 19 |

## Reading the cases

Poseidon varies the input arity from 1 through 12. `hash_bytes` packs up to 31 bytes directly into one big-endian field element without a Poseidon permutation (empty input returns zero). Each further chunk adds one two-input Poseidon permutation. This is a fixed-length encoding: length is not absorbed, so leading-zero aliases across different lengths must be separated by the caller's domain.

Nonzero chains use private values, so zero/nonzero selection is included. Initializing from the first element removes the unnecessary first selection/permutation: the one-element case previously cost 245 body rows. Owner and UTXO cases keep their protocol inputs private; `utxo_hash_with` receives precomputed owner/asset hashes.

Bounded-input cases sum the padded u64 slots with field additions. Token aggregation exposes the sum of spent-input hashes to retain their computation. Unique-address output cases include address initialization and expose data hashes, rather than full output UTXO hashes.

The amount-only balance baseline funds a source and reads both balances. Arithmetic cases include the SDK's actual private `balance.rs` by path in the generated crate, using a minimal HasBalance fixture to initialize two private u128 balances directly. They remove token setup, funding, hashing and amount-read narrowing, while retaining the API's validation, overflow/borrow checks, and asset checks. Public-transfer records and transferred counters are unused in arithmetic cases.

Complete balance cases retain both output UTXO hashes, the sum of all public-transfer record hashes (including the funding deposit), and both transferred counters. Private blindings prevent output hashes from becoming constants; tree IDs are zero. These cover token outputs and records, rather than a full transaction proof. The owner, asset and public-transfer account are constants in these original complete cases. `balance_private_*` repeats each operation with two private owners and private asset/account bytes, retaining the same output UTXO hashes, record hashes and transferred counters.

State lifecycle cases spend private UTXOs whose private state preimages must match their stored data hashes. Spend cases preserve state; update cases replace the private u64 state. Every case retains the spent-input hash. Live outputs and unique close markers expose full output UTXO hashes with private blindings. Close/burn cases withdraw the entire input balance to a private account first, retaining all public-transfer hashes; ordinary close and unique burn assert that no output remains. These cases exclude address creation, encryption and transaction aggregation.

Input-order cases retain every ordered hash, nullifier, latest tree ID and availability flag, including dummy slots, so the measurement covers metadata movement and stable ordering. Capacities are 1, 2, 5 and 10; a 20-slot experiment was stopped because symbolic selection compilation remained expensive and is not included as a completed measurement. Token-transaction cases retain the complete private transaction hash for private input UTXOs and a private context; the public-input wrapper returns that hash directly to isolate SDK transaction assembly.

## Xark equality finding

The baseline equality controls retained one body row for equal constant scalars and 32 for identical assets or the same private asset wire. The array RequireEqCircuit implementation dispatches each byte to the scalar intrinsic. Xark now skips identically-zero differences in `crates/frontend/src/builder.rs::emit_require_eq`, matching the existing gated behavior. All three controls now have zero body rows. SDK asset validation remains in place; distinct private wires still require equality, and unequal constants remain unsatisfiable.

## Reproduce

From the workspace root, set `XARK_SOURCE` to the dependency checkout and place the matching `xark` CLI on `PATH`:

```sh
python3 sdk-libs/circuit/benches/profile_primitives.py --write-report
```

Run one case or inspect its source/function/kind breakdown:

```sh
python3 sdk-libs/circuit/benches/profile_primitives.py --case poseidon_2
xark profile target/benchmarks/spr-circuit/cases/poseidon_2 \
  --out target/benchmarks/spr-circuit/profiles/poseidon_2
jq '{total, kinds, functions, lines}' target/benchmarks/spr-circuit/poseidon_2.json
```

The one- and three-element chain cases also generate compiled-circuit acceptance tests for every zero/nonzero position pattern, rejecting a changed expected hash:

```sh
xark test target/benchmarks/spr-circuit/cases/nonzero_chain_1
xark test target/benchmarks/spr-circuit/cases/nonzero_chain_3
```

The data/unique state-update cases generate native-versus-compiled acceptance tests, including rejection of a wrong state preimage or output hash:

```sh
xark test target/benchmarks/spr-circuit/cases/data_state_update
xark test target/benchmarks/spr-circuit/cases/unique_state_update
```

Ordering tests cover every five-slot dummy pattern and all metadata. Transaction tests compare native/compiled hashes across every nonempty real/dummy pattern and reject changed hashes or either nondefault ring field in real and dummy slots:

```sh
xark test target/benchmarks/spr-circuit/cases/input_order_5
xark test target/benchmarks/spr-circuit/cases/token_transaction_1
xark test target/benchmarks/spr-circuit/cases/token_transaction_5
```

Generated entrypoint crates, raw per-constraint profiles and aggregated JSON stay under `target/benchmarks/spr-circuit/`. No proving keys are generated. Function counts include callees and overlap. Source attribution currently refers to the generated entrypoint lines; the call chains identify primitive internals.

Full escrow/withdraw circuit profiles belong in [`sdk-tests/timelock-escrow/program/benches/BENCHMARKS.md`](../../../sdk-tests/timelock-escrow/program/benches/BENCHMARKS.md).
