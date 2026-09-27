# Asset Invariants

Covers `Asset` of `src/circuit/protocol/asset.rs`: `hash`, `sol`, `constant`, `DataHash`, and
its `Assert` and `Select` impls, against the native `zolana-hasher` `hash_bytes` and
`zolana-transaction` `SOL_MINT`. Invariants every type shares live in `cross-cutting.md`. ID
prefix: `INV-ASSET`; the tests live in `tests/unit/protocol/asset/`.

The fixtures in `tests/unit/protocol/asset/fixtures.rs` take `Mint` proof inputs, which
instantiate through `src/conversion/asset.rs` into 32 byte variables, each with the 9-row
range check "a byte proof input does not fit in 8 bits" (288 rows per mint, no hashing).
`AssetHash` asserts `mint.hash() == hash` with "the asset hash is hash_bytes of the mint"
(wire 1 is `hash`), `AssetDataHash` does so through `DataHash::hash`, `HashedTwice` asserts
it for the mint and a clone, `SolHash` for `Asset::sol()`, `Equal`, `EqualIf`, `IsEqual` and
`NotEqual` compare two mints with "the assets are equal" (`IsEqual`: "the claim is whether
the assets are equal"), `EqualsConstant` compares a mint with `Asset::constant(USDC)`, and
`Selected` hashes `Asset::select(condition, if_true, if_false)`. `Single` and `Pair` only
instantiate. The vectors are SOL (32 zero bytes), USDC (32 bytes of 4), 32 bytes of 255,
bytes 0..31 ascending, and ascending with byte 0 or byte 31 set to 255: the last two differ
from ascending only in the first and only in the second packed chunk (31 + 1 bytes).

## Asset (`hash`, `sol`, `constant`, `DataHash`)

### Native equivalence
- [x] **INV-ASSET-01: the hash of every mint is the native hash_bytes of its 32 bytes**
  - Covered by: `tests/unit/protocol/asset/native.rs` `every_mint_hashes_to_the_native_hash_bytes_of_its_32_bytes`; `tests/unit/protocol/asset/properties.rs` `every_mint_hashes_to_its_native_hash_natively_and_in_r1cs` (property)
  - Kind: native equivalence
  - Statement: for every mint vector and every random mint, the native value of `Asset::hash` of the instantiated `Mint` is exactly `zolana_hasher::primitives::hash_bytes(mint.asset)`.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`), `src/conversion/asset.rs:8-24` (`fn instantiate`, `fn asset`), `src/circuit/builtins/gadgets/hash_bytes.rs:10-32` (`fn hash_bytes`, `fn packed`)
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/asset/native.rs`, `tests/unit/protocol/asset/properties.rs`

- [x] **INV-ASSET-02: the R1CS claim wire of every honest assignment is the native hash**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `every_mint_satisfies_every_row_with_its_native_hash_on_the_claim_wire`
  - Kind: native equivalence
  - Statement: for every mint vector, wire 1 of the exported `AssetHash` assignment is exactly `hash_bytes(mint.asset)`.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`)
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

### Semantics
- [x] **INV-ASSET-03: a constant asset hashes as the instantiated mint**
  - Covered by: `tests/unit/protocol/asset/native.rs` `every_mint_hashes_to_the_native_hash_bytes_of_its_32_bytes`
  - Kind: semantics
  - Statement: for every mint vector, the value of `Asset::constant(&mint.asset).hash()` is exactly the native value of the instantiated mint's hash.
  - Location: `src/circuit/protocol/asset.rs:34-36` (`fn constant`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/asset/native.rs`

- [x] **INV-ASSET-04: the data hash of an asset is its asset hash**
  - Covered by: `tests/unit/protocol/asset/native.rs` `every_mint_hashes_to_the_native_hash_bytes_of_its_32_bytes`; `tests/unit/protocol/asset/native.rs` `every_mint_holds_natively_with_its_native_hash`
  - Kind: semantics
  - Statement: for every mint vector, `DataHash::hash` of the asset is exactly `Asset::hash`, and the `AssetDataHash` fixture holds natively with the native hash.
  - Location: `src/circuit/protocol/utxo/data.rs:59-63` (`impl DataHash for Asset`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/asset/native.rs`

- [x] **INV-ASSET-05: sol is the all-zero SOL mint, the default and the placeholder**
  - Covered by: `tests/unit/protocol/asset/native.rs` `sol_is_the_all_zero_sol_mint_and_the_default_and_placeholder_asset`
  - Kind: semantics
  - Statement: `SOL_MINT` is exactly 32 zero bytes and `Mint::SOL.asset`; `Mint::placeholder()` is exactly `Ok(Mint::SOL)`; `Asset::sol()`, `Asset::default()` and `Asset::constant(&SOL_MINT)` all hash to exactly `hash_bytes([0; 32])`, which is not 0.
  - Location: `src/circuit/protocol/asset.rs:38-40` (`fn sol`), `src/circuit/protocol/asset.rs:67-71` (`impl Default`), `src/conversion/asset.rs:26-30` (`impl Placeholder for Mint`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/asset/native.rs`

- [x] **INV-ASSET-06: distinct mints have distinct hashes**
  - Covered by: `tests/unit/protocol/asset/native.rs` `distinct_mints_have_distinct_hashes`
  - Kind: semantics
  - Statement: for every one of the 15 distinct pairs of mint vectors, including a change in only the first and in only the last byte, the two asset hashes differ.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/asset/native.rs`

- [x] **INV-ASSET-07: every mint holds natively with its native hash**
  - Covered by: `tests/unit/protocol/asset/native.rs` `every_mint_holds_natively_with_its_native_hash`; `tests/unit/protocol/asset/properties.rs` `every_mint_hashes_to_its_native_hash_natively_and_in_r1cs` (property)
  - Kind: semantics
  - Statement: for every mint vector and every random mint, the native run of `AssetHash` and of `AssetDataHash` with `hash = hash_bytes(mint.asset)` returns exactly `Ok(())`.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/protocol/asset/native.rs`, `tests/unit/protocol/asset/properties.rs`

### Error
- [x] **INV-ASSET-08: a claimed hash of another mint breaks exactly the hash rule natively**
  - Covered by: `tests/unit/protocol/asset/native.rs` `a_claimed_hash_of_another_mint_breaks_exactly_the_hash_rule_natively`; `tests/unit/protocol/asset/properties.rs` `a_hash_claimed_for_another_mint_is_refused_natively_and_in_r1cs` (property)
  - Kind: error
  - Statement: for every ordered distinct pair of mint vectors and every random pair of distinct mints, the native run of `AssetHash` with the other mint's hash returns exactly `RuleBroken("the asset hash is hash_bytes of the mint")` located in `fixtures.rs`.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative + property; `tests/unit/protocol/asset/native.rs`, `tests/unit/protocol/asset/properties.rs`

### Constraint
- [x] **INV-ASSET-09: the asset hash fixture has a pinned size and digest and no public input**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `the_asset_hash_fixture_has_a_pinned_size_digest_and_no_public_input`
  - Kind: constraint
  - Statement: the `AssetHash` export has exactly 529 constraints (288 byte rows, 240 rows of one two-input Poseidon over the two packed chunks, 1 claim row) and 530 variables, exactly 0 public inputs and 0 public outputs, 529 private inputs, and sha256 `7962528c9518dc8cfc42e725d60daece87503868f6ed62fd749c2e49fac013c7`.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`), `src/circuit/builtins/gadgets/hash_bytes.rs:10-32`
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

- [x] **INV-ASSET-10: a constant asset hash adds exactly one row and no variable**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `a_constant_asset_hash_is_one_row_with_the_hash_on_variable_zero`
  - Kind: constraint
  - Statement: the `SolHash` export is exactly the header (2 wires, 0 public outputs, 0 public inputs, 1 private input, 1 constraint) and the row A = {0: hash_bytes([0; 32]), 1: -1}, B = {0: 1}, C = {}; the SOL hash sits on variable 0.
  - Location: `src/circuit/protocol/asset.rs:34-44` (`fn constant`, `fn sol`, `fn hash`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

- [x] **INV-ASSET-11: a mint and its clones share one hash**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `a_mint_and_its_clone_share_one_hash_so_the_second_claim_costs_one_row`
  - Kind: constraint
  - Statement: the `HashedTwice` export, which hashes a mint and its clone, has exactly the constraint count of `AssetHash` plus 1 and exactly its variable count.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`, the shared `OnceCell`), `src/circuit/builtins/field/var.rs:116-125` (`fn cached`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

### Completeness
- [x] **INV-ASSET-12: every mint satisfies every row of the asset hash fixture**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `every_mint_satisfies_every_row_with_its_native_hash_on_the_claim_wire`; `tests/unit/protocol/asset/properties.rs` `every_mint_hashes_to_its_native_hash_natively_and_in_r1cs` (property)
  - Kind: completeness
  - Statement: for every mint vector and every random mint, the honest `AssetHash` assignment leaves no exported row unsatisfied.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`)
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/asset/r1cs.rs`, `tests/unit/protocol/asset/properties.rs`

### Soundness
- [x] **INV-ASSET-13: a claimed hash of another mint breaks exactly the hash row**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `a_claimed_hash_of_another_mint_breaks_exactly_the_hash_row`; `tests/unit/protocol/asset/properties.rs` `a_hash_claimed_for_another_mint_is_refused_natively_and_in_r1cs` (property)
  - Kind: soundness
  - Statement: for every ordered distinct pair of mint vectors, the `AssetHash` assignment with wire 1 set to the other mint's hash leaves exactly row 528 as the first unsatisfied row, and `check_tampered` returns exactly `ProofInputsBreakRule` at row 528 with the hash rule; so does every random pair in the export.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/protocol/asset/r1cs.rs`, `tests/unit/protocol/asset/properties.rs`

- [x] **INV-ASSET-14: every mint byte is range-checked to 8 bits**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `every_mint_byte_is_range_checked_to_8_bits`
  - Kind: soundness
  - Statement: for each of the 32 byte variables of a mint, setting it to its value plus 256 makes `check_tampered` return exactly `ProofInputsBreakRule` at row 9 * index + 8 with "a byte proof input does not fit in 8 bits".
  - Location: `src/conversion/bytes.rs:10-31` (`fn instantiate`, `range_check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/asset/r1cs.rs`

- [x] **INV-ASSET-15: no private variable of the asset hash fixture is free**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `no_private_variable_of_the_asset_hash_fixture_is_free`
  - Kind: soundness
  - Statement: for every mint vector, `check_private_variables(AssetHash)` reports exactly 529 constraints, 529 private variables, no free and no tolerated variable.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`), `src/conversion/bytes.rs:10-31`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/asset/r1cs.rs`

- [ ] **INV-ASSET-16: Picus finds the asset hash fixed by the mint bytes**
  - Partial coverage: `tests/unit/protocol/asset/picus.rs` `picus_finds_no_second_asset_hash_for_one_mint` runs Picus (cvc5) on the Picus export with the claim promoted, bounded at 60 s, and asserts only that it finds no counterexample: the run ends `Unknown`. The 288 byte range-check rows alone exceed the bound (the hash-free `IsEqual` and owner instantiation exports also end `Unknown` at 150 s), so determinism is not proven; INV-ASSET-15 is the hermetic substitute.
  - Kind: soundness
  - Statement: Picus reports the `AssetHash` Picus export with wire 1 promoted to an output exactly `Safe`.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`)
  - Severity: Medium
  - Suggested test: external (Picus); `tests/unit/protocol/asset/picus.rs`

### Shape
- [x] **INV-ASSET-17: setup from the SOL placeholder and proving synthesize the same rows**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `every_mint_satisfies_every_row_with_its_native_hash_on_the_claim_wire`; `tests/unit/protocol/asset/r1cs.rs` `a_mint_and_its_clone_share_one_hash_so_the_second_claim_costs_one_row`
  - Kind: shape
  - Statement: for every mint vector, `check_constraints(AssetHash)` returns exactly `Ok(529)` (setup from `Mint::SOL` and proving build the same matrices), and `check_constraints(HashedTwice)` returns exactly `Ok(530)`.
  - Location: `src/conversion/asset.rs:8-30`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

### Interop
- [x] **INV-ASSET-18: snarkjs accepts every honest asset hash witness and rejects a wrong claim**
  - Covered by: `tests/unit/protocol/asset/external.rs` `snarkjs_accepts_every_mint_and_rejects_a_claimed_hash_of_another_mint`
  - Kind: interop
  - Statement: for every mint vector, `snarkjs wtns check` on the `AssetHash` export returns exactly `WITNESS IS CORRECT` for the honest assignment and `WITNESS IS NOT CORRECT` with wire 1 set to the next vector's hash.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/asset/external.rs`

- [x] **INV-ASSET-19: snarkjs proves and verifies the asset hash circuit**
  - Covered by: `tests/unit/protocol/asset/external.rs` `snarkjs_proves_and_verifies_the_asset_hash_circuit`
  - Kind: interop
  - Statement: snarkjs Groth16 setup, prove and verify on the `AssetHash` export and the ascending mint's assignment verifies with exactly the public signals `[]`.
  - Location: `src/circuit/protocol/asset.rs:42-44` (`fn hash`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/asset/external.rs`

## Assert (`is_equal`, `assert_equal`, `assert_equal_if`, `assert_not_equal`)

### Semantics
- [x] **INV-ASSET-20: native assert_equal holds exactly for equal mints**
  - Covered by: `tests/unit/protocol/asset/native.rs` `assert_equal_holds_exactly_for_equal_mints_natively`
  - Kind: semantics
  - Statement: for every mint vector against itself, native `Equal` returns exactly `Ok(())`; for every distinct pair it returns exactly `RuleBroken("the assets are equal")`.
  - Location: `src/circuit/protocol/asset.rs:78-84` (`fn assert_equal`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/asset/native.rs`

- [x] **INV-ASSET-21: native assert_not_equal holds exactly for distinct mints**
  - Covered by: `tests/unit/protocol/asset/native.rs` `assert_not_equal_holds_exactly_for_distinct_mints_natively`
  - Kind: semantics
  - Statement: for every distinct pair of mint vectors, native `NotEqual` returns exactly `Ok(())`; for every mint against itself it returns exactly `RuleBroken("the assets are equal")`.
  - Location: `src/circuit/protocol/asset.rs:73-76` (`fn is_equal`; `assert_not_equal` is the `Assert` default)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/asset/native.rs`

- [x] **INV-ASSET-22: native is_equal is true exactly for equal mint bytes**
  - Covered by: `tests/unit/protocol/asset/native.rs` `is_equal_is_true_exactly_for_equal_mints_natively`; `tests/unit/protocol/asset/properties.rs` `is_equal_holds_exactly_for_equal_mint_bytes` (property)
  - Kind: semantics
  - Statement: for every pair of mint vectors and every random pair of mints, native `IsEqual` holds exactly for the claim `left.asset == right.asset` and returns exactly `RuleBroken("the claim is whether the assets are equal")` for the opposite claim; the asset id plays no part.
  - Location: `src/circuit/protocol/asset.rs:74-76` (`fn is_equal`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative + property; `tests/unit/protocol/asset/native.rs`, `tests/unit/protocol/asset/properties.rs`

- [x] **INV-ASSET-23: native assert_equal_if checks exactly when the condition holds**
  - Covered by: `tests/unit/protocol/asset/native.rs` `assert_equal_if_checks_exactly_when_the_condition_holds_natively`
  - Kind: semantics
  - Statement: for every pair of mint vectors, native `EqualIf` with the condition false returns exactly `Ok(())`; with the condition true it returns `Ok(())` for equal mints and exactly `RuleBroken("the assets are equal")` for distinct ones.
  - Location: `src/circuit/protocol/asset.rs:86-98` (`fn assert_equal_if`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/asset/native.rs`

- [x] **INV-ASSET-24: a constant asset equals exactly its own mint**
  - Covered by: `tests/unit/protocol/asset/native.rs` `a_constant_asset_equals_exactly_its_own_mint_natively`
  - Kind: semantics
  - Statement: for every mint vector, native `EqualsConstant` returns exactly `Ok(())` for USDC and exactly `RuleBroken("the assets are equal")` for every other mint.
  - Location: `src/circuit/protocol/asset.rs:34-36` (`fn constant`), `src/circuit/protocol/asset.rs:78-84` (`fn assert_equal`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/asset/native.rs`

### Constraint
- [x] **INV-ASSET-25: assert_equal compares the two packed chunks in one row each**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `assert_equal_compares_the_two_packed_chunks_in_one_row_each`
  - Kind: constraint
  - Statement: the `Equal` export has exactly the 576 rows of `Pair` plus 2 and exactly its 577 variables; the first chunk's row is 576, labelled "the assets are equal".
  - Location: `src/circuit/protocol/asset.rs:78-84` (`fn assert_equal`), `src/circuit/builtins/gadgets/hash_bytes.rs:23-32` (`fn packed`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

- [x] **INV-ASSET-26: comparing with a constant asset costs exactly two rows and no variable**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `a_mint_other_than_the_constant_breaks_a_comparison_row`
  - Kind: constraint
  - Statement: the `EqualsConstant` export has exactly the 288 rows of `Single` plus 2 and exactly its 289 variables.
  - Location: `src/circuit/protocol/asset.rs:34-36`, `src/circuit/protocol/asset.rs:78-84`
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

- [x] **INV-ASSET-27: assert_not_equal costs exactly seven rows over two mints**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `assert_not_equal_refuses_equal_mints_while_proving_with_exactly_the_rule`
  - Kind: constraint
  - Statement: the `NotEqual` export has exactly 2 * 288 + 7 = 583 constraints and 583 variables, and `check_constraints` returns exactly `Ok(583)` for every distinct pair.
  - Location: `src/circuit/protocol/asset.rs:74-76` (`fn is_equal`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

### Soundness
- [x] **INV-ASSET-28: distinct mints break the row of their first differing chunk**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `assert_equal_compares_the_two_packed_chunks_in_one_row_each`
  - Kind: soundness
  - Statement: for every mint vector against itself, the `Pair` assignment leaves no `Equal` row unsatisfied; for every distinct pair, the first unsatisfied `Equal` row is exactly 576 when the first 31 bytes differ and exactly 577 otherwise.
  - Location: `src/circuit/protocol/asset.rs:78-84` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/asset/r1cs.rs`

- [x] **INV-ASSET-29: a mint other than the constant breaks a comparison row**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `a_mint_other_than_the_constant_breaks_a_comparison_row`
  - Kind: soundness
  - Statement: for every mint vector, the `Single` assignment leaves no `EqualsConstant` row unsatisfied for USDC; for every other mint the first unsatisfied row is exactly 288 when its first 31 bytes differ from USDC's and exactly 289 otherwise.
  - Location: `src/circuit/protocol/asset.rs:34-36`, `src/circuit/protocol/asset.rs:78-84`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/asset/r1cs.rs`

- [x] **INV-ASSET-30: assert_equal_if refuses distinct mints once the condition is set**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `assert_equal_if_refuses_distinct_mints_once_the_condition_is_set`
  - Kind: soundness
  - Statement: for every distinct pair with the condition false, `check_constraints(EqualIf)` returns exactly `Ok(579)`; setting the condition wire to 1 makes `check_tampered` return exactly `ProofInputsBreakRule` with "the assets are equal" at row 577 when the first 31 bytes differ and at row 578 otherwise.
  - Location: `src/circuit/protocol/asset.rs:86-98` (`fn assert_equal_if`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/asset/r1cs.rs`

- [x] **INV-ASSET-31: a flipped equality claim breaks exactly the claim row**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `a_flipped_equality_claim_breaks_exactly_the_claim_row`
  - Kind: soundness
  - Statement: for every mint against itself and every distinct pair, `check_constraints(IsEqual)` with the true claim returns exactly `Ok(n)` for the export's n constraints, and flipping the claim wire makes `check_tampered` return exactly `ProofInputsBreakRule` at row n - 1 with "the claim is whether the assets are equal".
  - Location: `src/circuit/protocol/asset.rs:74-76` (`fn is_equal`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/asset/r1cs.rs`

### Error
- [x] **INV-ASSET-32: proving assert_not_equal on equal mints fails with exactly the rule**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `assert_not_equal_refuses_equal_mints_while_proving_with_exactly_the_rule`
  - Kind: error
  - Statement: for every mint vector against itself, `check_constraints(NotEqual)` fails with a circuit error that is exactly `RuleBroken("the assets are equal")` located in `fixtures.rs`: the proving synthesis refuses before any row is compared.
  - Location: `src/circuit/protocol/asset.rs:74-76` (`fn is_equal`; `assert_not_equal` is the `Assert` default)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/asset/r1cs.rs`

## Select (`Asset::select`)

### Semantics
- [x] **INV-ASSET-33: the selected asset hashes to the chosen mint**
  - Covered by: `tests/unit/protocol/asset/native.rs` `select_hashes_to_the_chosen_mint_natively`
  - Kind: semantics
  - Statement: for every distinct pair, native `Selected` holds exactly with the hash of `if_true` under a true condition and of `if_false` under a false one, and returns exactly `RuleBroken("the asset hash is hash_bytes of the mint")` with the other mint's hash.
  - Location: `src/circuit/protocol/asset.rs:101-105` (`fn select`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/asset/native.rs`

### Constraint
- [x] **INV-ASSET-34: select costs exactly one row per byte**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `select_multiplies_once_per_byte_and_a_flipped_condition_breaks_the_first_differing_byte`
  - Kind: constraint
  - Statement: the `Selected` export has exactly 2 * 288 + 1 (the condition) + 32 (one select row per byte) + 240 (Poseidon) + 1 (claim) = 850 constraints and 851 variables.
  - Location: `src/circuit/protocol/asset.rs:101-105` (`fn select`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

### Completeness
- [x] **INV-ASSET-35: both conditions satisfy every select row**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `select_multiplies_once_per_byte_and_a_flipped_condition_breaks_the_first_differing_byte`
  - Kind: completeness
  - Statement: for every distinct pair and both conditions, `check_constraints(Selected)` with the chosen mint's hash returns exactly `Ok(850)`.
  - Location: `src/circuit/protocol/asset.rs:101-105` (`fn select`)
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/asset/r1cs.rs`

### Soundness
- [x] **INV-ASSET-36: a flipped condition breaks the select row of the first differing byte**
  - Covered by: `tests/unit/protocol/asset/r1cs.rs` `select_multiplies_once_per_byte_and_a_flipped_condition_breaks_the_first_differing_byte`
  - Kind: soundness
  - Statement: for every distinct pair and both conditions, flipping the condition wire in the honest assignment leaves exactly row 577 + i as the first unsatisfied row, where i is the first byte at which the two mints differ.
  - Location: `src/circuit/protocol/asset.rs:101-105` (`fn select`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/asset/r1cs.rs`

## Summary

- Total: 36 (Critical 12, High 16, Medium 8); covered 35, partial 1 (INV-ASSET-16, Picus
  `Unknown` within its bound); findings: none.
- No circom reference: the Equivalence column is native equivalence against `hash_bytes`
  (INV-ASSET-01, -02).
