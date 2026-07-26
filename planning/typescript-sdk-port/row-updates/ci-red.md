# CI red: `tests / sdk-libs` and `tests / client integration`

Both jobs failed on the same unit test for the same reason. This was the whole
cause of both reds; they do not have separate roots. Fixing the mock brought
both recipes green locally (`just test-sdk-libs`,
`just test-client-integration`). Clippy on `zolana-client` with
`--features indexer-api` is clean.

## Root cause

`confirm_private_transaction_sync_waits_for_indexer` panicked at
`finish_submission_unsigned_sync_with` with `ClientError::InvalidField`.

Commit `d2fa0d60` (verify-b / C06) switched merkle-witness assembly from
unchecked `be` to `checked_be`, so indexer path elements, roots, and low/high
elements must be below the BN254 scalar modulus. That change is deliberate and
matches TypeScript `bytesField`. The mock nullifier response still used
`high_element: [u8::MAX; 32]`, which sits above Fr and is refused before the
dummy prove callback runs.

The JSON form at the old line 1634 is on the path that fails: finish fetches
spend proofs from the mock indexer, then `assemble` runs `checked_be` on
`high_element`. The in-memory `nullifier_proof` helper at the old line 1516
carried the same out-of-range value. That helper feeds `validate_spend_proofs`
today and did not trip this failure, but it would have broken the next
assemble-path test that reused it, so it got the same field-valid treatment.

## What changed

`BN254_SCALAR_MAX_BE` (`modulus - 1`, test-only) is defined in
`prover/field.rs` and used as the mock `high_element` in both the JSON
nullifier response and the in-memory helper. `[u8::MAX; 32]` stays in two
dedicated rejection tests:
`checked_be_accepts_below_modulus_and_refuses_at_and_above` for the unit check,
and `assemble_refuses_out_of_range_nullifier_high_element` for the finish /
assemble path that CI hit. `checked_be` itself was not weakened.

No production code changed. No TypeScript files were touched.

## Other fixtures

No other `sdk-libs/client` mock that `checked_be` reaches still carries an
out-of-range field value. Indexer mapping tests use small `bytes32(N)` patterns;
oracle helpers use `field_byte(...)` or `[1u8; 32]`. The field-alignment oracle
still pins unchecked `be` on `[0xff; 32]` as a length/value case, which is not
an assemble path.

## Checked and not the cause

The new `indexer-api` string-or-number integer visitors, `MissingOutput` /
`ConfirmationTimeout`, P256 prehash reduction, and zone-data hash normalisation
were not involved. Error-code stability was not the failure mode: both jobs
compiled and ran, then failed on the mock that fed `[u8::MAX; 32]` into
`checked_be`. The typescript fixture and merge-gate jobs were already fixed on
the base commit and were not re-investigated.
