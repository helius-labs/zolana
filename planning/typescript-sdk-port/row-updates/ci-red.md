# CI red: `tests / sdk-libs` and `tests / client integration`

Both jobs failed on the same unit test for the same reason. Fixing the mock
brought both recipes green locally (`just test-sdk-libs`,
`just test-client-integration`). Clippy on `zolana-client` with
`--features indexer-api` is clean.

## Root cause

`confirm_private_transaction_sync_waits_for_indexer` panicked at
`finish_submission_unsigned_sync_with` with `ClientError::InvalidField`.

Commit `d2fa0d60` (verify-b / C06) switched merkle-witness assembly from
unchecked `be` to `checked_be`, so indexer path elements, roots, and low/high
elements must be below the BN254 scalar modulus. That change is deliberate and
matches TypeScript `bytesField`. The mock nullifier response still used
`high_element: [u8::MAX; 32]`, which is above Fr and is now refused before the
dummy prove callback runs.

The same mock value lived in the in-memory `nullifier_proof` helper. That helper
only feeds `validate_spend_proofs` today and did not trip this failure, but it
would have broken the next assemble-path test that reused it.

## What changed

In `sdk-libs/client/src/client.rs` the mock high element is now a field-valid
`[1u8; 32]`, shared as `MOCK_HIGH_ELEMENT` by the JSON nullifier response and
the in-memory helper. Updating the test is the right fix: the production check
is correct, and the old fixture was only valid while Rust silently accepted
non-field bytes that TypeScript already rejected.

No production code changed. No TypeScript files were touched.

## Checked and not the cause

The new `indexer-api` string-or-number integer visitors, `MissingOutput` /
`ConfirmationTimeout`, P256 prehash reduction, and zone-data hash normalisation
were not involved. Error-code stability was not the failure mode: both jobs
compiled and ran, then failed on the mock that fed all-ones into `checked_be`.
The typescript fixture and merge-gate jobs were already fixed on the base
commit and were not re-investigated.
