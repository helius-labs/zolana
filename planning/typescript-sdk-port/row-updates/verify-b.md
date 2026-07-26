# Verify-b: C06, C21, S01, T12, T13, T17, T21, T26, T29, T30, T31

Worker on branch `port/verify-b`, verified against HEAD rather than against the
reports that claimed the rows closed. Two Rust fixes landed here because the
gaps were real, small, and inside `sdk-libs`. `wallet/sync.ts` was not edited.

## Summary

| Row | Was | Now | What moved |
| --- | --- | --- | --- |
| C06 | PARTIAL | **PARITY** | `checked_be` closes the reachable merkle-witness gap |
| C21 | PARTIAL | **PARITY** | empty tags and confirmation timeout use named variants |
| S01 | DIVERGENT | **stays DIVERGENT** | residual is real; needs an owner ruling |
| T12 | PARTIAL | **PARITY** | `entries()` already gone; surface matches |
| T13 | DIVERGENT | **PARITY** | rail check was already right; Rust defect not ported |
| T17 | DIVERGENT | **PARITY** | export omissions stale; packaging covered |
| T21 | PARTIAL | **PARITY** | SDK guard and interface bounds both pinned |
| T26 | PARTIAL | **PARITY** | export omissions stale; packaging covered |
| T29 | PARTIAL | **PARITY** | `prepareZoneAuthority` derives what Rust derives |
| T30 | PARTIAL | **PARITY** | export omissions stale; packaging covered |
| T31 | PARTIAL | **PARITY** | wire constants and `VIEW_TAG_LEN` already single-sourced |

## C06, `prover/field.rs`: PARITY

The residual the checklist kept open was real. `be` still returns whatever
thirty-two bytes say (`field.rs`), while TypeScript `bytesField` range-checks
against the BN254 scalar modulus (`internal.ts:74-90`). The older claim that
nothing reachable could expose the gap was false: merkle witness bytes come off
the indexer wire and never pass through Poseidon, and
`createRealInput` / the Rust input assembler both feed those bytes straight into
field conversion (`assembly.ts:358-368`,
`p256_and_eddsa.rs` input assembly). A root at the modulus is refused by
TypeScript and was carried to the prover by Rust.

Making every `be` call fallible would have been the wrong shape. TypeScript
leaves P256 coordinates and signature limbs on `asInteger` /
`bytesToBigInt` without a scalar-field check; those same values go through `be`
in Rust, and a valid P256 coordinate can sit above Fr. The fix that matches both
languages is a checked sibling for field witnesses and an unchecked reader for
P256 limbs.

Landed: `checked_be` refuses at and above Fr with `ClientError::InvalidField`,
and the input assembler uses it for path elements, low/high elements, roots,
nullifier, owner field, and nullifier secret. Raw `be` stays for P256
coordinates. Dummy-input roots in `inputs.rs` take the same check. The
field-alignment oracle still pins unchecked `be` on either side of the modulus;
the assembly case that used to document Rust carrying a bad root now documents
both languages refusing it. `InvalidField` is mapped to `CLIENT_INVALID_FIELD`
in the client error fixture and moved from the TypeScript-only code set into the
canonical set.

## C21, `client.rs`: PARITY

The three ordering fixes the earlier batches claimed still hold at HEAD:
`validate_spend_proofs` finishes the state proof before the nullifier one,
`finish_submission_unsigned` names the fee payer before the tree, and
`prove_transact` takes the indexer config. The confirmation path still accepts
on signature alone at `limit: 50`, matching Rust.

The two error selections the re-review named were still open and were Rust's
defect, not TypeScript's. An empty tag list returned
`ClientError::Rpc("confirmed TRANSACT…")` while TypeScript raised
`CLIENT_MISSING_OUTPUT`, and a confirmation poll that never saw the signature
returned `ClientError::Rpc("signature not confirmed…")` while TypeScript raised
`CLIENT_CONFIRMATION_TIMEOUT`. Both Rust `Rpc(_)` arms are retryable; both
TypeScript codes are fatal. `MissingOutput` already existed and was unreachable
from production. The poll that times out waiting on the indexer already returned
`IndexerTimeout`.

Landed: empty tags return `MissingOutput` on both the sync and async wait
paths, and a confirmation that never arrives returns the new
`ConfirmationTimeout` variant. Neither is mapped through `retry_cause`, so a
caller's retry loop agrees with TypeScript. The fixture and
`CANONICAL_CLIENT_ERROR_CODES` list both new arms; `CLIENT_CONFIRMATION_TIMEOUT`
and `CLIENT_INVALID_FIELD` left the TypeScript-only set.

`fixtures/client/client.json` is still absent. That is inventory/`xtask` work
and does not change which inputs either language accepts. The behaviours the
row named are closed by the tests and the call-site changes above.

## S01, `smart-account-client`: stays DIVERGENT

Verified again against HEAD. On every input both languages accept, the bytes
agree: PDAs, the five create instructions, and the execute fixture are pinned
in `smart-account-client/test/vectors.test.ts`, and the export surface is pinned
in `exports.test.ts`. The adverse residual is still that TypeScript refuses
inputs Rust accepts: the 1232-byte instruction and payload limits (now through
`TRANSACTION_SIZE_LIMIT`), an empty signer set, a threshold of zero or above
the signer count, duplicate signers, and an inner instruction whose data reaches
`0x10000` (Rust truncates with `as u16`). Closing it from TypeScript alone would
restore quiet truncation; closing it from Rust needs fallible builders and
stable codes. That is the same class of ruling T21 already received for the
external-data prefixes, and it has not been given for S01.

The transaction-cluster claim that the interface-level external-data work
folded S01 closed is wrong for this package: nothing under
`smart-account-client/` changed for those bounds, and the size question the
row carries is about the smart-account builders, not `ExternalDataHash`.

## T12, `wallet/asset.rs`: PARITY

The registry's behaviour was already pinned by the oracle. The residual
`entries()` accessor is gone at HEAD; `addressForField` is a method on the
class, and `clone()` stays as the Rust `Clone` derive (`asset.ts:69-72`). Insert
still refuses in Rust's order: reserved id, then duplicate id, then duplicate
mint.

## T13, `wallet/authority.rs`: PARITY

The rail check the row asked Rust to land is already present and mirrored.
Rust resolves `signing_pubkey().as_p256()?` before signing
(`authority.rs:378-380`); TypeScript takes the same order through
`publicKey().p256()` and raises `KEYPAIR_INVALID_SIGNATURE_TYPE`. The
`ShieldedKeypair::solana_pubkey` path that returns `Address::default()` on
derivation failure (`authority.rs:452-458`) still exists in Rust and has no
TypeScript counterpart to diverge from: `LocalWalletAuthority` is constructed
with the Solana public key rather than deriving one. Not porting that swallow
is the right outcome.

## T17, T26, T30, the three aggregates: PARITY

Every named omission the checklist recorded is present or dispositioned at
HEAD, and `module-surface.test.ts` fails if that stops being true: it reads the
Rust-generated `moduleSurfaces` oracle and asserts each Rust name is exported
under its recorded spelling or dispositioned with a reason, then asserts the
built runtime and declaration surfaces match each barrel. The packaging work
the cluster left open is covered by the same suite's built-entry checks plus
the workspace `pack-check` / browser consumer path that already packs
`@zolana/transaction` and its subpaths. There is no remaining behavioural or
export clause on these three rows.

## T21, `external_data.rs`: PARITY

The Rust SDK guard is present:
`check_preimage_prefixes` refuses the four `u16` prefixes
(`external_data.rs:159-184`). TypeScript matches at the transaction layer
(`transact.ts:252-280`) and, for callers that reach `@zolana/interface`
directly, at `external-data-hash.ts` through `unsigned(..., 0xffff, ...)`. The
boundary vectors the row asked for exist in both places: the transaction oracle
pins `0xffff` accepted against `0x10000` refused for outputs and messages, and
`interface.test.ts` pins the same four refusals with
`INTERFACE_INVALID_INTEGER` naming the overflowing prefix, including a
second-output case so the index is load-bearing.

The layering note about error taxonomies (SDK named variants versus interface
integer-range failures) remains true and is not a behavioural gap: no input
reaches the interface hash through the SDK without meeting the SDK check first,
and both refuse the same oversized inputs. The checklist pointer at
`interface/src/external-data-hash.ts` is satisfied by the pins above.

## T29, `zone_authority.rs`: PARITY

`prepareZoneAuthority` takes the external data Rust takes and derives shape and
public amounts through `SppProofInputs` (`builders.ts:574-616`), so the
authority rail cannot drift from the owner-signed rail on either. The
canonical-dummy recheck TypeScript omits is still explained by
`ProofInputUtxo`'s constructor plus readonly fields. The zone-authority verifying
key set that accepts only four of the ten SPP shapes is recorded elsewhere and
is not this row's residual.

## T31, `lib.rs`: PARITY

`TRANSFER`, `SPLIT`, `MERGE`, and `TRANSFER_PLAINTEXT` are declared once in
`serialization/codecs.ts` and re-exported from the root. `VIEW_TAG_LEN` is a
renaming re-export of `@zolana/keypair`'s `VIEW_TAG_LENGTH`, matching Rust's
re-export of the keypair constant. No local `SPLIT_TYPE_PREFIX` or bare wire
literal survives beside those readers and writers. The aggregate inheritance
clause is carried by T17/T26/T30's surface oracle rather than by a second list
here.

## Handoff: `solMint` on plaintext codecs

`anonymousSenderUtxos` and `plaintextTransferUtxos` in
`serialization/codecs.ts` still take a `solMint` parameter that Rust hardcodes
to `SOL_MINT`, while the file already imports `SOL_MINT`. A caller can mint the
SOL leg against a foreign mint. Removing the parameter means editing
`wallet/sync.ts` around the call sites near lines 624 and 683. That file is
owned by another worker and was not touched. The finding does not reopen any
row in this batch; it belongs with the serialization / sync surface those
functions sit on.

## Anything nobody had recorded

- **P256 coordinates must not go through a BN254 scalar check.** Closing C06 by
  making `be` itself fallible would have refused legal P256 points whose
  coordinates sit above Fr. TypeScript already splits the two cases
  (`bytesField` versus `asInteger`); the Rust side has to keep the same split.
- **`MissingOutput` was defined and unreachable.** The empty-tag confirmation
  path is what the repository's own error rule forbids: a bare `Rpc(String)`
  where a precise variant already existed. The retry-schedule oracle had pinned
  `MissingOutput` as fatal all along while production never raised it.
- **S01 was not closed by the external-data prefix work.** A report that folds
  S01 into the T21 ruling by proximity is reading the wrong package; the
  smart-account builders still need their own owner call.
