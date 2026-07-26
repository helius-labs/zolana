# FND-D5: zero-length dummy ciphertext and P3 residuals

Worktree `zolana-ts-fnd-d5`, branch `port/fnd-d5`. Scope: `sdk-libs` only.

## Job One — F133 / D5 / F103 zero-length dummy ciphertext

### Reachability

The leak is real and reachable through the public authority rail.

`PreparedTransfer::finalize` took `dummy_len = 0` when `slots.iter().any(None)` was false and `dummy_recipient_count == 0`. A short payload of only `Some` entries (or `vec![]`) has no `None` to iterate, yet missing indices still take the `random_dummy_ciphertext(dummy_len)` arm. Reproduced:

- Honest `sign` with padding (`IN2_OUT3` change-only): lengths `[88, 88, 88]` — no leak.
- `finalize(..., vec![])` on `IN1_OUT2` change-only (pad count 0, sender slots only): lengths `[0, 0]` — leak on the wire if the caller continues to assemble.

`LocalWalletAuthority` / `sign` always pass `encode_confidential_slots` output of matching length, so the honest keypair rail never hit it. The authority rail's public `finalize` does.

TypeScript already indexes by output position (`payload[index] === undefined`), so the same short payload length-matches. Extra signatures and excess ciphertext slots stay under `match_rust` and were not changed; neither was found to leak.

### Fix

Rust now decides dummy length by final output position, matching TypeScript:

```rust
let needs_dummy_ciphertext = (0..outputs.len())
    .any(|index| slots.get(index).and_then(|slot| slot.as_ref()).is_none());
```

### Tests

- Rust: `short_finalize_payload_length_matches_real_ciphertexts`, `padded_finalize_keeps_real_and_dummy_ciphertext_lengths_equal` in `transfer.rs`.
- TypeScript: `padded finalize ciphertext lengths` in `transfer.test.ts` (padded shape and empty-payload finalize).

Addresses F137's gap: both languages now finalize with `padCount > 0` and assert equal real/dummy lengths.

## Job Two — P3 residuals

### Residual 1 — off-curve G2 at compress

**Disposition: keep TypeScript strict; deliberate TypeScript-only fail-fast.**

Solana's `alt_bn128_g2_compress_be` skips the G2 curve equation (SIMD-0129: compression is meant to pair with `sol_alt_bn128_group_op`, which validates). TypeScript calls `assertValidity()` and refuses the same bytes. Fixture id `off-curve-g2-compress-divergence` pins both outcomes with `disposition: "typescript-fail-fast"`.

This is not the dummy-ciphertext class: an off-curve G2 leaks nothing, and an assembled proof fails on-chain pairing. Rust cannot cheaply mirror the check without abandoning the syscall that is the point of the host path. No owner ruling needed unless the team wants Rust to add an optional pre-check.

### Residual 2 — unknown proof-response fields

**Disposition: keep shared acceptance (forward compatibility).**

Serde ignores unknown keys on `GnarkProofJson`; TypeScript reads named fields only. Both accept `unexpected_field`. The Go prover's `ProofJSON` is a closed set today (`ar`/`bs`/`krs` plus optional commitment limbs with `omitempty`), but additive fields are the normal evolution path for prover metadata. Rejecting in both languages would be new behaviour in two places at once with no soundness win — a wrong proof still fails verification. P3's rejection checklist line is the wrong bar for this surface. Fixture id `unknown-response-field` pins `disposition: "accept-forward-compat"`. No owner ruling required unless product wants a hard schema lock.

### Residual 3 — G2 `y1 == 0 && isLargest(y0)`

**Disposition: keep skipped; impossibility/intractability for prover-relevant points.**

Algebraic construction (solve `(x³ + b).c1 = 0` for `x ∈ Fp2`, then `y0 = ±sqrt((x³ + b).c0)`) finds on-curve points with `y.c1 == 0` at `x1 = 2`. Every such point fails the r-torsion check (`is_in_correct_subgroup_assuming_on_curve == false`); TypeScript `assertValidity` rejects with `bad point: not in prime-order subgroup`. Expected `|G2 ∩ locus|` is O(1) inside a ~2^254 group, so there is no short construction of a prime-order witness. Scalar search was the wrong tool; the skip is now backed by locus evidence rather than a failed search. Fixture row keeps `unavailable: true` with that reason and evidence block. Generator: `cargo run -p xtask --bin proof-response-parity` (optional `--probe-y1-zero`).

## Owner rulings

None required for the three P3 residuals under the dispositions above. Job One already had D5 / F103.
