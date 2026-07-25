# Zone-authority accepts six shapes it cannot prove

Queued for the client worker behind `C08` and `T23`. Closes a hazard recorded inside the
already-closed `C18`.

## The divergence

`ZoneAuthorityProver::build` resolves against `SPP_SUPPORTED_SHAPES`, which holds ten shapes.
`program-libs/interface/src/verifying_keys/` holds four zone-authority keys: `1_1`, `2_2`, `3_3`,
`4_4`. Both SDKs will therefore build a zone-authority request for 1x2, 2x3, 4x3, 5x3, 5x4, or 1x8,
and the caller learns at proving time that no key can verify it.

## Why this needs no ruling

It was raised as a question for the owner, whether to narrow the SDKs or generate the six missing
keys. Reading the specification made the question unnecessary. `docs/spec.md`, in the zone-authority
instantiation section following the sentence beginning "A default-zone UTXO can neither be spent nor
created", carries a table of supported shapes listing exactly four: 1 in 1 out, 2 in 2 out, 3 in 3
out, 4 in 4 out. The keys on disk match the specification, so the SDKs are the diverging side.

The four are not an arbitrary subset. A zone-authority transition proves no owner authorization and
cannot move value out of the zone, so it re-randomizes or reshuffles a fixed set of UTXOs rather
than splitting or merging them. Inputs equal outputs, and the missing six are exactly the non-square
members of the ten: 1x2, 2x3, 4x3, 5x3, 5x4, 1x8.

## The fix

Restrict the zone-authority path in both languages to the four square shapes and reject the rest
with a named error stating which shapes the rail supports. A caller asking for 2x3 cannot guess the
reason from a bare rejection.

Pin it with a test on each side: 1x1, 2x2, 3x3, and 4x4 build, and a non-square shape drawn from the
supported ten is refused. A shared vector is preferable to two independent tests.

Derive the accepted set from something that cannot drift from the keys if that is possible without
editing outside `sdk-libs`. Otherwise write the list with a comment naming the specification section
and the four key files it must agree with.

## Constraints

`sdk-libs/**` only. Adding the six missing keys is a `prover/` change and is now known to be wrong on
the merits rather than merely out of scope.

Breaking for callers passing a non-square shape, which the standing pre-1.0 ruling permits.

This is strictness the specification requires, not the port tightening past its original. The commit
message should say so, because the surrounding rows record the opposite pattern as a regression.
