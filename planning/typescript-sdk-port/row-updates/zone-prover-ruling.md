# Zone prover rows: deferral withdrawn

**The owner ruled on 2026-07-25 that the three zone prover paths are built during the parity phase rather than deferred to PKP-05. Rows C13, C14, and C18 change disposition from deferred to in scope. Row C07, the forester address append, keeps its `NOT_APPLICABLE` disposition.**

This file exists for the reconciler. It records a disposition change, not a review outcome, so no row moves to `PARITY` here and no verdict is claimed. The rows become ordinary open work owned by the client batch.

## What changes

| Row | Rust source | Was | Now |
| --- | --- | --- | --- |
| C13 | `sdk-libs/client/src/prover/transact/zone_eddsa.rs` | Deferred to PKP-05 | Open, owned by the client batch |
| C14 | `sdk-libs/client/src/prover/transact/zone_p256.rs` | Deferred to PKP-05 | Open, owned by the client batch |
| C18 | `sdk-libs/client/src/prover/zone_authority.rs` | Deferred to PKP-05 | Open, owned by the client batch |
| C07 | `BatchAddressAppendInputs` in `sdk-libs/client/src/prover/inputs.rs` | `NOT_APPLICABLE` | Unchanged |

## Why the deferral was withdrawn

The gap sits one step from the end of a working pipeline rather than at its boundary. `sdk-libs/ts/transaction/src/instructions/builders.ts` and the interface package already build zone instruction data and the prepared zone-authority object, so a TypeScript caller can assemble a complete zone transaction and then find no way to prove it. A capability missing at the edge of an SDK reads as scope; the same capability missing in the middle of a path that otherwise works reads as a defect, and callers hit it late.

Building now is also cheaper than the row count suggests. The Rust sources are 123, 152, and 166 lines, and `zone_eddsa.rs` is substantially the non-zone `eddsa.rs` with one extra zone hash in the public-input chain, and that chain is one the TypeScript prover already assembles. The types these paths consume and produce exist on both sides. What is missing is the step between: prepared data to prover request, request to response, response to proof.

## Why the forester row is different

C07 stays `NOT_APPLICABLE` on a fact rather than a preference. TypeScript ships no forester, so nothing in that language would call an `address-append` builder and nothing would read what it produced. The SDK would be exporting an instruction whose proof it has no way to generate.

Light Protocol landed in the same place for the same reason. Its `js/stateless.js/src/programs/system/layout.ts` decodes append, nullify, and address-insert inputs so an indexer can read them, and it stops there; a search of `js/` for a matching builder returns nothing. The rule that falls out of both is the same: decode any instruction that can appear in a transaction, and build only those whose inputs the SDK can produce for itself.

## What still has to happen in the cryptographic phase

Withdrawing the deferral does not empty PKP-05. Parity-phase evidence shows that TypeScript builds the same request bytes as Rust. It does not show that the resulting proof verifies against the intended statement and nothing else, which is the question PKP-05 exists to answer. The zone rails are where that distinction carries the most weight, because their public-input chain is shorter than the confidential one and the zone program field is the only value binding a proof to its zone. `proof-and-key-parity.md` now carries two zone-specific exit conditions: a proof built for one zone must not verify for another, and the anonymous chain must not be satisfiable by a confidential-chain assembly.

## Inventory conflict, resolved

`inventory-client.md:61` dispositioned the zone-authority prover as `port` and promised `src/prover/zone-authority.ts` and `fixtures/client/zone_authority.json`, neither of which existed, while the checklist deferred the same work. The audit at `quality-and-completeness-audit.md` flagged the disagreement and required one of the two to move. The checklist moves. The inventory was right.
