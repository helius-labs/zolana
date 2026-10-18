# Custom rings after PR #427

This is a code review of the custom-ring delta with [PR #427](https://github.com/helius-labs/zolana/pull/427) treated as merged. It does not regrade the default ring or count key publication and deployment as code findings.

**Code verdict:** The known custom-ring blockers now have enforcing code and regression coverage. No reviewed path demonstrates inflation, double spend or an unproved auditor opening. This is a bounded code finding, not a proof that every witness is safe.

| Guarantee | Enforcing path | What the tests must establish |
|---|---|---|
| A policy proof governs the transfer SPP settles | [Policy transaction opening](../prover/server/custom_rings/circuits/policy/transaction.go) uses the same private transaction hash. [The ring processor](program/src/instructions/transact.rs) builds public inputs from its own account, selected roots and the forwarded transaction. | Valid shaped settlements, wrong public input, root and last-slot rejection. |
| Membership and escrow cannot be forged | [Registry circuits](../prover/server/custom_rings/circuits/registry) prove presence or absence under an accepted root. [List updates](program/src/instructions/update_members.rs) preserve escrow. [Key registration](program/src/instructions/register_key.rs) is the only setter and proves encryption to the auditor. | Forged path, missing leaf, escrow rewrite and bad registration rejection. |
| Auditor transfer and deposit data match settled notes | [Audit disclosure](../prover/server/custom_rings/circuits/base/audit.go) encrypts fields used in the commitments. [The ring program](program/src/instructions/forward.rs) now requires an audited deposit in every mode. | Valid audit openings, false fields, missing deposit proof and corrupt recipient payloads. Recipient delivery remains outside this proof. |
| Every permitted merge has an auditor opening | [The ring merge proof](../prover/server/circuits/spp_merge/ring.go) proves a registered owner record under the on-chain selected root. The escrow commitment binds the nullifier key and auditor ciphertext. The merge ciphertext binds amount and mint to the settled output. [The scanner](client/src/merge_audit.rs) checks confirmed events and authenticated registry pages. The indexed request includes the selected root as its thirteenth public field. | Valid ring-to-SPP settlement, bad root, missing registration, noncanonical mint chunks, commitment mismatch, indexed request shape and unresolved reporting. Anonymous ring merge remains disallowed. |
| No caller borrows the ring PDA's signature | [Transfer](program/src/instructions/transact.rs) checks payer and owners. [Public leg parsing](program/src/instructions/public_legs.rs) checks SOL sources and token authorities. [Deposit and merge](program/src/instructions/forward.rs) check the funder before CPI. | Missing signer and PDA alias rejection across every public leg. |
| Recovery cannot hide a proved note | [Rust](client/src/decrypt.rs) and [TypeScript](../sdk-libs/ts/src/ring/audit.ts) start with verified auditor openings. Merge scanners keep a confirmed output that cannot be opened as unresolved. | Wrong recipient payload, wrong amount, absent key, page gap and confirmed-event mismatch. |

The merge opening identifies the amount, mint, commitment, ring data, input nullifiers and authenticated member. Photon can also provide the RegisterKey signer tag for new projections. The merge event does not say whether that tag used an Ed25519 or PDA shielded key. Neither SDK invents a spendable note from that tag alone. Historical rows without the signer tag still expose the raw authenticated opening.

The circuit walkthrough in [policy/doc.go](../prover/server/custom_rings/circuits/policy/doc.go) documents the policy order and public-input boundary. The merge circuit names its ownership, registry, ciphertext and ring-data obligations in source. The [audit map](audit-readiness.md) links these obligations to callers and tests. Source comments are an aid to review, not a substitute for tests or an external audit.

The intentional limits are ordinary recipient delivery outside the proof, 32 accepted registry roots, per-transfer outflow caps, delegate exemptions and the documented transaction-size boundary. Direct scans trust chain RPC for confirmed contents and the indexer for complete history. Ring RPC also trusts its server to make those checks. It exposes unresolved merges rather than reporting an incomplete scan as complete.

| Maintainer question | Code-only answer |
|---|---|
| Same readiness as the default ring? | The known custom-ring code blockers are fixed. Current merge keys settle every supported merge proof width through the custom program and SPP. |
| Secure and fully constrained proofs? | The reviewed policy, registry, disclosure, merge and optimized arithmetic paths have explicit bindings. A full proof-system guarantee requires an external audit. |
| Circuit source documentation better? | Policy and merge proof obligations are now readable in source. A ranking against the default ring is subjective. |
| Implementation gaps? | No remaining blocker has been reproduced in the reviewed delta. Final integration evidence is still required. |
| Documentation current? | This review, the audit map and the overview describe the implemented merge and audit boundaries. |
| External-audit readiness? | Review the proof-obligation map, adversarial witnesses and origin/indexer trust boundary. |
| Mainnet readiness, code only? | No known code blocker remains in this differential review. This does not replace an external audit. Release operations are outside this verdict. |

## Combined validation

The program negative suite passes 240 tests against freshly rebuilt SBF. The custom-ring CPI test settles valid 8-slot, 24-slot and 52-slot merge proofs with current keys, including 24 and 50 real-input cases. It checks the new commitment and every nullifier PDA. The measured total costs are 155,215, 206,898 and 305,130 CU. The 8-slot case rejects an unwritten root and an authenticated empty root. Two default-ring merge regressions also pass with the new keys. The full workspace compiles with all targets. The base Rust client passes 202 tests, the ring SDK 126, the ring audit client 54 and the signed ring RPC 31. Photon OpenAPI generation matches the tracked schema. TypeScript passes 1,695 non-live tests, typecheck, lint, build and distribution checks. Go indexed tests, focused circuit tests, vet and the 58-key catalog check pass. The six merge R1CS files match the pinned keys and verifier exports. Formatting and diff checks pass.
