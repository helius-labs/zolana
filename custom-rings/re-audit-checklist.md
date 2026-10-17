# Custom rings: code differential after PR #427

Baseline: [PR #427](https://github.com/helius-labs/zolana/pull/427) at `9d751d67c06dfeacf3e4d111c7a1866f2c280142` is merged. This review covers the custom-ring code added or changed on top of that baseline at `bf6bc122d`. It does not regrade PR #427 or treat proving-key availability, publication and deployment as code findings.

**Verdict:** No inflation, double-spend or missing constraint was demonstrated in the reviewed custom-ring paths. One audit-completeness gap remains in code. A non-escrow ring, including an audit-only ring, can merge notes without producing an auditor-readable opening for the resulting note. This conflicts with the [ring README's](README.md) guarantee that every custom ring is audited, so it blocks code-only signoff.

| Open differential finding | Evidence and effect | Required decision or fix |
|---|---|---|
| Non-escrow merge has no auditor disclosure | [The ring forwarder](program/src/instructions/forward.rs) rejects merges only in anonymous mode. The [merge circuit](../prover/server/circuits/spp_merge/ring.go) binds an output ciphertext recoverable with the owner's nullifier secret. [Recovery](client/src/recover.rs) needs that secret. `RingMode::Off` does not require key escrow even when policy is enabled, and the auditor-tag scan does not include merges. The auditor key alone therefore cannot open the merged note, identify the inputs from their nullifiers or follow the output's later spend. Conservation and owner recovery still hold. | Add a proof-bound auditor disclosure for the real merge inputs and output, tied to their commitments and published nullifiers. Keep the owner-recovery ciphertext. Do not describe it as auditor VE. |

The rest of the previous custom-ring findings have code fixes:

| Obligation | Current enforcing path |
|---|---|
| Registry membership cannot bypass key escrow | [UpdateMembers](program/src/instructions/update_members.rs) preserves the escrow commitment and requires a valid writer. [RegisterKey](program/src/instructions/register_key.rs) proves auditor encryption and refuses overwrite. Photon projects the authenticated stored list bits. |
| Policy applies to the transaction SPP settles | [The policy circuit](../prover/server/custom_rings/circuits/policy/transaction.go) reopens `PrivateTxHash`. [The program](program/src/instructions/transact.rs) builds public inputs from its policy account and the forwarded SPP transaction. General and shared-path registry proofs authenticate their leaves. |
| Auditor disclosure matches committed transfer outputs | [The audit circuit](../prover/server/custom_rings/circuits/base/audit.go) encrypts the fields used for output commitments. Anonymous mode also discloses sender, spent notes and recipients. [Rust audit](client/src/decrypt.rs) and [TypeScript audit](../sdk-libs/ts/src/ring/audit.ts) use verified openings even when unproved recipient delivery is corrupt. |
| The ring PDA does not authorize a caller by accident | [Transfer](program/src/instructions/transact.rs) checks the outer payer and owner signers. [Public-leg parsing](program/src/instructions/public_legs.rs) checks every SOL source and SPL token authority before the PDA signs the CPI. Direct deposit and merge check their own funder. Negative program tests exercise PDA aliases. |
| Merge preserves authenticated state | [The ring merge wrapper](../prover/server/circuits/spp_merge/ring.go) requires every real input to carry the output ring-data hash. The shared output constraints reject a zero asset. Owner-recovery ciphertext is bound to the committed amount and mint. |
| Recovery does not hide an unresolved note | Rust and TypeScript recovery start from verified openings. Unknown mints and missing recovery material stay unresolved. Recipient metadata cannot replace proved data hashes. The audit scans stop on a terminal frontier and ring RPC identifies events by signature plus ordinal. |
| An unmarked default output cannot burn funds on ring rails | Rust and TypeScript SDK preflight reject a real default-ring output without its required exit marker and owner tag before proving. |

The source documentation now explains the full policy constraint order, public-input provenance and optimized gadget assumptions in [the policy walkthrough](../prover/server/custom_rings/circuits/policy/doc.go). It is adequate for a source audit. A claim that it is categorically better than the default-ring documentation would be subjective. [The overview](changes-overview.md) describes the merge-auditor limitation. The [ring README](README.md) still says every custom ring is audited while allowing the non-escrow merge above, so its headline guarantee needs correction alongside the code.

Code checks passed after the latest fixes: 337 custom-ring program tests against rebuilt SBF, `cargo check --workspace --all-targets`, 1,683 TypeScript tests plus a packed consumer, and focused Go circuit and prover tests. Fourteen specialized anonymous and delegate cases and three ring-merge sizes settled valid proofs on the merged code. The complete specialized matrix also settled before PR #427. These results support the checked paths, but tests do not certify all possible witnesses.

The remaining intentional boundaries are ordinary recipient delivery outside the proof, 32 accepted registry roots, per-transfer outflow caps, delegate exemptions and transaction-size exclusions. Direct SDK audits trust chain RPC for confirmed contents and indexer completeness. Ring RPC clients additionally trust that service's origin checks. Those limits are documented and separate from the audit-only merge decision.

| Maintainer question | Code-only answer |
|---|---|
| Same readiness as the default ring? | Not yet for the claimed auditor-access behavior because non-escrow merge lacks an auditor opening. This comparison makes no release-artifact claim. |
| Proofs secure and fully constrained? | No missing relation was found in the inspected custom policy, registry, disclosure, merge and arithmetic paths. The review is evidence, not a formal proof of the entire circuit family. |
| Circuit source documentation better? | The policy flow and optimized assumptions are now documented well enough for review. The comparison with default is not a security verdict. |
| Implementation gaps? | The non-escrow merge disclosure gap above remains. The previously identified escrow, signer, recipient-data, recovery and ring-data gaps have code fixes. |
| Documentation current? | Mostly for storage, policy and transfer disclosure. The README's broad audit guarantee conflicts with non-escrow merge behavior. |
| Further external-audit work? | Agree on the merge audit guarantee, then make its proof obligation and regression test explicit. Continue adversarial witness review across specialized shapes. |
| Mainnet readiness, code only? | Hold until non-escrow merges meet the stated auditor guarantee. |

Automatic security review previously rejected a live registry proof-mutation reproduction because of potential cybersecurity risk. The projection issue was established by source reading and checked with a storage-only regression. The blocked reproduction was not run.
