# Spec Writing Guide

A reference for writing technical specifications. The patterns are tech-agnostic. Use them as a checklist when drafting or reviewing.

## Structural Patterns

### 1. Table of contents

Every section and subsection linked from the top. Mandatory beyond ~500 lines.

### 2. Abstract before specification

Three short paragraphs: what the system is, how it works end-to-end, what this document covers.

### 3. Single flat terminology table

One `Term | Definition` table. Do not spread definitions across multiple typed tables (Actors, Accounts, Operations).

### 4. Group by concern, not by actor

Sections per concept (Deposits, Withdrawals, Execution, Proving, RPC, Interfaces). Each concept lives in exactly one place; do not duplicate it inside per-actor subsections.

### 5. Anchor links between sections

Define a concept once, link to it everywhere else.

### 6. Mermaid sequence diagrams for both happy and failure paths

Every major flow gets two diagrams, one for success and one for the failure or bounce-back path.

### 7. Numbered, ordered execution steps

Write each procedure (verifier check, instruction handler, state-transition function) as a numbered list with one responsibility per step and an explicit precondition.

## Content Patterns

### 8. Permission matrix

One table: `Action | Component | Authorized caller`. List every privileged call. Follow with a short rationale-notes list for the non-obvious rows.

### 9. Role separation with cold/hot key rationale

Separate governance (cold, rare) from operational (hot, online) roles. State that the same address MAY hold both, but every privileged call is still attributed to its role.

### 10. Visibility table for every privacy-relevant payload

`Field | Visibility | Reason`. Apply to every wire-format struct that crosses a trust boundary.

### 11. Failure-mode events table

`Event | Emitted by | When`. One row per failure mode, distinguishable from sibling modes.

### 12. Validation rules inline at the call site

Describe each entry point as a numbered list of checks and side effects (validate, require, snapshot, transfer, append, emit).

### 13. Triggering-conditions pattern for failure sections

Structure: "There are N triggering sites: ...", then handling per site, then events. Enumerate triggers before describing logic.

### 14. Snapshot-on-submit for mutable parameters

Any rate, fee, or key index that the system may change later MUST be snapshotted onto the queued or pending item at submission time, so in-flight changes do not retroactively affect already-committed work.

### 15. Named errors for every invariant

Every required precondition gets a named error (`MissingX`, `InvalidY`), not a generic revert. Include the error table in the spec.

### 16. Sentinel values explicitly named and documented

If "zero" or `0xff…ff` carries meaning, name the constant and state why (avoiding storage clearing, distinguishing user-supplied entries from internal ones, etc.).

### 17. Two-step authority transfers

`transferX(new)` plus `acceptX()` for every privileged role.

### 18. Explicit "what is NOT enforced" callouts

State non-enforcement as deliberately as enforcement. Pattern: "The system does not validate X at submission time; if X is later rejected, the funds or work are parked in registry Y, recoverable via Z."

### 19. Inline rationale for every non-obvious choice

A "Why X and not Y" sentence next to each non-trivial decision.

### 20. Default-deny with explicit allow-list

For any extensible surface (RPC methods, instruction tags, message types, schema versions), state that anything not explicitly listed is rejected, then list what is allowed.

### 21. Versioned wire formats with a discriminator byte

Every wire-format object that may be extended gets a leading version or type discriminator. Every hash domain over such objects folds the discriminator in. One queue can then carry multiple message types.

### 22. Monotonic batch and sequence indices that advance on no-op

A counter that advances even when the batch is empty makes a missing batch detectable. Apply to any periodic finalization.

### 23. Recovery path for extended downtime

State what happens when a component has been offline longer than the system's standard memory window (block-hash history, root cache, key grace period). Provide an explicit fallback that uses witness data to bridge the gap.

### 24. Network-upgrade and versioning section

Cover: how the verifier, circuit, or program rotates; the versioning counter; the activation rule; behavior when an operator does not upgrade; behavior when part of the stack is upgraded but another part is stale.

### 25. Constants table with named magic numbers and units

Every numeric constant gets `NAME = value` with a stated unit and a one-line purpose. No unnamed numbers in prose.

### 26. Common-types section before interfaces

All structs defined once, in one place. Interfaces reference them.

## Stylistic Patterns

### 27. RFC 2119 keywords

Use MUST, MUST NOT, SHOULD, MAY, REQUIRED in capitals for normative statements. Lowercase prose for explanation.

### 28. Invariants attached to interface definitions

Doc-comment notes on each function signature spell out the preconditions, named error, and rationale. The interface block stands alone; readers do not need to chase prose.

### 29. Concrete byte and resource budgets

State wire size per message, gas or compute cost per call, capacity per queue, max sizes per field.

### 30. Rationale-notes bullet list after a normative table

State the rule in a table, then a short bulleted list explaining only the non-obvious rows.

### 31. Cross-reference at every concept reuse

When a term, constant, or component is mentioned outside its definition section, link back to the canonical definition.

## Checklist

Before publishing a spec, verify:

- [ ] TOC present and linked
- [ ] Abstract describes the system end-to-end in three paragraphs or less
- [ ] Trust assumptions stated explicitly (who is trusted for what)
- [ ] Single terminology table
- [ ] Permission matrix with rationale
- [ ] Constants table with named values, units, and purposes
- [ ] Common-types section before interfaces
- [ ] Every entry point has a numbered validate-and-execute list
- [ ] Every failure mode has a triggering condition, a recovery path, and a distinct event
- [ ] Every wire-format struct has a visibility table
- [ ] Every privileged role has a two-step transfer
- [ ] Every mutable parameter is snapshotted at submission time
- [ ] Every extensible surface uses default-deny with an explicit allow-list
- [ ] Versioning and upgrade story present
- [ ] Recovery path for extended downtime present
- [ ] Sequence diagrams cover both happy and failure paths
- [ ] All numeric values named and units stated
- [ ] Anchor links used; no concept redefined inline outside its canonical section
- [ ] MUST, SHOULD, MAY used for normative statements
- [ ] No "TBD" left in normative sections
