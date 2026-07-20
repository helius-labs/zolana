# Security Audit Checklist (Phase 4)

Audit the *design as specified and implemented*, not code style. For each item,
either confirm the property with a code citation or open a ledger finding.
Weaknesses in the general design are `type: design-weakness`; the skill never
fixes code.

## Double-spend & nullifiers

- Nullifier uniqueness across the full queue/tree window: can a nullifier be
  inserted twice across queue rotation, batch boundaries, or forester lag?
- Bloom filter false-positive policy: what happens to an honest transaction on
  a false positive, and can an attacker grind one to censor a victim?
- Nullifier domain separation: are nullifiers, padding/reserved nullifiers,
  and merge tags in disjoint namespaces? Can any instruction pin or reserve a
  value another user would legitimately produce?
- Padding inputs/outputs: are padding UTXOs and their nullifiers bound to the
  proof so they cannot be substituted or replayed?

## Proof binding

- Is every user-controlled instruction field bound into the proof's public
  inputs (amounts, recipients, hashes such as `private_tx_hash`, `data_hash`,
  `zone_data_hash`, fee fields, payer binding)? List any unbound field.
- Public input hash construction: any malleability (length extension, field
  overflow, ambiguous concatenation) in how public inputs are hashed?
- Root freshness: which historical roots are accepted, and can a stale root
  enable spending pruned or reorged state?

## Rails (EdDSA vs P256)

- Are the two rails' proofs, verifying keys, and BSB22 commitment handling
  strictly separated (a proof for one rail can never verify under the other)?
- Signer binding per rail: eddsa signer index vs P256 ownership — can a UTXO
  owned under one rail be spent via the other?

## Zones & CPI

- Zone authority checks: can a zone program be impersonated, or a
  zone-authority instruction be invoked outside the intended CPI context?
- Are zone data hashes bound to the proof and to the executing zone program id?

## Value conservation

- Sum checks across inputs, outputs, public deposit/withdraw amounts, and
  fees — including edge shapes (all-padding inputs, zero-amount outputs) and
  both-public-amounts cases.

## Privacy claims

- For every "Private"/"Visible" claim in the spec (sender, recipient, amount,
  zone), does the implementation actually deliver it (e.g. payer binding on
  withdraw reveals sender unless relayed)? Overclaims are findings.
- View tags, encrypted UTXO layout, and sender slots: any metadata leak
  (lengths, orderings, deterministic ephemerals) that links transactions?

## Keys & derivation

- Key hierarchy: does compromise of a viewing/transaction key stay contained
  (no escalation to spend authority)?
- Deterministic derivations: can any derived key or ephemeral repeat across
  transactions in a way that links or leaks (see spec TODO on viewing-key
  repetition)?

## Liveness & operators

- Forester: single-authority liveness dependency; what stalls (nullifier
  queue, batches) if it halts or censors, and is that documented in Trust
  Assumptions?
- Relayer fee griefing: can a relayer front-run, censor, or extract value from
  a queued transaction beyond the agreed fee?
- Prover and indexer trust: confirm they are untrusted for safety (only
  liveness/privacy), and that the spec's trust table matches reality.

## Upgrade & governance

- Who can change protocol config, trees, verifying keys, or authorities, and
  is every privileged instruction listed in the Permission Matrix with the
  correct signer?
