# Row updates from the spec amendments

Written by the worker who applied the 2026-07-25 spec amendments: G7-1, T23,
and C04 in the first rounds, then the deposit and protocol-config amendments
for I07, I19, I10, and I22. It records which review-checklist rows the
amendments release and which ones they leave held, so the checklist owner can
transcribe them without rereading the spec diff. The evidence behind the first
three is in [authority-rulings.md](../authority-rulings.md), recorded at
`1d6b9873`.

## What the spec now says

| Ruling | Section | Change |
| --- | --- | --- |
| G7-1 | Pubkey Field Encoding, Owner Hash | Two encodings are defined. `owner_pk_field` is parity-free and enters `owner_hash`; `pk_field` keeps the parity bit and applies to a registered viewing key. Each cites its circuit, program, and SDK implementation. References through the transact and merge sections now name the encoding they mean. |
| T23 | SPP Proof public inputs, UTXO Ownership Check | The confidential and anonymous branches are described as implemented, with a new `Owner tag by variant` subsection giving the per-variant marker and the reason the two forms prove the same statement (the confidential variant pins `p256_signing_pk` to the recomputed owner key at `circuit.go:184`). |
| C04 | RPC, Indexer | An integer crossing the JSON boundary is restricted to the IEEE-754 safe-integer range, and a decoder rejects a value outside it. `Context` is corrected from `slot: u64` to `block_time: i64`. |

The rail-separation paragraph is complete as of the follow-up. It was a marked
placeholder while [owner-hash-collision-audit.md](../owner-hash-collision-audit.md)
was still being written; the audit has since landed and the paragraph now
carries the settled argument. Separation no longer comes from the encoding,
since both rails run `owner_pk_field` over 32 bytes. It rests on `owner_hash`
being a fixed target, which makes reuse a Poseidon preimage rather than a
birthday collision, and on each rail authorizing the same bytes under a
different hardness assumption. The spec states as an assumption that an Ed25519
owner at address `S` is also addressable as the P256 owner of x = `S`, so that
owner's authorization is the weaker of Ed25519 signing and the P256 discrete log
at x = `S`. No marker remains in the spec.

Two things the audit raises are deliberately absent from the spec: a reported
weakness in the merge and user-registry path, and whether the ECDSA gadget is
satisfiable for a degenerate `(0, 0)` witness. Both are under separate
verification and will arrive as their own rulings if confirmed.

## Rows the amendments release

| Row | Held on | Now |
| --- | --- | --- |
| G7-1 | the spec defining one `pk_field` while four implementations use two | Resolved by amendment. No code change: the implementations were correct. |
| T23 | the spec stating both the zero sentinel and the equality form for a confidential P256-owned input | Resolved by amendment. No code change, and no verifying key or proving key moves. |
| C04 | `Context { slot: u64 }` against the `block_time: i64` the three implementations use, and an unstated JSON integer domain | Resolved by amendment. The TypeScript safe-integer check at `codec.ts:69` is conformant rather than divergent. |
| K06 | the P256 owner-hash construction conflict | The encoding half is settled: `ownerPublicKeyField` implements the form the spec now names. The row keeps its other findings (construction and facade APIs, compressed-address handling, ownership boundaries, fixtures). |
| K07 | owner hashing inheriting K06 | Same: the inherited conflict is gone, the row's own findings remain. |
| K14 | the K06 owner-hash conflict among several package-surface findings | Same. |
| T02, T07 | the memo record (tag `3`) missing from the UTXO Data table | Already closed by `b9a5386f` under the earlier memo ruling. Both languages implement what the spec now defines, so the named prerequisite is met. |

## The interface amendments: I07, I19, I10, I22

A later round applied the deposit and protocol-config amendments, on the
evidence in
[interface-spec-conflicts.md](./interface-spec-conflicts.md) (`e8147c4b`). The
spec changes landed in `b97b2a88` (deposit) and `58b2be6a` (protocol config).

| Amendment | Section | Change |
| --- | --- | --- |
| A: deposit payload | `deposit`, `zone_deposit` | `DepositIxData` is `view_tag`, `owner` (the recipient `owner_hash`), `blinding`, one `amount`, `Option<UtxoData>`, `Option<memo>`. The `public_sol_amount` / `public_spl_amount` pair is gone; the asset comes from the settlement accounts. `ZoneDepositIxData` follows, with `zone_data_hash` and `zone_data` unconditional. Both note `deserialize_exact`. |
| A: deposit accounts | `deposit`, `zone_deposit` | Six accounts for SOL and seven for SPL, eight for the zone form, including the trailing program account the spec's own check 7 needs for the `emit_event` self-CPI. The checks lists follow, with the signer and non-zero-amount checks the program performs. |
| A: stray tag row | Instructions | The duplicate `zone_deposit = Tag 1` row is deleted. Tag 15 stands. |
| B: discovery | `deposit` | New `Discovery` paragraph. The tag is still the recipient's signing pubkey, unchanged. What is new is the consequence: the program copies `view_tag` through unread, Photon indexes it, and `get_shielded_transactions_by_tags` filters on it, so a wrong derivation loses discovery with no error anywhere. |
| C: config updates | Protocol config | New `Protocol config updates` paragraph tabulating the seven variants against the fields they write, recording the absence of cross-field validation, the atomic multi-instruction composition, and the incoming-authority co-signature required to rotate `protocol_authority`. |

| Row | Held on | Now |
| --- | --- | --- |
| I07 | deposit payload shape and tag semantics | Released. The payload and account text match the program. |
| I19 | deposit builder accounts and tag numbers | Released. The account tables and Tag 15 match the builder. |
| I10 | the spec claiming a full rewrite against a single-field enum | Released. |
| I22 | inheriting I10 | Released with it; the row had no independent finding. |

Residual findings, none of them blocking:

- The discovery tag itself. The spec's rule is unchanged and both SDKs still
  write the recipient's viewing pubkey. A separate worker is changing them to
  the signing pubkey, so the divergence is an SDK parity item, not a spec one.
- Creation-side flag laxity. `create_protocol_config` casts raw bytes into the
  three `u8` flags with no range check, so it can write a byte no update can
  produce. Behavior is unaffected because the three `allows_*` accessors that
  read the flags test non-zero. It is
  recorded in the spec rather than the findings register, because a conforming
  decoder has to know to treat any non-zero byte as `true`. Narrowing it would
  be a program change.
- Three divergences the deposit reading surfaced belong to other rows and were
  left alone: the event's `tx_viewing_pk` and `salt` typed as `Option` against
  fixed zeroed arrays, the output slot's tag field named `owner` in the spec
  and `view_tag` in the event crate, and a `memo` on `ProoflessOutput` the spec
  does not list. Whichever row owns the event crate should rule on them.
