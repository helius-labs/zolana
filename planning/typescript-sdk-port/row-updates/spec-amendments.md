# Row updates from the three spec amendments

Written by the worker who applied the 2026-07-25 spec amendments for G7-1, T23,
and C04. It records which review-checklist rows the amendments release and which
ones they leave held, so the checklist owner can transcribe them without
rereading the spec diff. The evidence behind each ruling is in
[authority-rulings.md](../authority-rulings.md), recorded at `1d6b9873`.

## What the spec now says

| Ruling | Section | Change |
| --- | --- | --- |
| G7-1 | Pubkey Field Encoding, Owner Hash | Two encodings are defined. `owner_pk_field` is parity-free and enters `owner_hash`; `pk_field` keeps the parity bit and applies to a registered viewing key. Each cites its circuit, program, and SDK implementation. References through the transact and merge sections now name the encoding they mean. |
| T23 | SPP Proof public inputs, UTXO Ownership Check | The confidential and anonymous branches are described as implemented, with a new `Owner tag by variant` subsection giving the per-variant marker and the reason the two forms prove the same statement (the confidential variant pins `p256_signing_pk` to the recomputed owner key at `circuit.go:184`). |
| C04 | RPC, Indexer | An integer crossing the JSON boundary is restricted to the IEEE-754 safe-integer range, and a decoder rejects a value outside it. `Context` is corrected from `slot: u64` to `block_time: i64`. |

One point stays open by instruction. The collision argument that stood at the
old line 278 does not survive the correction, because both rails run
`owner_pk_field` over 32 bytes. That paragraph is now a marked placeholder
pointing at `owner-hash-collision-audit.md`, which had not landed when this was
written. A row that depends on the separation argument rather than on the
encoding stays held until the audit lands.

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

## Rows these amendments do not release

I07, I10, I19, and I22 stay `BLOCKED`. Their conflicts are elsewhere in the
spec: I07 and I19 on the deposit instruction's accounts, payload, tag semantics,
and initial viewing-key tag; I10 and I22 on which fields a protocol-config
update rewrites. Nothing in the owner-hash encoding, the confidential owner tag,
or the integer domain touches those, so they wait on their own rulings.
