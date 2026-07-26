# Rust accepts the decimal-string form the spec already permits

Worker on `port/int-domain` from `ts-sdk-port`. Implemented the reader half of
the integer-domain ruling in `sdk-libs/indexer-api`. TypeScript was left alone;
it already accepted both forms. `planning/typescript-sdk-port/review-checklist.md`
was not touched.

The prior note at [x01-integer-domain-light.md](./x01-integer-domain-light.md)
proposed this change and stopped at a recommendation. The protocol owner ruled
that Zolana matches Light here, so the recommendation is superseded and the
change is in.

## What Light's visitor actually does

Light's wire helper lives in the Photon service at
`photon/src/common/typedefs/unsigned_integer.rs` (the checkout under
`/Users/tilohelius/Workspace/photon`, not under `light-protocol`). It is a
transparent newtype over `u64` with derived `Serialize` and a hand-written
`Deserialize` that calls `deserializer.deserialize_any`. The visitor implements
only two arms: `visit_u64` returns the value, and `visit_str` runs
`str::parse::<u64>()`, mapping a parse error to
`"Invalid unsigned integer value: …"`. There is no `visit_i64`, no
`visit_u128`, and no empty-string special case. An empty string, a negative
string, and a digit string past `u64::MAX` all fail through `parse`. A negative
JSON number fails through serde's default `visit_i64` path, which reports an
invalid type against the visitor's `expecting` string.

Light has no signed counterpart. Fields that use the newtype are unsigned. The
OpenAPI schema for Photon's own `Context.slot` advertises `UnsignedInteger`, but
the Rust field is a plain `u64` with derived `Deserialize`, so that particular
field does not actually accept a string on the wire. The tolerant reader is the
newtype, not every integer in the schema.

## What landed here

`sdk-libs/indexer-api/src/integer.rs` holds two `deserialize_with` helpers,
`deserialize_u64` and `deserialize_i64`. They are shared infrastructure, not
tied to one response type. The unsigned helper mirrors Light's visitor
structure and error wording. The signed helper adds `visit_i64` and a
`visit_u64` arm that `try_from`s into `i64`, because under `deserialize_any`
`serde_json` routes non-negative numbers through `visit_u64`. Without that arm
a positive `block_time` written as a JSON number would fail. Serialize is
unchanged: derived serde still emits a bare JSON number.

The seven attributes sit on exactly the fields the ruling already named:

| Field | Type | Struct |
| --- | --- | --- |
| `block_time` | `i64` | `Context` |
| `slot` | `u64` | `EncryptedUtxoMatch`, `ShieldedTransaction` |
| `start_seq` | `u64` | `GetNullifierQueueElementsRequest` |
| `seq` | `u64` | `NullifierQueueElement` |
| `root_seq` | `u64` | `MerkleProof`, `NonInclusionProof` |

No other integer was widened. `leaf_index`, the non-inclusion element indices,
`root_index`, `tree_type`, and `limit` stay on plain serde and still refuse a
string. Nothing outside that list looked like it belonged; the queue sequences
are already in the seven, and the tree-height caps on the index fields are the
same ones that kept them off the TypeScript union.

## Photon

Photon does not redefine these wire types. `services/photon` imports
`Context`, the match and proof structs, and the nullifier-queue request from
`zolana_indexer_api` (`Cargo.toml` depends on that crate with the `openapi`
feature). Widening the reader therefore widens Photon's JSON-RPC deserialize
path for the same seven fields. `cargo check -p photon-indexer` still passes.
No Photon source needed a change: writers continue to emit numbers, and every
payload that used to deserialize still does.

## Tests and gates

The new tests pin behaviour, not the derive. A string body and a number body
for the same digits deserialize to the same value for both widths; a string one
past `u64::MAX` or `i64::MAX` is refused; an empty string is refused;
`leaf_index` still rejects a decimal string; and serialization of
`Context.block_time` and `NullifierQueueElement.seq` still emits a JSON number.

`cargo check -p zolana-indexer-api`, `cargo test -p zolana-indexer-api`,
`cargo clippy -p zolana-indexer-api -- -D warnings`, and
`cargo check -p photon-indexer` all passed on this tree.
