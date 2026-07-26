# X01: how Light handles a u64 past 2^53 on the JSON wire

Worker on `port/spec-x01`. Read-only against Light Protocol at
`/Users/tilohelius/Workspace/light-protocol` and its Photon indexer at
`/Users/tilohelius/Workspace/photon`. No Rust under `sdk-libs/` was changed.

The question is the remaining half of C04: our TypeScript decoder accepts a
decimal string on the seven unbounded indexer integers, the specification
permits that string, and our Rust `serde` refuses it. Light faced the same
stack (Rust service, TypeScript client, one JSON wire). This file records what
each of Light's sides does, whether they are symmetric, and what that means for
us.

## 1. Light's Rust: writes a number, accepts either

The indexer service's wire type is Photon's `UnsignedInteger`
(`photon/src/common/typedefs/unsigned_integer.rs`).

**Serialize.** Derived, transparent over `u64`:

```13:15:photon/src/common/typedefs/unsigned_integer.rs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default, Copy, PartialOrd, Ord)]
#[serde(transparent)]
pub struct UnsignedInteger(pub u64);
```

A response therefore carries a JSON number. There is no `serialize_with` that
emits a string, and the OpenAPI schema it advertises is
`type: integer, format: uint64` (same file, lines 17–29).

**Deserialize.** A hand-written visitor that accepts either form:

```34:67:photon/src/common/typedefs/unsigned_integer.rs
impl<'de> Deserialize<'de> for UnsignedInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UnsignedIntegerVisitor;

        impl<'de> Visitor<'de> for UnsignedIntegerVisitor {
            type Value = UnsignedInteger;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an unsigned integer or string containing an unsigned integer")
            }

            fn visit_u64<E>(self, value: u64) -> Result<UnsignedInteger, E>
            where
                E: Error,
            {
                Ok(UnsignedInteger(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<UnsignedInteger, E>
            where
                E: Error,
            {
                value
                    .parse::<u64>()
                    .map(UnsignedInteger)
                    .map_err(|e| Error::custom(format!("Invalid unsigned integer value: {}", e)))
            }
        }

        deserializer.deserialize_any(UnsignedIntegerVisitor)
    }
}
```

A request may send a JSON number or a decimal string; both become a `u64`.

The OpenAPI-generated Rust *client* in Light
(`light-protocol/sdk-libs/photon-api/src/codegen.rs:29130-29132`) is narrower:
`#[serde(transparent)] pub struct UnsignedInteger(pub u64)` with a derived
`Deserialize`, so it accepts only a JSON number. That client is not the service.
The wire authority is Photon's typedef above.

## 2. Light's TypeScript: parses either, and rewrites the response first

Two layers, both in `js/stateless.js`.

**Transport.** Before `JSON.parse`, the raw response text is rewritten so any
integer literal outside the IEEE-754 safe range becomes a quoted string
(`rpc.ts:291-302`, applied at `:346`):

```291:302:js/stateless.js/src/rpc.ts
export function wrapBigNumbersAsStrings(text: string): string {
    return text.replace(/(":\s*)(-?\d+)(\s*[},])/g, (match, p1, p2, p3) => {
        const num = Number(p2);
        if (
            !Number.isNaN(num) &&
            (num > Number.MAX_SAFE_INTEGER || num < Number.MIN_SAFE_INTEGER)
        ) {
            return `${p1}"${p2}"${p3}`;
        }
        return match;
    });
}
```

That is what keeps digits intact when Photon emits a bare number past `2^53`.

**Decoder.** Per field, `BNFromStringOrNumber` accepts a string or a safe
number and refuses an unsafe number
(`rpc-interface.ts:316-328`):

```316:328:js/stateless.js/src/rpc-interface.ts
const BNFromStringOrNumber = coerce(
    instance(BN),
    union([string(), number()]),
    value => {
        if (typeof value === 'number') {
            if (!Number.isSafeInteger(value)) {
                throw new Error(`Unsafe integer. Precision loss: ${value}`);
            }
            return bn(value); // Safe number → BN
        }
        return bn(value, 10); // String → BN
    },
);
```

Light applies it selectively to fields whose domain can exceed `2^53`
(`lamports`, `amount`, `balance`, `seq`, `slotCreated`, `discriminator` at
`rpc-interface.ts:424-457`, `:666-690`). Fields it treats as bounded
(`slot`, `blockTime`, `leafIndex`, `rootSeq`) stay on plain `number()`
(`:429`, `:540-555`, `:566-581`).

## 3. Are the two sides symmetric?

No. The writer always emits a JSON number. The string form is a reader's
tolerance on both ends of the stack that need it:

| Actor | Writes | Reads |
| --- | --- | --- |
| Photon service (`UnsignedInteger`) | number | number **or** string |
| TypeScript client | numbers in requests (via `JSON.stringify`) | number **or** string, after the transport rewrite |
| `photon-api` Rust client | number | number only |

So the tolerant sides are the Photon service's deserializer and the TypeScript
client. The string is never the canonical on-wire shape a service produces.

That matches the framing already in our specification: the string is "a
reader's tolerance rather than a shape a service has to adopt"
(`docs/spec.md` Integer encoding paragraph).

## 4. Where we stand against that

Our TypeScript port already follows Light's client half: per-field
`unboundedWireInteger` on `block_time`, both `slot`s, both `root_seq`s, and the
nullifier-queue `seq` / `start_seq` (`sdk-libs/ts/indexer-api/src/codec.ts`),
plus the transport rewrite under a different name. The encoder still emits
only JSON numbers, and refuses a `bigint` it cannot write as a safe number.

Our Rust does not follow Light's *service* half. The seven unbounded fields are
plain `i64` / `u64` with default `serde` and no string visitor
(`sdk-libs/indexer-api/src/lib.rs:478,496,544,591,609,630,662`). A body the
specification permits, and that TypeScript may produce when quoting, is refused
by Rust. Nothing is broken today because the port only ever writes JSON
numbers; the gap is latent.

## Recommendation

Do not change what we write. Light writes numbers; we write numbers; keep that.

Keep the TypeScript reader as it is. The string-or-safe-number union and the
transport rewrite are Light's answer, and they are already in the port.

**Proposal (out of scope for this branch):** give the seven unbounded fields in
`sdk-libs/indexer-api` a Photon-style `Deserialize` that accepts a JSON number
or a decimal string, while leaving `Serialize` as a bare number. That is the
one-line summary of
`photon/src/common/typedefs/unsigned_integer.rs:34-67` applied to
`block_time`, `slot`, `root_seq`, `seq`, and `start_seq`. It makes Rust accept
what the specification already permits, matches Light's service, and does not
change any response Photon emits. No OpenAPI format change is required if the
schema continues to advertise `integer`; the string remains a reader's
tolerance, not a declared alternate type.

Do not reopen the per-field list here. Light puts `slot` / `rootSeq` on plain
`number()` because it treats them as bounded in practice; our C04 ruling put
them on the unbounded path because the protocol does not cap them. That choice
is already recorded and implemented. This note is only about the
string-versus-number wire question on whichever fields the union already covers.
