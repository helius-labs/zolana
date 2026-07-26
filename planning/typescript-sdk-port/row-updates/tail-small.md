# Tail-small: six ruled register rows

Branch `port/tail-small`. Each item was verified against the finding text and
owner ruling before the change.

## F123 — hardcoded page limits

**Wrong:** `checkedPageLimit` in `@zolana/indexer-api` and `@zolana/client`
compared against literal `1`/`1000` while `MIN_PAGE_LIMIT`/`PAGE_LIMIT` were
already exported. Wallet sync defaulted to a buried `1_000`. `safeSchemaPath`
dropped `cursor` and camelCase field paths from API diagnostics.

**Changed:** page-limit checks take `min`/`max` parameters defaulting to the
exported constants; wallet sync uses a named `DEFAULT_PAGE_LIMIT`; schema-path
allowlist covers `cursor` and camelCase wire names.

**Proof:** `indexer-api/test/schema.test.ts` (“keeps page-limit validation on
the exported constants”); `api/test/responses.test.ts` (“retains cursor paths on
schema failures”).

## F144 — wrong unread fixture offset

**Wrong:** `recipientCountPrefixOffset` was computed as `(33 + …)` while the
owner key is 34 bytes. Nothing in TypeScript read the field.

**Changed:** deleted the field from `xtask`’s transaction fixture generator and
regenerated `serialization-v1.json` (owner ruling: delete, do not correct).

**Proof:** `npm run fixtures:check`; field absent from the regenerated JSON.

## F127 — unverifiable keypair hash fixture

**Wrong:** `fixtures/keypair/hash.json` marked `testOnlySecret: true` but
published no secret, so Poseidon owner/public-hash fields could not be
recomputed from that file alone.

**Chose:** publish the deterministic test secrets (`ed25519SecretBytes`,
`p256SecretBytes`) in the fixture inputs rather than remove the Poseidon
expectations — the fixture’s purpose is to pin those hashes.

**Proof:** `keypair-vectors.test.ts` (“matches hash and field encoding
operations”) derives every expected Poseidon field from `hash.json` inputs
only; fixture regenerated via `ts-fixtures`.

## F146 — registry clone silent no-op

**Wrong:** `Wallet.registry` returned `#registry.clone()`, so
`wallet.registry.insert(...)` mutated a throwaway copy.

**Changed:** getter returns the live registry (Rust’s public `registry` field).
Constructor still clones the input so the caller’s map stays independent.

**Proof:** `transaction/test/core.test.ts` — insert through `wallet.registry`
is visible to subsequent `resolve`/`balance`.

## F124 — unchecked payer hash

**Wrong:** `prepareZoneAuthority` accepted a caller-supplied
`payerPublicKeyHash` with no tie to a payer address; Rust derives
`sha256_be(payer)`.

**Changed:** API takes `payer: Address` and derives the hash internally.
Mismatched hash/payer pairs are unrepresentable.

**Proof:** `transfer.test.ts` asserts
`prepared.payerPublicKeyHash === sha256Be(decodeAddress(payer))`; zone and
Rust-oracle callers updated to pass the payer address.

## F142-P — base58 length brute-force

**Wrong:** confirmation decoded instruction data by trying lengths `1..1232`
and then decoding again.

**Changed:** `decodeBase58Bytes` decodes once (canonicality-checked, no fixed
length); the confirmation path validates `length <= TRANSACTION_SIZE_LIMIT`
after that single decode.

**Proof:** `client/test/solana-rpc.test.ts` (“decodes instruction base58 in one
pass for large payloads”) for 711-, 805-, and 1232-byte payloads.

## Invalid / skipped

None of the six failed verification.
