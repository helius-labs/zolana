# Finishing the rulings handoff

Branch `port/handoff`, worktree `zolana-ts-handoff`. This picks up the three items
[`rulings-implementation.md`](rulings-implementation.md) handed off when the files they needed were
held by other agents: the K11 call sites, the T28 TypeScript half, and the four missing Browserslist
declarations.

Two are done, and one turned out to be owned and already written by another worker.

## K11: the call sites

**Commits** `5d80eccc` and `4c06d259`, landed after `port/zone-read` merged.

The order was forced rather than chosen. `port/zone-read` held both
`sdk-libs/ts/transaction/src/serialization/codecs.ts` and
`sdk-libs/ts/transaction/src/wallet/sync.ts` while it corrected a zone-resolution divergence, and it
rewrote the bodies of the same functions whose signatures K11 changes. A correctness fix outranks a
type narrowing, so this batch wrote its conversion, parked it on `port/handoff-k11-wip`, and reset
`port/handoff` off it so the two branches never met in a merge. The parking branch is deleted now
that its content is here.

**What survived the replay.** All eleven signature conversions, unchanged. Diffing the parked patch
against the replayed one leaves a single line, and it is not one of the conversions: zone-read had
dropped `ShieldedPublicKey` from the `sync.ts` import that the conversion also edits, so the context
around the edit moved rather than the edit itself. The two merge bodies were byte-identical to what
was parked, and `inTransactionCategory` and `splitEmbeddedKey` were untouched, so each of the three
claims behind the rewrite was re-checked against the merged file and each still held.

**The two functions zone-read newly exported need nothing.** `plaintextTransferUtxos` and
`prooflessUtxo` are public surface now, but they take a payload, a registry and an owner; neither
takes a viewing key, so K11 does not reach them.

**What the conversion does.** Seven of the eleven signatures are in `codecs.ts` and four in
`sync.ts`, and the import line each file leads with changes with them. Nine need the annotation
alone: `encryptConfidential`, `encryptAnonymous`, `decryptAnonymous`, `decryptConfidential` and
`decryptConfidentialAsSender` in `codecs.ts`, and `confidentialSendRecipients`,
`ensureViewingKeyEntries`, `advanceViewingKeyEntry` and the `counterparties` closure in `sync.ts`,
plus the import each file leads with.

Two needed the body first. `encryptMerge` and `decryptMerge` called `secretBytes()` and handed the
exported copy to the free `encryptVerifiable` and `decryptVerifiable` from `@zolana/keypair/merge`,
which is the one thing `ViewingKeyLike` withholds. They now call the interface's own methods, which
is what Rust does: `Merge::encrypt` is `cx.tx.encrypt_verifiable(&cx.user_viewing_pk, bytes)?` and
`Merge::decrypt` is `cx.viewing_key.decrypt_verifiable(&tx_viewing_pk, ciphertext)?`. Side by side:

```ts
export function encryptMerge(
  txViewingKey: ViewingKeyLike,
  userViewingPublicKey: P256PublicKey,
  value: MergePlaintext,
): Uint8Array {
  const plaintext = encodeMerge(value);
  const encrypted = inTransactionCategory(() =>
    txViewingKey.encryptVerifiable(userViewingPublicKey, plaintext),
  );
  return concat(encrypted.txViewingPublicKey.toBytes(), encrypted.ciphertext);
}

export function decryptMerge(userViewingKey: ViewingKeyLike, body: Uint8Array): MergePlaintext {
  const { key, rest } = inTransactionCategory(() => splitEmbeddedKey(body));
  return decodeMerge(inTransactionCategory(() => userViewingKey.decryptVerifiable(key, rest)));
}
```

Two behaviours move with the bodies, both toward Rust. The manual zeroization goes, because no copy
of the secret is made to zero. And both keypair calls sit inside `inTransactionCategory`, so a
destroyed key that used to escape as a raw `KeypairError` now arrives as `TRANSACTION_KEYPAIR`,
which is what Rust's `?` into `TransactionError::Keypair` does. The handoff predicted that for
`decryptMerge`; `encryptMerge` gets it too, because `Merge::encrypt` converts the same way and
`encryptMerge` converted nothing at all before.

`DecodeContext.viewingKey`, `decodeContextForSlot` and `WalletSyncMaterial.viewingKeys` stay
concrete, as the handoff requires: Rust binds `&'a ViewingKey` and `Vec<ViewingKey>` there, so
widening them would make TypeScript the more permissive of the two.

**The type gate, and why the handoff's warning needed more than noting.** `npm run typecheck`
compiles `src/**` only, so a type-level assertion in a test file is checked by nothing, and eslint's
typed rules report lint findings rather than compile errors. Rather than route around that,
`typecheck.mjs` now compiles a package's `test/types/tsconfig.json` alongside its sources when one
exists. The first such project is `sdk-libs/ts/transaction/test/types/viewing-key-like.types.ts`,
which drives all seven `codecs.ts` signatures with a `ViewingKeyLike` backend and pins the three
surfaces that must stay concrete.

Its own control is inside it. `ViewingKey` carries private fields, so no structural stand-in
satisfies it, and the file asserts that with a `@ts-expect-error`; an unused `@ts-expect-error` is
itself a compile error, so the assertion above it cannot quietly become vacuous. Control edit, run
through `npm run typecheck` rather than a hand-invoked `tsc`: widening `tx` back to `ViewingKey` in
`codecs.ts` fails the gate with three `TS2345`s naming `#private`, `secretBytes` and `destroy` as
what a backend lacks. Re-run after the replay onto the merged bodies, with the same three errors at
the same three lines.

**Row transition.** K11: proposed closed. The interface half closed for `@zolana/keypair` at
`335a026c`, and the `transaction` call sites the row also named are now converted.

## T28: the TypeScript half was another worker's, and has since merged

Owed against `ts-sdk-port` when this batch reached it, but not owed to this batch. `port/t28-close`
had it at `64320c10` with its test at `1b8c148b`, live in another worktree, so writing it here would
have collided on the exact lines it changes. It merged at `54021ca8`. Verified against the ruling
rather than reimplemented:

- `normalizeZoneDataHash` collapses an all-zero hash to `undefined`, and both storing sites route
  through it: the `ProofInputUtxo` constructor and `createProofOutput`, which is where
  `withZoneData` and `withZoneDataHash` land. `mergeZone`'s `outputZoneDataHash` in
  `instructions/builders.ts` follows for free through `createProofOutput`, as `MergeZone::new` did
  in Rust.
- The zone address is untouched, and the test holds it that way: two `not.toEqual` assertions fail
  if anyone extends normalization to the address, which is the clause `run-authorizations.md` holds
  until the owner confirms it.

**Row transition.** T28: none proposed from this branch. `port/t28-close` records its own in
[`t28-close.md`](t28-close.md), and the address clause stays held.

## Browserslist: the four remaining packages

**Commit** `ef21fca5`. `hasher`, `transaction`, `indexer-api` and `api` take the same five queries
the other six browser packages took at `9ad5401c`:

```json
"browserslist": [
  "chrome >= 94",
  "edge >= 94",
  "firefox >= 93",
  "safari >= 16.4",
  "ios >= 16.4"
]
```

The floors are the esbuild `es2022` target read back as browser versions, so the declaration
describes what `npm run test:browser` already bundles rather than promising new support. All ten
publishable browser packages now carry it; `test-kit` is not a browser package and does not.

**No test, deliberately.** Q26 rules "State a Browserslist. Do not gate on it", and the ruling
argues the point: a manifest field tests nothing, and the property it appears to promise needs a
real browser run rather than a static scan. The standing rule that every change carries a
failing-without-it test yields to the specific ruling here, which is the only place in this batch
where it does.

## A defect reported to another batch, since fixed there

`sdk-libs/ts/keypair/test/vectors/capability-boundary-certification.test.ts:290` failed
`npm run lint:packages` with `no-unnecessary-type-assertion` when this batch merged `ts-sdk-port` at
`66ec32f3`. It arrived with `aebde4af` from `port/crypto-b`, which was live, so it was recorded
rather than fixed here, and `port/crypto-b` has since deleted the cast.

Worth keeping in the record as K11 fallout rather than as a stray lint finding: the line cast
`asViewing.publicKey() as P256PublicKey`, which was necessary while `ViewingKeyLike` returned
`P256PublicKey | Promise<P256PublicKey>` and became redundant the moment it returned the value. A
narrowing that reaches an interface leaves redundant casts behind it in every package that consumed
the wider type, and only the lint gate finds them.

## Gates run

`npm run build` before every suite.

- `npm run build`, `npm run typecheck`, `npm run lint`, `npm run lint:packages`,
  `npm run format:check`
- `npx vitest run`, 1987 passed and 1 skipped across 118 files
- `npm run test:vectors`, `npm run test:property`
- `npm run check:packaging` (inventory, exports, dependencies, api, browser, pack)
