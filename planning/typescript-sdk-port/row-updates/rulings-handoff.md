# Finishing the rulings handoff

Branch `port/handoff`, worktree `zolana-ts-handoff`. This picks up the three items
[`rulings-implementation.md`](rulings-implementation.md) handed off when the files they needed were
held by other agents: the K11 call sites, the T28 TypeScript half, and the four missing Browserslist
declarations.

One of the three is done, one turned out to be owned and already written by another worker, and one
is written but parked. The parking is the substance of this note, so it leads.

## K11: the call sites are written and held back

`port/zone-read` is live in `sdk-libs/ts/transaction/src/serialization/codecs.ts` and
`sdk-libs/ts/transaction/src/wallet/sync.ts`, closing a read-path divergence where TypeScript stores
a zone-carrying UTXO that Rust refuses. That is a correctness defect against a type narrowing, and
it rewrites the bodies of the same functions whose signatures K11 changes, so it goes first.

The work is written and parked on `port/handoff-k11-wip`, two commits:

- `a843d3f2` narrows the call sites and moves the two merge bodies.
- `6e37f01c` adds the type gate below.

Eleven signatures change, seven in `codecs.ts` and four in `sync.ts`, plus the import line each file
leads with. `a843d3f2`'s message counts those thirteen edits as twelve and its second paragraph is
off by one against the nine annotation-only signatures; the breakdown here is the accurate one, and
the commit is due to be rewritten against the merged bodies anyway.

`port/handoff` was reset off both, so `codecs.ts` and `sync.ts` are untouched by this branch and
`port/zone-read` merges without meeting them. Whoever resumes this reads the merged bodies before
replaying the patch rather than replaying it blind: the two merge functions are exactly what
zone-read may have restructured.

**What the parked patch does.** Nine signatures need the annotation alone: `encryptConfidential`,
`encryptAnonymous`, `decryptAnonymous`, `decryptConfidential` and `decryptConfidentialAsSender` in
`codecs.ts`, and `confidentialSendRecipients`, `ensureViewingKeyEntries`, `advanceViewingKeyEntry`
and the `counterparties` closure in `sync.ts`, plus the import each file leads with.

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
itself a compile error, so the assertion above it cannot quietly become vacuous. Control edit run
against the source: widening `tx` back to `ViewingKey` in `codecs.ts` fails `npm run typecheck` with
three `TS2345`s naming `#private`, `secretBytes` and `destroy` as what a backend lacks.

**Row transition.** K11: no change. The interface half is closed for `@zolana/keypair`; the call
sites stay open until `port/zone-read` merges and the parked branch is replayed.

## T28: the TypeScript half is written, on an unmerged branch

Still owed against `ts-sdk-port`, and not owed to this run. `port/t28-close` has it at `64320c10`
with its test at `1b8c148b`, and that branch is live in another worktree, so writing it here would
have collided on the exact lines it changes. Verified against the ruling rather than reimplemented:

- `normalizeZoneDataHash` collapses an all-zero hash to `undefined`, and both storing sites route
  through it: the `ProofInputUtxo` constructor and `createProofOutput`, which is where
  `withZoneData` and `withZoneDataHash` land. `mergeZone`'s `outputZoneDataHash` in
  `instructions/builders.ts` follows for free through `createProofOutput`, as `MergeZone::new` did
  in Rust.
- The zone address is untouched, and the test holds it that way: two `not.toEqual` assertions fail
  if anyone extends normalization to the address, which is the clause `run-authorizations.md` holds
  until the owner confirms it.

**Row transition.** T28: no change from this branch. It closes when `port/t28-close` merges.

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

## A defect in another batch's package

`sdk-libs/ts/keypair/test/vectors/capability-boundary-certification.test.ts:290` fails
`npm run lint:packages` with `no-unnecessary-type-assertion`. It arrived on `ts-sdk-port` with
`aebde4af` from `port/crypto-b`, which is live, so it is recorded rather than fixed.

It is K11 fallout and worth reading as such: the line casts
`asViewing.publicKey() as P256PublicKey`, which was necessary while `ViewingKeyLike` returned
`P256PublicKey | Promise<P256PublicKey>` and is redundant now that it returns the value. The
required change is deleting the cast. Until then `check:static` is red on the integration branch for
a reason that has nothing to do with the assertion the test is making.

## Gates run

`npm run build` before every suite.

- `npm run build`, `npm run typecheck`, `npm run format:check`, `npm run lint`
- `npm run lint:packages`, failing only on the `port/crypto-b` line above
- `npx vitest run`, 1982 passed and 1 skipped across 117 files
- `npm run check:packaging` (inventory, exports, dependencies, api, browser, pack)
