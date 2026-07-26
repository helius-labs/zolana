# F130: Light Protocol error-detail redaction (finding)

**Status.** Light has no transferable policy. Recommend one fail-closed allow-list
everywhere; keep `keypair`, tighten `client` (and note `transaction`).

**Method.** Local read of sibling checkout
`/Users/tilohelius/Workspace/light-protocol` at `b7936408b`
(`git@github.com:Lightprotocol/light-protocol.git`). Cross-checked the same
`errors.ts` on GitHub `main`
([raw](https://raw.githubusercontent.com/Lightprotocol/light-protocol/main/js/stateless.js/src/errors.ts)).
Searched `zolana-ts-sdk-port` for vendored / `node_modules/@lightprotocol/*`
copies: none. Web search for Light TS `sanitizeDetails` / error redaction found
no such helper. Zolana surfaces cited from this port tree.

---

## 1. How Light handles error details and secret leakage

### No redaction or sanitisation step

Light's TypeScript SDK does **not** sanitize structured error payloads. There is
no allow-list, deny-list, or recursive redactor on thrown errors.

The structured error hierarchy in `@lightprotocol/stateless.js` is
`MetaError` and nine subclasses in
[`js/stateless.js/src/errors.ts`](https://github.com/Lightprotocol/light-protocol/blob/main/js/stateless.js/src/errors.ts)
(local: `/Users/tilohelius/Workspace/light-protocol/js/stateless.js/src/errors.ts`):

```ts
class MetaError extends Error {
    code: string;
    functionName: string;
    codeMessage?: string;

    constructor(code: string, functionName: string, codeMessage?: string) {
        super(`${code}: ${codeMessage}`);
        this.code = code;
        this.functionName = functionName;
        this.codeMessage = codeMessage;
    }
}
```

That is the entire payload: a string code, a function name, and an optional
human string. There is no `details` object, no nested maps, no byte arrays, and
no post-construction filter.

Live throw sites mostly use plain `Error` or Solana's `SolanaJSONRPCError`
(e.g. `js/stateless.js/src/rpc.ts`). The `MetaError` subclasses are exported
(`js/stateless.js/src/index.ts` re-exports `./errors`) but are nearly unused in
the JS packages; the `new UtilsError(...)` constructions found under this
checkout are in the CLI
(`cli/src/commands/init/index.ts:228-255`), with messages like
`Architecture ${arch} is not supported.` (not key material).

`js/token-interface/src/errors.ts` and
`js/compressed-token/src/v3/errors.ts` define string constants / one custom
`Error` subclass with fixed string fields (`operation`, `batchCount`). Again: no
details bag, no sanitiser.

### Sidestepping without a redactor

Two ways, neither of which is a redaction policy:

1. **No structured details bag.** Call sites cannot smuggle
   `Uint8Array` / nested objects into a typed `details` field because the type
   does not exist.
2. **Different threat model.** Current Light TS packages
   (`@lightprotocol/stateless.js`, `@lightprotocol/compressed-token`,
   `@lightprotocol/token-interface`) implement ZK compression for public
   compressed accounts/tokens. They do not handle shielded viewing keys,
   nullifier keys, or decrypted amounts the way `@zolana/keypair` /
   `@zolana/client` do. Remnant enum names such as
   `BLINDING_EXCEEDS_FIELD_SIZE` in `errors.ts` are taxonomy leftovers under a
   `// TODO: Clean up` comment, not an active secret-handling path.

Light therefore does not answer "fail-closed vs fail-open on `details`." That
API surface is absent from the packages above.

This matches the port's own comparison note:
`planning/typescript-sdk-port/light-protocol-comparison.md` (section "Where
Zolana is already ahead"): Light has neither the redaction layer nor the
call-site discipline; its error taxonomy is "nine unused classes under a
`// TODO: Clean up`."

---

## 2. Answers to the four questions

| # | Question | Light |
|---|----------|-------|
| 1 | Redaction step, or avoid another way? | **Avoids:** no structured `details` payload; compression SDK without shielded key surfaces. No redactor. |
| 2 | Fail-closed or fail-open? Per package or central? | **Neither.** No policy. Errors are per-package plain / `MetaError` / Solana RPC errors; nothing central. |
| 3 | Nested structures / non-primitives? | **N/A.** `MetaError` only stores strings. Nested objects are not part of the error API. |
| 4 | Public API vs internal errors? | **No distinction.** Same `Error` / `MetaError` / `SolanaJSONRPCError` shapes everywhere; no boundary sanitiser. |

---

## 3. Does Light's approach transfer?

**No.** There is no Light rule to copy for F130. The standing "resolve open
questions the way Light did" instruction therefore falls through: Light did not
resolve this shape of question because it did not introduce a structured
`details` map that can carry secrets.

Zolana already chose a richer error surface (closed codes + `details` + wrapped
`cause`) precisely because it ports Rust variants and must surface diagnostics
across keypair / transaction / client boundaries. That design opens a leak
channel Light's TS SDK does not have. Closing the channel is a Zolana decision.

---

## 4. Zolana status (the contradiction)

### Keypair: fail-closed allow-list

`sdk-libs/ts/keypair/src/error.ts:61-88`:

- Fixed `DETAIL_KEYS`: `name`, `expected`, `actual`, `minimum`, `maximum`,
  `index`, `prefix`, `reason`, `type`.
- Copies only those keys, and only when the value is `number` or `string`.
- Drops unknown keys, nested objects, `Uint8Array`, etc.
- `cause` is non-enumerable so dependency messages that quote bytes stay out of
  `JSON.stringify` / enumeration (`error.ts:100-107`).

### Client: mixed

`sdk-libs/ts/client/src/error.ts`:

- **`ClientError` constructor path is already fail-closed on shape.**
  `validateClientError` + `DETAIL_SHAPES` (`:430-524`, `:641-665`) reject
  unknown codes, unknown fields, wrong kinds, and accessors. Stored via
  `copyAndFreeze` / `cloneSafeValue` (`:681-704`), which keep scalars and plain
  nested objects under *already-validated* keys, and throw on non-plain values.
- **`sanitizeDetails` (used when wrapping foreign errors into `cause`) is
  fail-open.** At `:706-735` it walks recursively, drops only keys matching
  `/(secret|private|seed|blinding|nonce|scalar)/iu`, and keeps arbitrary other
  scalar keys (and nested plain objects/arrays). That is the opposite of
  keypair.

So the leak the finding describes is not "`ClientError.details` as a whole is
open," but specifically: **`safeDetails` → `sanitizeDetails` when
`fromClientCause` / `safeCause` re-hosts `KeypairError` / `TransactionError`
payloads** can preserve keys keypair would have stripped, when those keys reach
the client wrapper without keypair's constructor running first (or when they
arrive via `TransactionError`, which uses a deny-list). Transaction errors use
a similar deny-list (`sdk-libs/ts/transaction/src/error.ts:178-189`), so a
`TransactionError` raised on the client path can still carry non-denied keys
into `ClientError.cause.details`.

---

## 5. Recommendation (specific file changes)

Light does not transfer. Apply the owner's instinct: **one fail-closed rule.**

### Keep `sdk-libs/ts/keypair/src/error.ts` as the canonical policy

No change required to the allow-list or the primitive-only filter. That file is
the correct model.

### Change `sdk-libs/ts/client/src/error.ts`

Two concrete edits (smallest coherent fix for the two files named in F130):

1. **Stop using the deny-list walker as a second policy.** In `safeCause`, when
   the cause is already a `KeypairError` or `TransactionError`, copy
   `cause.details` as the upstream package left it (already sanitized by that
   package). Do not run the recursive fail-open `sanitizeDetails` over it
   again. That removes the path where client can *widen* what keypair
   narrowed.

2. **Replace `sanitizeDetails` itself with a fail-closed allow-list** (or
   delete it if nothing else calls it after (1)). If anything still needs a
   client-local sanitiser for unstructured external maps, restrict it to the
   same primitive allow-list pattern as keypair, optionally extended with the
   small closed set of diagnostic keys the client wrapper actually forwards
   today (`code` is already lifted separately; nested keys that must survive
   when re-hosting transaction diagnostics are `requested`, `available`,
   `inputs`, `outputs`, and other keys already present on live
   `TransactionError` call sites). Unknown keys drop. Non-primitives drop.
   Nested objects are not re-walked to keep arbitrary children; either flatten
   to known keys or drop.

Do **not** weaken keypair to match client.

### Related (outside the two files, but same policy)

`sdk-libs/ts/transaction/src/error.ts:178-189` uses the same deny-list /
scalar-keep pattern as client. Unifying F130 for real means converting
transaction to an allow-list (or per-code `DETAIL_SHAPES` like client
constructors) in the same follow-up. Leaving transaction fail-open would leave
a side door into `ClientError.cause.details` even after client is tightened.

### What not to do

- Do not invent a Light-style "no details bag" rollback of the Rust-parity
  error taxonomy; that would break the port's code mapping.
- Do not treat `DETAIL_SHAPES` on `ClientError` as already closing F130; it
  closes constructor details, not the wrap-path sanitiser.

---

## 6. Blast radius in tests

Unifying to fail-closed **does** change payloads some tests assert, but the
surface is small and localized.

### Will keep working

- Keypair redaction / layout tests
  (`keypair/test/vectors/error-redaction-certification.test.ts`,
  `keypair/test/vectors/keypair-parity.test.ts`): already expect allow-list
  behaviour (`details: { reason: "destroyed" }`, smuggled keys dropped).
- Client leak-negative tests that assert `"must not escape"` is absent
  (`client/test/error.test.ts` around the wrap / deep-sanitize cases): stricter
  filtering still passes.
- `ClientError` constructor vectors driven by `DETAIL_SHAPES`: those vectors
  do not go through `sanitizeDetails`; changing that helper does not alter
  `error.details` for codes like `CLIENT_POLL_TIMED_OUT`.

### Will need expectation updates if client allow-list is *strict keypair keys only*

`client/test/error.test.ts`:

| Approx. lines | Current assertion | Effect of keypair-only allow-list on wrap path |
|---------------|-------------------|------------------------------------------------|
| 325-339 | `TransactionError` wrap keeps `cause.details: { requested, available }` | **Breaks**: those keys are not in keypair `DETAIL_KEYS`. |
| 374-394 | `TRANSACTION_UNSUPPORTED_SHAPE` wrap keeps `{ inputs, outputs }` | **Breaks**: same. |
| 307-323, 343-371 | Keypair wrap keeps `{ reason }` / `{ prefix }` | Still passes. |
| 445-471 | Unknown keys / nested / cause bytes dropped | Still passes (stricter). |
| 474-486 | Known key `name` carrying hex material survives | Still passes (documented residual: value trust is call-site, not sanitiser). |

If the client allow-list is extended with the transaction diagnostic keys that
tests and call sites already use (`requested`, `available`, `inputs`,
`outputs`, and siblings), those two wrap assertions keep working and the change
is mostly a policy rename plus dropping the deny-list regex. Still a public
error-surface change, but not a large test rewrite.

### Cost label

F130 was tagged `OPEN, COSTLY` in
`planning/typescript-sdk-port/row-updates/fnd-tail.md` because it touches public
error surfaces across packages. The *test* blast radius for the two named files
is on the order of **2-4 assertions** in `client/test/error.test.ts` if the
allow-list is naively keypair-only; **near-zero assertion churn** if the
allow-list is the union of keys already produced by keypair + transaction
wrappers. The costly part is agreeing the shared allow-list (and ideally fixing
`transaction/src/error.ts` in the same change), not rewriting a large suite.

---

## 7. Verdict for the authority register

| Item | Result |
|------|--------|
| Light policy | None: no details sanitiser; avoids the bag rather than filtering it |
| Transfers? | No |
| Zolana change | Fail-closed: keep keypair; rewrite client wrap-path `sanitizeDetails` to allow-list (stop deny-list keep-arbitrary); treat transaction deny-list as same follow-up |
| Test blast radius | Small: primarily wrap-path assertions for transaction detail keys in `client/test/error.test.ts` |

F130 can leave "Pending a Light Protocol check" and move to implement fail-closed
unification.
