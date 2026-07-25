# Light Protocol comparison

A design comparison between Zolana's TypeScript SDK (`sdk-libs/ts`, branch
`ts-sdk-port`) and Light Protocol's (`js/stateless.js`, `js/compressed-token`,
`js/token-interface` at `b7936408`). Light is the upstream lineage: same chain,
adjacent protocol, several years of production use. It is prior art to read
against, not a standard to meet, and two of the findings below are Light
defects Zolana should be careful not to inherit.

Everything here is read from source. Where the two disagree the code decides,
and each claim carries a `path:line`.

## If only three things get done

Decide about `@solana/kit` before the `Transaction` type is public surface (F1),
because it is the one finding whose cost rises with every week it waits. Fix
confirmation so a rejected transaction reports the program error instead of a
timeout (F2), which is an afternoon and removes the worst debugging experience
the SDK currently offers. Fold the Poseidon copies into one and decide whether
the WebAssembly oracle is in scope (F3), because that is where a silent
divergence from the program would do the most damage.

## Findings, ordered by how much they would change

| # | Finding | Verdict |
| --- | --- | --- |
| F1 | Zolana depends on no Solana library and hand-writes the transaction compiler, the wire serializer, and the JSON-RPC client. Light reuses `@solana/web3.js`; its newest package uses `@solana/kit`. | Expensive, schedule it |
| F2 | Zolana's confirmation cannot tell a rejected transaction from a dropped one, and classifies a decoded program error as retryable. Light's confirmation is worse: it reports success for a transaction that executed and failed. | Cheap now |
| F3 | Light binds the Rust hasher through WebAssembly and ships no Poseidon. Zolana reimplemented it in TypeScript five times. | Half cheap, half expensive |
| F4 | Light's `TestRpc` reimplements the indexer from on-chain events and is compared against Photon method by method. Zolana's `TestIndexer` is a fixture recorder that cannot substitute for the real one. | Expensive, schedule it |
| F5 | Zolana's error model is richer than Light's, whose taxonomy is dead code, and discards the underlying failure on the way. Three hazards, all local fixes. | Cheap now |
| F6 | Zolana's `Rpc` interface bundles the Solana node and the indexer, so each implementation rejects half of it at runtime. Construction takes four objects where Light takes one string. | Cheap now |
| F7 | Light ships one-call actions over the composable layer. Zolana ships only the composable layer. | Cheap now |
| F8 | Zolana's branded byte types are applied by cast, so the compiler proves nothing. Light's `BN254` is a bare alias and proves less still. | Cheap now |
| F9 | Light executes its browser claim in Chromium. Zolana proves a stronger property statically and never runs the bundle. | Cheap now |
| F10 | Twelve packages against Light's three. Two of Zolana's are the transport and the schema for the same server. | Cheap now, for one merge |
| F11 | Zolana's prover client has retries, timeouts, job polling, and a response cap. Light's has none of them. The only difference in Light's favour is circuit coverage, which Light cannot help with. | Permanent, stop treating as a gap |

---

## F1. Zolana rebuilt Solana's client libraries; Light reuses them

Zolana's TypeScript SDK depends on no Solana package. Across the ten publishable
packages the only third-party runtime dependencies are `@noble/curves`,
`@noble/hashes`, `@noble/ciphers`, `@noble/ed25519`, and `bs58`. Everything
Solana-shaped is written locally: the address and signature types
(`interface/src/index.ts:46-47`), the transaction shape
(`interface/src/index.ts:71`), the compute-budget instruction encoders
(`client/src/client.ts:708-728`), the JSON-RPC client (`client/src/solana-rpc.ts:58-417`),
the wire serializer (`client/src/solana-rpc.ts:464-473`), and the message
compiler (`client/src/client.ts:615-698`).

Light takes `@solana/web3.js` as a peer dependency
(`js/stateless.js/package.json`) and reuses `PublicKey`, `Connection`,
`TransactionMessage`, `VersionedTransaction`, `ComputeBudgetProgram`,
`AddressLookupTableAccount`, and `SolanaJSONRPCError`. Its whole transaction
builder is thirteen lines:

```26:39:js/stateless.js/src/utils/send-and-confirm.ts
export function buildTx(
    instructions: TransactionInstruction[],
    payerPublicKey: PublicKey,
    blockhash: string,
    lookupTableAccounts?: AddressLookupTableAccount[],
): VersionedTransaction {
    const messageV0 = new TransactionMessage({
        payerKey: payerPublicKey,
        recentBlockhash: blockhash,
        instructions,
    }).compileToV0Message(lookupTableAccounts);

    return new VersionedTransaction(messageV0);
}
```

Zolana's equivalent is eighty-three lines that re-derive the runtime's account
ordering from first principles, and the only specification for that ordering is
a comment:

```650:661:sdk-libs/ts/client/src/client.ts
  // `solana_message::Message::new` compiles through `CompiledKeys`, whose
  // `BTreeMap<Address, _>` hands each privilege class back in ascending address
  // order with the fee payer lifted to the front. Ordering by first appearance
  // instead produces a different account list and different compiled indexes
  // for the same instructions.
  const accounts = [...accountMap.values()].sort((left, right) => {
```

Three consequences follow for a caller, and they are not equally serious.

**No address lookup tables.** `compileLegacyTransaction` emits a legacy message.
Light emits v0 and passes lookup tables through, and it does so because it had
to: `js/stateless.js/src/utils/state-tree-lookup-table.ts:1-40` creates lookup
tables holding every state tree and queue address, because compressed
transactions run out of account slots. Zolana's `transact` carries a tree, a
registry, an optional withdrawal, and SPL accounts, and will meet the same
ceiling. Reaching it means writing a v0 compiler as well.

**No interoperation with the wallet ecosystem.** `TransactionSigner`
(`wallet/src/submit.ts:28`) takes Zolana's own `{ messageBytes, signatures }`
object. A caller holding a Phantom or wallet-adapter connection must write an
adapter in both directions, and cannot hand Zolana a `Connection` it already
has. Light's `createRpc` accepts one (`js/stateless.js/src/rpc.ts:251-284`).

**Correctness sits in places no one will look.** `decodeBase58UnknownLength`
recovers an instruction's byte length by attempting every length from one to
1,232 until one parses (`client/src/solana-rpc.ts:608-617`). `compactU16` is
implemented twice, at `client/src/client.ts:730` and
`client/src/solana-rpc.ts:627`. The README already records what happens when
duplicated arithmetic drifts (`README.md:132-141`).

The recommendation is not "depend on web3.js". Zolana's constraints (no
`Buffer`, no `node:*`, no `process`, tree-shakable, browser-first) are the exact
constraints `@solana/kit` was written for, and Zolana's `Transaction` type is
already close to kit's. Light itself has taken that step for its newest package:
`js/token-interface/package.json` depends on `@solana/kit`, `@solana/compat`, and
`@solana/instruction-plans`. Adopting kit's `compileTransaction` and wire
encoding would delete the hand-rolled compiler, the duplicate `compactU16`, the
base58 length search, and the legacy-only limitation at once.

This is expensive: it changes the type at the boundary of `@zolana/client` and
`@zolana/wallet`, so every caller and every test moves with it. It is worth
scheduling before the first release rather than after, because the
`Transaction` shape is public surface and changing it later is a breaking change
for everyone.

## F2. Both SDKs mis-report a transaction that executed and failed

Zolana's `confirmTransaction` returns `false` when the signature status carries
an error:

```293:301:sdk-libs/ts/client/src/solana-rpc.ts
    const decoded = object(status, "result.value[0]");
    if (decoded["err"] !== null) return false;
    return (
      decoded["confirmationStatus"] === "confirmed" ||
      decoded["confirmationStatus"] === "finalized" ||
      decoded["confirmations"] === null
    );
```

`false` is also what a transaction that has not landed yet returns, so
`#waitForSignature` (`solana-rpc.ts:342-360`) keeps polling and resubmitting a
transaction the runtime has already rejected, and after the timeout reports
`CLIENT_CONFIRMATION_TIMEOUT`. The resubmission swallows the reason on the way:
`await resubmit().catch(() => signature)` at `solana-rpc.ts:358` discards a
preflight rejection that says exactly why the transaction will never land.
`confirmPrivateTransaction` inherits this through `pollUntil`
(`client/src/client.ts:496-510`), so a caller whose transfer was rejected for
insufficient balance is told the confirmation timed out.

Light is worse. Its confirmation never inspects `err` at all:

```97:102:js/stateless.js/src/utils/send-and-confirm.ts
            const status = await rpc.getSignatureStatuses([txId]);

            if (status?.value[0]?.confirmationStatus === commitment) {
                clearInterval(intervalId);
                resolve(txId);
            }
```

A transaction that executed and failed reaches `confirmationStatus ===
'confirmed'` with a non-null `err`, so `confirmTx` resolves and
`transfer()` returns a signature for a transfer that did not happen. Do not copy
this. Zolana's behaviour is safe and merely uninformative; Light's is unsafe.

The second half of the finding is that Zolana already decodes the program error
and then throws the information away. `solana-rpc.ts:394-403` turns a JSON-RPC
`InstructionError` into `CLIENT_RPC_PROGRAM_ERROR` carrying a decoded
`ShieldedPoolError`, which is real progress over Rust, whose client error enum
has only `Rpc(String)` (`sdk-libs/client/src/error.rs:186`). But `retryCause`
then classifies the new code as transient:

```149:159:sdk-libs/ts/client/src/retry.ts
    case "CLIENT_RPC":
    case "CLIENT_RPC_HTTP":
    case "CLIENT_RPC_JSON":
    case "CLIENT_RPC_ENVELOPE":
    case "CLIENT_RPC_PROGRAM_ERROR":
```

The comment above it explains why: every code in the list narrows Rust's
`ClientError::Rpc`, which `retry_cause` reports as retryable
(`sdk-libs/client/src/error.rs:230`). That mapping is correct for the codes
Rust actually had. It is wrong for the one TypeScript added, because a program
error is deterministic and no number of retries will change it. Parity with Rust
was preserved by discarding the improvement over Rust.

Both fixes are cheap. Make `confirmTransaction` distinguish "failed" from "not
yet", have `#waitForSignature` raise the program error rather than time out, and
drop `CLIENT_RPC_PROGRAM_ERROR` from `retryCause`. Record the Rust divergence
deliberately rather than leaving it to look like drift.

## F3. Light binds the Rust hasher; Zolana rewrote it five times

Light's published SDK computes no Poseidon hashes. The `LightWasm` interface
(`js/stateless.js/src/test-helpers/test-rpc/test-rpc.ts:70-75`) is satisfied by
`@lightprotocol/hasher.rs`, a WebAssembly build of the same Rust code the
program uses, and it appears only in `test-helpers` and in tests. Every
production path asks the indexer for hashes and proofs instead
(`js/stateless.js/src/rpc.ts:929-977`).

Zolana cannot make that choice wholesale, and the reason is in the protocol
rather than in taste. Light's compressed accounts are public, so the indexer can
hash them and hand the result back. Zolana's outputs are encrypted, so the
client must compute its own commitments and nullifiers. Some client-side hashing
is required.

What is not required is five independent TypeScript reimplementations of it.
The README records the cost: 6,798 round constants and 819 matrix entries
regenerated from the Grain LFSR against Rust's committed tables, 312 parity
tests to establish they agree, two copies that accepted arities the
`sol_poseidon` syscall rejects and so produced digests no validator could
reproduce, and a fifth copy in `client/src/internal.ts` that the coverage audit
missed and that still carries the over-wide table (`README.md:132-141`,
`README.md:165-175`, `README.md:184-186`).

Two separable actions follow. Folding the copies into one is cheap and already
queued. The WebAssembly differential oracle, also queued (`README.md:191`), is
the expensive half and is the one that matters: it replaces "312 tests agree" with
"the same code runs in both languages", which is the guarantee Light bought
outright. If a WASM build of `zolana-hasher` is feasible, consider shipping it as
the default and keeping the TypeScript implementation as the fallback for
environments that cannot load WebAssembly, rather than the other way round.

## F4. Light has an oracle against its indexer; Zolana has none

Light's `TestRpc` is not a mock. It extends `Connection` and implements the same
`CompressionApiInterface` as the Photon-backed `Rpc`
(`js/stateless.js/src/test-helpers/test-rpc/test-rpc.ts:121`), reconstructing
tree state by parsing on-chain events and rebuilding the Merkle tree in
TypeScript. Because it is interface-compatible, tests run both against the same
chain and compare: `js/stateless.js/tests/e2e/rpc-interop.test.ts` is 821 lines
that call `rpc.getValidityProof` and `testRpc.getValidityProof`,
`rpc.getCompressedAccountsByOwner` and `testRpc.getCompressedAccountsByOwner`,
and assert the two agree. That is a differential oracle against the indexer, and
it catches a class of bug that no amount of unit testing reaches: the indexer
returning a well-formed answer that is wrong.

Zolana's `TestIndexer` is a different thing. It is a recorder a test feeds:

```6:16:sdk-libs/ts/test-kit/src/indexer.ts
export class TestIndexer {
  readonly #outputs: IndexedOutput[] = [];
  readonly #nullifiers = new Set<string>();
  readonly #transactions = new Map<Signature, IndexedTransaction>();

  record(transaction: IndexedTransaction): void {
```

Its surface is `record`, `outputs`, `byViewTag`, and `transaction`, none of
which `ZolanaIndexer` exposes, so it cannot be substituted for the real
indexer, and nothing in the tree compares the two.

Zolana's own oracle discipline is real and Light has no counterpart to it: the
interface batch generated a JSON oracle from the `zolana-interface` crate and
compared TypeScript against it, closing 33 rows without touching a source file
and catching an asymmetry in the merge codecs that side-by-side reading had
recorded as parity twice (`README.md:143-148`). That covers a different seam. The
Rust oracle answers "does TypeScript encode what Rust encodes". Light's interop
test answers "is the indexer telling us the truth". Zolana has the first and not
the second.

The seam is cheaper to close here than it was for Light, because Photon lives in
this repository (`services/photon`) and consumes the same `zolana-event` and
`zolana-interface` crates, so a divergence is a genuine bug rather than a version
skew. It is still expensive: it means a TypeScript reimplementation of view-tag
scanning, output decryption, and tree reconstruction, kept interface-compatible
with `ZolanaIndexer`. Schedule it, and note that the end-to-end harness cannot
currently run alongside the batches (`README.md:287-293`), so this work depends
on that being fixed first.

## F5. Zolana's error model is far better and drops the evidence

Light's error taxonomy is dead code. `js/stateless.js/src/errors.ts` defines nine
enums and nine `MetaError` subclasses under a `// TODO: Clean up` on line 1, and
not one of them is referenced anywhere else in `js/src`. The real style is
`throw new Error(...)`, twenty-three of them in `rpc.ts` alone, plus
`SolanaJSONRPCError` for RPC failures. Zolana's model is better in kind: 140
codes with a per-code detail schema, a runtime validator, and a redaction layer
with no Rust counterpart (`client/src/error.ts`). Keep it. Three specific things
about it would change a caller's experience.

**The message is the code.** `ClientError` passes the code as the `Error`
message (`client/src/error.ts:530`), so `err.message` reads `CLIENT_RPC_HTTP`
with no method, no URL, and no status. The status is in `.details`, which
survives `util.inspect` but not any logger that forwards `err.message`, and not
a browser `throw`. Light's messages name the operation and the operand:
`` `failed to get info for compressed account ${hash}` `` at
`js/stateless.js/src/rpc.ts:835`. Composing the message from the code plus the
details is a few lines in the constructor and costs nothing structurally.

**A bad construction replaces the real failure.** `validateClientError` throws a
bare `TypeError` when a detail field is missing or mistyped
(`client/src/error.ts:615-639`). That check runs on the error path, which is the
least forgiving place to fail closed: a typo in a detail key at a rarely reached
call site converts a real failure into `TypeError: missing details for
CLIENT_X`, with the original cause gone. Keeping the assertion under test and
degrading to "drop the bad details, keep the code" in a production build
preserves the discipline without the failure mode.

**The underlying error is discarded.** `safeCause` reduces anything it does not
recognise to `{ category: "external" }` (`client/src/error.ts:601`), so a
`TypeError: fetch failed` from an unreachable prover arrives with no message and
no stack, and because that object becomes the `Error`'s own `cause`, the stack
chain is severed too. Light keeps the `SolanaJSONRPCError` with the server's
text. The pattern that resolves the tension already exists in this repository:
`KeypairError` keeps its dependency cause non-enumerable so it is available to a
debugger and invisible to `JSON.stringify` (`README.md:118-122`). Apply the same
to `ClientError` and both properties hold.

## F6. `Rpc` bundles two servers, and construction takes four objects

Zolana's `Rpc` interface (`client/src/rpc.ts:100-137`) mixes Solana node
methods (`getAccount`, `getBalance`, `getLatestBlockhash`, `sendTransaction`)
with indexer methods: `getMerkleProofs`, `getNonInclusionProofs`,
`getInputMerkleProofs`. No single server answers both, so every implementation
implements half of it and rejects the rest at runtime:

```313:321:sdk-libs/ts/client/src/solana-rpc.ts
  getMerkleProofs(
    _treeAccount: Address,
    _leaves: readonly Bytes32[],
    _config?: IndexerRpcConfig,
    _context?: RequestContext,
  ): Promise<GetMerkleProofsResponse> {
    void [_treeAccount, _leaves, _config, _context];
    return Promise.reject(unsupported("getMerkleProofs"));
  }
```

`ZolanaClient` also declares `implements Rpc` and then forwards seven methods
verbatim to `this.rpc` (`client/src/client.ts:140-174`), which is inheritance
written out longhand. Light gets the same composition from
`class Rpc extends Connection implements CompressionApiInterface`
(`js/stateless.js/src/rpc.ts:689`): the Solana surface comes from the base class,
the compression surface is one interface, and a caller who needs
`getSlot` or `simulateTransaction` has it.

Splitting `Rpc` into a node interface and an indexer interface is a
type-level change with no runtime cost, and it removes three throwing stubs and
seven forwarding methods.

The construction sequence is the second half. Light:

```251:256:js/stateless.js/src/rpc.ts
export function createRpc(
    endpointOrWeb3JsConnection?: string | Connection,
    compressionApiEndpoint?: string,
    proverEndpoint?: string,
    config?: ConnectionConfig,
): Rpc {
```

One argument, and the indexer and prover endpoints default from it; no argument
at all gives the three local ports. Zolana requires the caller to build
`SolanaRpc`, `ZolanaIndexer`, and `ProverClient`, then pass all three plus a tree
address into `new ZolanaClient({...})` (`client/src/client.ts:80-89`), and the
constructor then duck-types what it was handed (`client.ts:91-109`). A
`createZolanaClient(url, options?)` that fills the three endpoints and resolves
the tree is cheap and removes the most common source of setup error.

Light's defaulting has a trap worth not copying: when the caller passes one
endpoint, the prover endpoint defaults to it (`js/stateless.js/src/rpc.ts:271-276`),
so `/prove` is sent to a Solana RPC node and fails with a confusing error.
Default the local ports, require the prover URL to be explicit otherwise.

## F7. Light ships actions; Zolana ships only the pieces

Light's whole compressed-lamport transfer is one call with five arguments:

```30:37:js/stateless.js/src/actions/transfer.ts
export async function transfer(
    rpc: Rpc,
    payer: Signer,
    lamports: number | BN,
    owner: Signer,
    toAddress: PublicKey,
    confirmOptions?: ConfirmOptions,
): Promise<TransactionSignature> {
```

Inside, it paginates the account scan, selects inputs, fetches the validity
proof, builds the instruction, signs, sends, and confirms
(`js/stateless.js/src/actions/transfer.ts:38-102`). The composable layer is still
there underneath, as `LightSystemProgram.transfer` at line 85, so a caller who
needs to control input selection or batch instructions drops down to it.

Zolana's shielded transfer has no such entry point. A caller constructs the four
client objects, calls `syncWallet` to populate a `Wallet`, calls `createTransfer`
to get an `UnsignedPrivateTransaction`, calls `signPrivateTransaction`, sends,
calls `confirmPrivateTransaction`, and calls `syncWallet` again. The imports in
the end-to-end test span six packages
(`sdk-libs/ts/e2e/actions/actions.test.ts:1-45`).

Most of that shape is protocol-rooted and should stay. Zolana holds private state
the client must maintain, so a `Wallet` and a `sync` step exist and Light has no
counterpart. The build/sign split is a real improvement, not overhead: it is what
lets a `WalletAuthority` hold a P256 key, sign on a rail the notes do not
determine (`wallet/src/private-transaction.ts:77-89`), and prompt for approval
before the proof inputs are finalised (`private-transaction.ts:135-138`). Light
cannot express any of that, because its owner is a `Signer`.

What is not protocol-rooted is that there is no convenience layer at all. A
`transfer({ client, wallet, authority, feePayer, recipient, asset, amount })`
in `@zolana/wallet` that runs the sequence and returns a confirmed signature is
a thin composition of functions that already exist, and it is the difference
between an SDK a newcomer can start with and one they must first read.

## F8. Branded bytes proved by cast, and an alias that proves nothing

Zolana's fixed-width types are nominal:

```42:53:sdk-libs/ts/interface/src/index.ts
type FixedBytes<Length extends number> = Uint8Array & {
  readonly __fixedBytesLength: Length;
};

export type Address = string & { readonly __address: unique symbol };
export type Signature = string & { readonly __signature: unique symbol };
export type Bytes16 = FixedBytes<16>;
export type Bytes31 = FixedBytes<31>;
export type Bytes32 = FixedBytes<32>;
```

Light's field-element type is `export type BN254 = BN`
(`js/stateless.js/src/state/BN254.ts:12`), a plain alias with no nominal
component at all, so any `BN` satisfies any `BN254` parameter. Validation exists
but only inside `createBN254` (`BN254.ts:15-28`), and nothing routes values
through it. Zolana's design is better and should stay.

The gap is that the brand is only ever applied by assertion:
`new Uint8Array(utxoHash) as Bytes32` (`client/src/client.ts:230`),
`value.slice() as Bytes32` (`interface/src/index.ts:348`). A cast asserts the
length rather than establishing it, so the type carries a claim the compiler has
not checked, and the actual length check happens separately and imperatively a
few lines away (`client/src/client.ts:217-227`). One validating constructor per
width, plus a lint rule forbidding the bare cast outside it, converts the brand
from documentation into a guarantee. Cheap, and worth doing before the surface is
public.

A related divergence is not a defect on either side. Light models field elements
as `BN`, which buys arithmetic and base58 for free and matches the base-10
encoding its circuits want. Zolana models them as byte arrays, which buys
byte-exact comparison against Rust fixtures. Both are right for their test
strategy.

## F9. Light runs its browser claim; Zolana checks a stronger property statically

Zolana's browser gate scans every source file for `Buffer`, `require(`, `node:`,
and `process`, then bundles the whole graph with esbuild under the `browser`
condition and scans the output for the same tokens
(`sdk-libs/ts/config/browser-check.mjs:29-92`). That is a stronger static
property than Light holds: Light's `./browser` entry point still ships a `buffer`
polyfill as a runtime dependency (`js/stateless.js/package.json`), which Zolana's
gate would reject outright.

Light's gate is a different kind. `playwright.config.ts` starts `http-server` on
port 4004, and `tests/e2e/browser/rpc.browser.spec.ts` loads the built bundle in
Chromium and calls `createRpc().getCompressedAccountsByOwner(...)` inside
`page.evaluate`, asserting on the result. That proves the bundle loads and
executes in a browser, which a static scan cannot: a missing Web Crypto
algorithm, an ESM condition that resolves to a Node build of `@noble`, or a
top-level `await` a target does not support all pass Zolana's check and fail in
Chromium.

The two gates are complementary and neither subsumes the other. Adding Light's is
about fifteen lines of Playwright configuration plus one spec, and it is the only
place Light's browser story is ahead.

## F10. Twelve packages, two of which are one package

Light ships three: `stateless.js` (the RPC, state types, program layouts,
actions, and, notably, the test helpers, exported from the root index at
`js/stateless.js/src/index.ts:4`), `compressed-token`, and `token-interface`.
Zolana ships ten publishable packages plus `config`, `e2e`, `fixtures`,
`reports`, and `vectors`.

Most of Zolana's boundaries earn their cost, and they earn it in a way Light's do
not. `@zolana/interface` has one runtime dependency and no protocol logic, so a
program author or an explorer can take the codecs without the client.
`@zolana/keypair` isolates the secret material and the redaction discipline that
protects it. `@zolana/test-kit` as a separate package is a better call than
Light's, which puts `test-helpers` on the published root surface and so ships a
mock RPC and a TypeScript Merkle tree to every production consumer.

Two boundaries do not earn it. `@zolana/api` is a single 527-line file
(`sdk-libs/ts/api/src/index.ts`) whose only dependencies are `@zolana/interface`
and `@zolana/indexer-api`; `@zolana/indexer-api` is six files whose only
dependency is `@zolana/interface`. They are the transport and the schema for the
same server, both browser-safe, and nothing consumes one without the other.
Merging them removes a package, a build step, a typecheck step, and six test
configurations.

The split has a cost the README has already paid once and is worth stating
plainly: packages resolve each other through their `exports` map, so a
cross-package test imports `dist` rather than `src`, and a stale `dist` after a
merge produced what looked exactly like a cross-batch regression in secret
redaction (`README.md:84-90`). That cost scales with package count, and it is the
argument for not adding more.

## F11. The prover client is Zolana's, and Light has nothing to teach it

Light's prover client is a fifty-line function
(`js/stateless.js/src/rpc.ts:356-410`): one `fetch`, no timeout, no retry, no
job polling, three circuit types selected by a string literal, and a
`response.statusText` in the error. Zolana's `ProverClient`
(`client/src/prover/client.ts`) validates the URL and rejects credentials in it,
retries three times, bounds each request at 600 seconds sized deliberately for a
cold load of a 63MB proving key (`client.ts:20-22`), polls `/prove/status` for
queued proofs with a floor on the interval so a misconfigured client cannot spin
(`client.ts:24`, `client.ts:33-42`), and caps the response at one megabyte
(`client.ts:16`).

The boundary is also drawn more carefully. Zolana separates assembling inputs
(`prover/assembly.ts`), calling the prover (`prover/client.ts`), and parsing and
compressing the response (`prover/proof.ts`); Light's `proverRequest` builds the
request body, calls, parses, negates, and compresses in one function.

The remaining difference is coverage, not shape: the Rust client emits eight
`circuitType` values and TypeScript emits four (`README.md:200-206`). That is a
scheduled gap in Zolana's own plan, and Light, which has three circuit types
because its protocol has three, has nothing to contribute to closing it. Stop
reading this area as a place where Zolana is behind.

---

## Where Zolana is already ahead

Collected so the list is visible in one place, because a document organised
around what to change reads as though everything needs changing.

**Error redaction with no Rust counterpart.** `sanitizeDetails` and `safeCause`
(`client/src/error.ts:565-710`) bound what reaches an error surface, and the
call-site discipline behind them is asserted by a test that scans the sources
(`README.md:115-123`). Rust cannot do this: `KeypairError` derives `Copy` so its
payload holds no owned data, but `ClientError::Keypair` prints the inner payload
verbatim through `source()` (`README.md:125-130`). Light has neither the layer
nor the discipline, and its error taxonomy is nine unused classes under a
`// TODO: Clean up`.

**Response parsing that is typed.** Light's `rpc.ts` reaches for `as any`
throughout, with a `// TODO: fix type` above one of them
(`js/stateless.js/src/rpc.ts:1018-1038`), and its V1/V2 branching doubles every
parse path (`rpc.ts:2008-2093`). Zolana decodes through narrow validators that
name the failing path (`client/src/solana-rpc.ts:652-681`), so a malformed
response produces `CLIENT_INVALID_RPC_RESPONSE` with `details.path` rather than
`undefined is not a function` three frames later.

**Confirmation that refuses rather than lies.** See F2. Light's returns a
signature for a transaction that failed.

**A browser gate that would reject Light.** `browser-check.mjs` forbids
`Buffer`, `require(`, `node:`, and `process` in both source and bundle. Light
ships `buffer` as a runtime dependency of its browser entry point.

**The Rust JSON oracle.** Generating fixtures from the real crate and comparing
TypeScript against them, rather than reading the two languages side by side, is
the single most productive technique in this port (`README.md:143-148`), and
Light has nothing like it. Keep applying it; F4 asks for a second oracle at a
different seam, not a replacement for this one.

**The build and sign split.** `buildPrivateTransaction` and
`signPrivateTransaction` are separate (`wallet/src/private-transaction.ts:176`,
`:198`), and signing re-verifies that every field feeding each input commitment
still matches the wallet's view before it signs (`private-transaction.ts:52-75`).
Light's `transfer` builds and signs in one closure with a `Signer`.

## Differences rooted in the protocols, not in taste

These are not gaps and should not be scheduled as though they were.

**The P256 ownership rail.** Ownership can sit on a key Solana does not verify,
so the signing rail is a property of the authority rather than of the notes
being spent (`wallet/src/private-transaction.ts:77-89`), the proof carries a
BSB22 commitment the eddsa rail does not, and the client must produce a P256
signature over a message hash. Light has one rail and no counterpart to any of
it.

**Zone transactions and zone authorities.** No Light analogue exists. The
missing zone provers are a coverage gap in Zolana's own plan, not a shape
Zolana should be reading out of Light.

**Client-side commitment and nullifier computation.** Light's compressed
accounts are public, so the indexer hashes them and the SDK asks for the result.
Zolana's outputs are encrypted, so the client must compute its own. This is why
the SDK carries Poseidon at all; F3 is about how many copies of it, not whether
it belongs.

**Client-held wallet state and a sync step.** Light queries the indexer by owner
and gets its accounts back. Zolana scans view tags, decrypts what matches, and
maintains a local `Wallet` of unspent notes, so `syncWallet` exists and there is
nothing in Light to compare it against.

**Field elements as bytes rather than as `BN`.** Both are correct for the
oracle each SDK tests against. See F8.

## Survey: the seams not covered above

**How each supplies an endpoint.** Light: one optional argument, a string or an
existing `Connection`, from which the indexer and prover endpoints default, and
no argument at all gives the three local ports
(`js/stateless.js/src/rpc.ts:251-284`). Zolana: three constructed objects, each
validating its own URL and rejecting embedded credentials, a fragment, or a
non-HTTP scheme (`client/src/solana-rpc.ts:82-99`,
`client/src/prover/client.ts:57-80`). Zolana's validation is better and its
ergonomics are worse; the two are independent and F6 asks only for the second.

**Caching.** Light caches state tree infos for an hour behind a single in-flight
promise so concurrent callers share one fetch
(`js/stateless.js/src/rpc.ts:721-748`). Zolana caches nothing: `ZolanaClient`
takes its tree as a constructor argument and every indexer call goes to the
wire. For a single-tree deployment that is the right answer, and it becomes
wrong the moment a second tree exists.

**Instruction decoding as public surface.** Light exports
`deserializeAppendNullifyCreateAddressInputsIndexer` from
`js/stateless.js/src/programs/system/layout.ts`, naming its consumer in the
symbol. Zolana exports the data codecs from `@zolana/interface/codecs`, which is
the harder half, but keeps the instruction-level decoder private to the RPC
adapter: `transactViewTags` (`client/src/solana-rpc.ts:531-552`) dispatches on
the tag byte, decodes the payload, and resolves an owner tag against the
instruction's account list, and none of that is reachable from outside. An
explorer or a competing indexer would reimplement it. Promoting it to
`@zolana/interface` is cheap and is the same rule the README already adopted,
applied in the direction it has not yet been applied.

**Pagination.** Both drain their cursors and neither exposes an iterator for
doing so. Light's transfer action loops over `getCompressedAccountsByOwner`
until it has enough lamports or the page is short
(`js/stateless.js/src/actions/transfer.ts:45-68`), so every caller working at the
RPC layer repeats that loop. Zolana's `syncWallet` drains both the transaction
and the encrypted-output endpoints to exhaustion and deduplicates across them
(`wallet/src/sync.ts:187-239`), which is the more careful of the two. The single
place Zolana caps a page rather than draining is confirmation, and it does so
deliberately: `limit: 50` with a comment recording that omitting it let a busy
tag push the signature off the first page (`client/src/client.ts:515-519`).
Nothing to change here.

**Compute budget.** Light sets 350,000 units in the action
(`js/stateless.js/src/actions/transfer.ts:96`). Zolana defaults to 300,000 with a
constructor override and an optional priority fee
(`client/src/client.ts:42`, `:111-128`), which is better, and then hard-codes
1,400,000 for both merge paths (`client/src/client.ts:583`, `:604`) where the
override does not reach. Light also ships
`utils/calculate-compute-unit-price.ts` for priority-fee estimation, which
Zolana has no equivalent for; that is a small, self-contained thing to port if
mainnet submission is in scope.

**Where the prover boundary sits.** Light assembles, calls, parses, negates, and
compresses inside one function (`js/stateless.js/src/rpc.ts:356-410`). Zolana
splits assembly (`prover/assembly.ts`), transport (`prover/client.ts`), and
parsing with compression (`prover/proof.ts`), which is why its proof compression
can carry its own vector tests
(`client/test/vectors/proof-compression.test.ts`). Zolana's boundary is the
better one and needs no change.

