# Quality and completeness audit of `sdk-libs/ts`

**Functionality was cut, and the cut is documented rather than hidden: four of the eight prover request shapes the Rust client can emit have no TypeScript path at all, so no TypeScript caller can prove a zone transaction on either rail, a zone-authority transition, or a forester address append. Shortcuts were taken, and two of them were still live when this audit started: the client's Poseidon copy accepted arities the chain cannot verify, and keypair's `bigIntToBytes` truncated silently above 2^256. Both are fixed here. Code quality is otherwise good: no `any`, no `@ts-ignore`, no `eslint-disable`, and no swallowed error in any source file.**

Audited at `9bea051d` on `ts-sdk-port`, 2026-07-25. Evidence commands were run in this worktree; every claim below names a file and a line.

The pattern behind the two live defects is worth naming, because it will recur. Both are *stranded copies*: a helper duplicated across packages, fixed in one copy, and left alone in the others because nothing compared the others to Rust. The client is the package that had no Poseidon parity suite, and it is the package whose Poseidon copy was wrong. Keypair is the package whose `bigIntToBytes` had no vector test, and it is the copy that still truncated. Duplication is not only a tidiness problem here; it is the mechanism by which a fix fails to land.

## Severity ordering

| # | Finding | Kind | State |
| --- | --- | --- | --- |
| [F1](#f1) | Four of eight prover circuit types have no TypeScript path | Functionality missing | Recorded; already deferred to PKP-05 |
| [F2](#f2) | Client Poseidon hashed past arity 12, producing unverifiable digests | Functionality wrong | **Fixed** at `a8285d49` |
| [F3](#f3) | Keypair `bigIntToBytes` truncated at 2^256 and accepted negatives | Functionality wrong | **Fixed** at `a8285d49` |
| [F4](#f4) | Two hash-chain tests asserted only on the fixture and could not fail | Test cannot fail | **Fixed** at `9bea051d` |
| [F5](#f5) | TypeScript rejects merge ciphertexts the Rust SDK decodes | Stricter than Rust | Recorded |
| [F6](#f6) | `check:static`, which CI runs, was red on the branch | Gate | Being fixed in-tree by another worker |
| [F7](#f7) | Eight unreachable exports, including `OutputUtxo` and the zone merge assembler | Dead code | Recorded |
| [F8](#f8) | `create_two_inputs_hash_chain`: the "seven callers" claim is wrong | Correction | Recorded |
| [Q1](#q1) | Five Poseidon implementations, none of them line-for-line identical | Quality | Recorded, with why the fold is not one commit |
| [Q2](#q2) | Three definitions of the same wire discriminants | Quality | Recorded |
| [Q3](#q3) | `assembleMergeWithProofsUnchecked` named for a check it performs | Quality | **Fixed** at `f0332e8b` |
| [Q4](#q4) | Fixture-recording tests inflate the headline test count | Quality | Recorded |

## Functionality missing or wrong

### F1

**Four of the eight prover request shapes have no TypeScript path.** `sdk-libs/client/src/prover/json.rs` emits eight `circuitType` values. TypeScript emits four.

| Rust `circuitType` | Emitted by | TypeScript |
| --- | --- | --- |
| `transfer-confidential` | `json.rs:407` | `client.ts:290` |
| `transfer-p256-confidential` | `json.rs:235` | `client.ts:290` |
| `merge` | `json.rs:309` | `client.ts:101` |
| `merge-zone` | `json.rs:315` | `client.ts:105` |
| `transfer-zone` | `json.rs:419` | none |
| `transfer-p256-zone` | `json.rs:240` | none |
| `transfer-zone-authority` | `json.rs:414` | none |
| `address-append` | `json.rs:363` | none |

The missing builders are `ZoneTransferProver` (`prover/transact/zone_eddsa.rs`), `ZoneTransferP256Prover` (`zone_p256.rs`), `ZoneAuthorityProver` with its `ZoneAuthorityProofResult` and `ZoneAuthorityWitness` (`zone_authority.rs`), and `BatchAddressAppendInputs` (`prover/inputs.rs`). `sdk-libs/ts/client/src/prover/` has no zone module; `find` returns `assembly.ts`, `client.ts`, `index.ts`, `merge.ts`, `proof.ts`, `types.ts`.

**A reader should conclude this is a real gap that is honestly booked, not a hidden one.** `public-exports.md:1250` defers the three zone provers to PKP-05 under rows C13, C14, and C18; row C07 dispositions `BatchAddressAppendInputs` as `NOT_APPLICABLE` on the sound argument that TypeScript ships no forester, so the type would have neither producer nor consumer. Two things still need doing. `inventory-client.md:61` still carries disposition `port` and promises `src/prover/zone-authority.ts` plus `fixtures/client/zone_authority.json`, neither of which exists, so the inventory and the checklist disagree; one of them must move. And the consequence is worth stating plainly in the status table rather than only in a row: the transaction and interface packages already build `PreparedZoneAuthority` and the zone instruction data, so a TypeScript caller can assemble a zone-authority transaction all the way up to the point of proving it and then cannot finish. A pipeline that stops one step short is more misleading than one that is absent.

### F2

**`sdk-libs/ts/client/src/internal.ts:26` carried a sixteen-entry partial-round table where every other copy carries twelve.** The four other TypeScript Poseidon copies stop at twelve inputs because `light_poseidon` caps the width at 13 and the `sol_poseidon` syscall takes at most twelve arguments. The client's copy listed partial-round counts for widths 14 through 17 as well, so `poseidon()` with 13 to 16 inputs returned a digest instead of raising. That digest is not reproducible by any on-chain verifier, which makes it worse than an error: it is a wrong answer that looks like a right one.

**Why it survived:** the client is the only one of the five packages with a Poseidon implementation that had no Poseidon parity suite. `interface`, `keypair`, `merkle-tree`, and `transaction` each have `test/vectors/poseidon-parity.test.ts`; `client` had none. The shared fixture `vectors/poseidon-parity-v1.json` already contains a `poseidon-reject-arity-above-max` case with 13 inputs, so the vector to catch this existed and nothing consumed it.

**Fixed** at `a8285d49`: the table is truncated to twelve and `client/test/vectors/poseidon-parity.test.ts` compares the client copy against all 100 digest vectors, the reject cases, and the arity boundary. A control edit restoring the wide table fails two of its cases, so the test is falsifiable.

**Note this defect was queued and not dispatched.** The plan README lists "a fifth Poseidon copy in `client/src/internal.ts` that the coverage audit missed and that still carries the over-wide arity table, a one-line change held only because a worker owns that file". A correctness defect on the proof path should not wait on file ownership; the holding cost was higher than the conflict cost.

### F3

**`sdk-libs/ts/keypair/src/bytes.ts:36` `bigIntToBytes` wrote the low bytes of any value.** Rust's `bigint_to_be_bytes_array` (`program-libs/hasher/src/bigint.rs:23`) takes a `BigUint`, so a negative has no representation, and returns `HasherError::InvalidInputLength` when the value needs more bytes than the array holds. The TypeScript copy did neither: at or above 2^256 it silently kept the low 32 bytes, and for a negative value `BigInt` arithmetic shifted in an all-ones prefix, so `-1n` encoded as 32 bytes of `0xff`.

**The blast radius was latent, not live.** `bigIntToBytes` is not in `keypair/src/index.ts`, so no external caller reaches it, and both internal callers (`poseidon.ts:61` and `merge/core.ts`) pass values already below the BN254 modulus. The finding is that the guard was missing, not that a user was harmed.

`sdk-libs/ts/merkle-tree/src/bytes.ts:36` had the same defect, was fixed, and carries a comment explaining exactly why truncation is wrong. The keypair copy was not fixed alongside it.

**Fixed** at `a8285d49`, matching the Rust error shape: the reported byte width is the same figure `InvalidInputLength` carries, so `2^256` reports 33 against an expected 32, as `vectors/program-libs-parity-v1.json` `hasher.bigint.rejects[0].beError` records. `keypair/test/vectors/program-libs-bigint.test.ts` pins it against the same Rust vectors `merkle-tree` already consumes.

### F4

**`sdk-libs/ts/transaction/test/vectors/program-libs-event.test.ts:137` and `:146` asserted only on the fixture.** The first, "returns a single element unhashed", found the `single` vector and asserted `single.output === single.inputs[0]`. The second, "is order sensitive", found the `pair` and `pair-reversed` vectors and asserted their outputs differ. Neither called `hashChain`. No change to any TypeScript source file could have failed either one; they tested that the Rust generator emits what the Rust generator emits.

Both are in the file whose name claims to check `hash_chain.rs` against the port, which is what makes them worse than merely useless: they read as coverage of the thing they do not touch.

**Fixed** at `9bea051d`: both now run their inputs through `hashChain` and compare against the recorded Rust output.

**One skipped test exists and it is legitimate.** `sdk-libs/ts/test-kit/test/user-registry.live.test.ts:17` gates its `describe` on `process.env["ZOLANA_TEST_LIVE"] === "1"`. It is an opt-in localnet lifecycle test that needs a validator, and it was run manually and passed (`review-2026-07-24.md`, row V4). The residual is that no CI job sets the variable, so the registry merge-enable lifecycle has no automated coverage; `.github/workflows/typescript.yml` never sets it.

### F5

**`sdk-libs/ts/interface/src/codecs/index.ts:454` and `:525` reject a merge ciphertext whose first byte is not `2`; the Rust SDK does not.** `MergeTransactIxDataRef::from_bytes` (`program-libs/interface/src/instruction/instruction_data/merge_transact.rs:81`) calls `validate_shape`, which checks four lengths and nothing else. There is no prefix check anywhere in the Rust codec.

This is the residue of the guard that the scope audit reverted from `program-libs/`. The Rust half is gone; the TypeScript half is not.

**A reader should conclude the encode side is harmless and the decode side is a real asymmetry.** The shielded-pool program does reject a non-`2` prefix, at `programs/shielded-pool/src/instructions/merge/processor.rs:32` and `merge_zone/processor.rs:39`, with `InvalidMergeOutputScheme`. So refusing to *build* such an instruction blocks nothing the chain would have accepted. Refusing to *decode* one is different: `readMergeData` at line 525 throws `INTERFACE_CODEC` where Rust hands back the parsed structure, so a TypeScript tool inspecting a rejected or malformed on-chain instruction cannot read it while the Rust tool can. That is a diagnostic path, so severity is low, but the two languages should agree and today they do not. Rows I08, I20, and I21 are the rows that flipped from `DIVERGENT` to `PARITY` and back on this exact question; the code state above is what those rows should be judged against.

### F6

**`npm run check:static` failed on the branch as of 20:53, which fails the `static` job in `.github/workflows/typescript.yml:75`.** Two errors, both in files no in-flight batch had touched:

```
sdk-libs/ts/interface/src/codecs/index.ts:141  @typescript-eslint/no-confusing-void-expression
sdk-libs/ts/interface/src/instructions/index.ts:14  'Bytes64' is defined but never used
```

The README's status line reads "1018 unit tests pass, typecheck, lint, and the checklist gate clean". That is true of `npm run lint`, which lints only `eslint.config.js`, `prettier.config.js`, `vitest.config.js`, and `sdk-libs/ts/config`. It lints no package source. The script that lints package source is `lint:packages`, and it was failing. Quoting "lint clean" without naming which script is how a red CI job gets recorded as green.

Another worker fixed both in-tree while this audit was running; `npm run lint:packages` is clean as of 20:59. The lesson stands.

### F7

**Eight exports have no consumer anywhere in `sdk-libs/ts`, including tests.** Found by scanning every `export` in every `src/` tree for references in every other TypeScript file in the workspace.

| Symbol | Location | Note |
| --- | --- | --- |
| `OutputUtxo` | `interface/src/index.ts:222` | No codec, no importer, no consumer. Confirms the README's claim exactly. |
| `assembleMergeZoneWithProofs` | `client/src/prover/merge.ts:130` | The zone counterpart of `assembleMergeWithProofs`, which `client/test/merge.test.ts:293` does exercise. Not reachable, not tested, and its comment claims a parity with the fetching path that nothing checks. |
| `p256SignatureBytes` | `wallet/src/private-transaction.ts:219` | Not re-exported by `wallet/src/index.ts`. |
| `random16` | `transaction/src/internal.ts:151` | |
| `checked33` | `transaction/src/internal.ts:192` | |
| `copy32` | `wallet/src/internal.ts:7` | |
| `base64Bytes` | `wallet/src/internal.ts:213` | |
| `TRANSFER`, `SPLIT`, `MERGE`, `TRANSFER_PLAINTEXT`, `VIEW_TAG_LEN`, `DEFAULT_TAG_WINDOW` | `transaction/src/index.ts:75-80` | Public exports with no consumer; see [Q2](#q2). |

None were deleted here. The `internal.ts` helpers sit in files that `port/transaction` and `port/wallet-misc` are still editing, and deleting `assembleMergeZoneWithProofs` would remove a capability the Rust SDK has (`MergeZoneWitness`) rather than tidy up. The right disposition for that one is to export and test it, which is a surface change gated by `public-exports.md`.

### F8

**`create_two_inputs_hash_chain` has no production Rust caller, so the "seven callers on the proof path" claim is wrong.** `rg` across the whole repository finds it at its definition (`program-libs/hasher/src/hash_chain.rs:46`), in the hasher's own tests, and in `xtask/src/bin/program-libs-parity.rs`. Nothing else. The seven proof-path callers are callers of `create_hash_chain_from_slice`, which *is* ported, as `hashChain` in `transaction/src/internal.ts:123` and `client/src/internal.ts:126`, and which the fixture and the tests do cover.

The correct conclusion is the opposite of the one recorded: **do not port it.** Adding a function with no TypeScript caller would be dead code, and F7 already lists eight of those. The two functions genuinely differ, since `H(i) = H(H(i-1), first[i], second[i])` is not a fold of the single-input chain, so anyone who did need it could not build it from `hashChain`, but nobody needs it.

One real residue: the Rust generator emits `hasher.hashChain.createTwoInputsHashChain` vectors and a `twoInputsLengthMismatch` error case into `vectors/program-libs-parity-v1.json`, and no TypeScript test reads either. Unconsumed vectors in a committed oracle invite exactly the misreading above. Either drop them from the generator or annotate them as recorded-not-compared, the way `merkle-tree/test/vectors/program-libs-hasher.test.ts:52` annotates `Sha256BE`.

## Quality only

### Q1

**Five Poseidon implementations, and the claim that three are line-for-line identical does not hold.**

| Location | Signature | Error type |
| --- | --- | --- |
| `interface/src/merge-utils.ts:29` | `Uint8Array[] -> Bytes32` | `InterfaceError("INTERFACE_HASH")` |
| `keypair/src/poseidon.ts:17` | `Uint8Array[] -> Uint8Array` | `KeypairError("KEYPAIR_POSEIDON")`, with a distinct `KEYPAIR_FIELD_ELEMENT_TOO_LONG` |
| `transaction/src/internal.ts:91` | `Uint8Array[] -> Bytes32` | `TransactionError("TRANSACTION_HASH")` |
| `client/src/internal.ts:100` | `bigint[] -> bigint` | `ClientError("CLIENT_HASHER")` |
| `merkle-tree/src/hashers.ts` | `Hasher32` object | `MerkleTreeError` |

What is identical across all five is the mechanism: the same BN254 modulus, the same twelve-entry partial-round table (after F2), the same `grainGenConstants` call, and the same per-arity permutation cache. What differs is the boundary: input and output types, and the error each raises. So the fold is real but it is not a deletion. It needs a core that takes an error factory, with each package keeping its own wrapper so no thrown code changes.

**This was not folded here, deliberately.** The core would have to live in `@zolana/interface`, the only package all four others depend on, and `@zolana/interface`'s export map is checked by `workspace-check.mjs` against a fixed `entryPoints` list, so adding a subpath is a gated surface change. More importantly `port/transaction`, `port/wallet-misc`, and the client work are all in flight, and a change touching four packages at once would conflict with three of them. It belongs in one dedicated commit after the batches land, which is where the README already queued it. What was fixed instead is the thing that made the fifth copy dangerous rather than merely redundant.

### Q2

**Three definitions of the same wire discriminants.** `transaction/src/index.ts:75-78` exports `TRANSFER = 1`, `SPLIT = 2`, `MERGE = 3`, `TRANSFER_PLAINTEXT = 4`. `transaction/src/serialization/codecs.ts:19` separately declares `const SPLIT_TYPE_PREFIX = 2`, and line 538 defaults a parameter to the literal `expectedTypePrefix = 4`. The codecs, which are the only code that reads or writes these bytes, use the local constant and the literal; the exported constants have no consumer at all.

The Rust originals are used: `sdk-libs/transaction/src/serialization/plaintext.rs:131` checks `parsed.type_prefix != TRANSFER_PLAINTEXT`. The port copied the constants to the package root and then did not wire them to the code that needs them. A reader should conclude that a change to the wire format would have to be made in three places and that two of them are silent.

### Q3

**`assembleMergeWithProofsUnchecked` (`client/src/prover/merge.ts:153`) was named for a check it runs.** It calls `validateMergeMaterial` at line 160; the only thing it leaves to its caller is deciding which merge rail `prepared` belongs to. The two proof-fetching entry points therefore validate twice, which is deliberate, because it fails before the indexer round trip, but nothing said so.

**Fixed** at `f0332e8b`: renamed to `assembleMergeRailUnchecked` with the double validation explained. Private function, no behaviour change.

### Q4

**Some vector tests record Rust facts rather than compare TypeScript against them, and they count toward the headline number.** `merkle-tree/test/vectors/program-libs-hasher.test.ts:44`, `:52`, `:82`, and `:123` assert only on fixture contents. Unlike F4 these are honest, because lines 53 and 83 carry comments saying precisely that no TypeScript counterpart exists to compare, and pinning a Rust value the port deliberately does not carry is a reasonable thing to do. The problem is only that "1018 unit tests pass" mixes them with tests that exercise the port. A reader who wants to know how much of the port is covered cannot get it from that number.

## What is good, and worth not losing

Three things in this code are better than the surrounding process suggests, and they should be defended in review rather than rediscovered.

The type discipline is genuinely strict. Across every `src/` and `test/` tree there is not one `any`, not one `as any`, not one `@ts-ignore`, and not one `eslint-disable`. The only five `@ts-expect-error` comments are in `transaction/test/fixed-bytes.test.ts`, where they are the assertion: they prove the branded fixed-length byte types actually reject a wrong width at compile time.

No source file swallows an error. Every `catch` in `sdk-libs/ts/*/src` either rethrows, wraps into the package's error type, or is a deliberate predicate. `wallet/src/sync.ts:124` and `:134` return `false` for a payload that does not decode, which is the `.ok()` idiom the Rust reads with, and `wallet/src/sync.ts:54` rethrows anything that is not the one RPC-unsupported code it handles.

Where a guard could have been copied wrongly, it was checked. `wallet/src/private-transaction.ts:58` compares every field that feeds the commitment before signing, which is field-for-field what `validate_unsigned_inputs` (`sdk-libs/wallet/src/actions/transaction.rs:889`) compares. The zone-authority guards in `transaction/src/instructions/builders.ts:510-520` match `sdk-libs/transaction/src/instructions/zone_authority.rs:57-73` exactly, including the absence of the over-strict withdrawal check that an earlier pass had added and a later one removed.

## Verification

Run in this worktree after the three commits, with `node_modules/.vite` cleared first:

| Command | Result |
| --- | --- |
| `npm run test:unit` | 77 files passed, 1 skipped; 1143 tests passed, 1 skipped |
| `npm run typecheck` | clean |
| `npm run lint` | clean |
| `npm run lint:packages` | clean, after another worker's in-tree fix; see [F6](#f6) |

The unit count rises from 1018 to 1143 because of the two new parity suites; none of the increase comes from relaxing an assertion.

## Commits

| Commit | Kind | Files |
| --- | --- | --- |
| `f0332e8b` | Refactor, no behaviour change | `client/src/prover/merge.ts` |
| `a8285d49` | Fix, with pinning tests | `client/src/internal.ts`, `keypair/src/bytes.ts`, and their two new vector suites |
| `9bea051d` | Test strengthening | `transaction/test/vectors/program-libs-event.test.ts` |
