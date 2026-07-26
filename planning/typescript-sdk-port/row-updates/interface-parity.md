# Interface parity: I01-I37

Branch `port/interface-a`, forked from `ts-sdk-port` at `c585faaf`. Scope is the
36 adverse rows `I01`-`I37` (`I16` is the one non-adverse row and was covered
incidentally).

**Result: 33 of 36 rows now hold evidence-backed parity, 1 divergence is
recorded and pinned, and 3 rows close only partially with the residue named
below.** No file under `sdk-libs/ts/interface/src/**` was changed. The port
already matched current Rust everywhere I tested except the single divergence in
section 3; every row that was open was open for lack of evidence, not for lack
of correctness.

## 1. What the evidence is

Reading two files and finding them similar is what produced the 31 false
verdicts, so I built a generator instead.

`xtask/src/bin/ts-interface-oracle.rs` links against the real `zolana-interface`
crate and prints, as JSON, what current Rust actually does: every constant and
tag, all 29 error codes and messages, the supported shape list in order,
`ciphertext_hash` / `pk_field` / `pack33` outputs across chunk boundaries, every
PDA and bump, the `bytemuck` byte image of each state account, `wincode` bytes
for each instruction-data type, the full `Instruction` (program id, data,
account metas with flags) for every builder, `external_data_hash` for transact
and merge, the accept/reject verdict of each Rust decoder on hand-built
non-canonical inputs, and the `pub use` list scraped from each Rust `mod.rs`.

Its output is committed at `sdk-libs/ts/interface/test/rust-oracle.json`
(1756 lines) and consumed by
`sdk-libs/ts/interface/test/vectors/rust-oracle.test.ts` (41 tests). Every row
below cites the test that backs it. Regenerate with:

```bash
cargo run -p xtask --bin ts-interface-oracle > sdk-libs/ts/interface/test/rust-oracle.json
```

Two guards make the oracle hard to satisfy dishonestly:

- The generator **panics** if a Rust builder re-export has no instruction vector
  in the oracle, so a new Rust builder breaks generation rather than passing
  silently. (It caught one gap while I wrote it: `UpdateProtocolConfig`.)
- The re-export ledgers assert set equality between the scraped Rust `pub use`
  names and an explicit Rust-name -> TypeScript-name mapping, so adding or
  removing a Rust export fails the TypeScript suite.

`u64` fields cross the JSON boundary as strings and are parsed back to `BigInt`;
emitting them as JSON numbers silently rounded `u64::MAX` to `2^64` and produced
a passing-looking mismatch.

## 2. Misrouted rows

Repointed as instructed. All four named `interface/src/index.ts` or
`interface/src/internal.ts`, neither of which holds the behaviour. `internal.ts`
is base58, sha256, validators, and a Writer/Reader pair.

| Row | Rust | Recorded TypeScript | Correct TypeScript |
| --- | --- | --- | --- |
| I02 | `shape.rs` | `interface/src/internal.ts` | `interface/src/shape.ts` |
| I03 | `merge_utils.rs` | `interface/src/internal.ts` | `interface/src/merge-utils.ts` |
| I30 | `state/discriminator.rs` | `interface/src/internal.ts` | `interface/src/state.ts` (`StateDiscriminator`) |
| I34 | `state/tree.rs` | `interface/src/index.ts` | `interface/src/state.ts` (`STATE_HEIGHT:10`, `TREE_ACCOUNT_SIZE:15`, `STATE_ROOT_OFFSET:16`) |

I34's counterpart is `state.ts`, not the package root: `index.ts` only
re-exports those constants. Reviewing it at the root would have checked that a
name is exported rather than that its value matches Rust; the oracle checks the
value.

## 3. The one divergence

**TypeScript refuses a merge payload that the Rust decoder reads.**

Input that exposes it: a `MergeTransactIxData` (or `MergeZoneIxData`) whose
`encrypted_utxo` first byte is not `MERGE_ENCRYPTED_UTXO_TYPE_PREFIX` (`2`,
`OutputDataEncoding::VerifiablyEncrypted`). The exact bytes are in the oracle as
`decodeAcceptance.mergeNonCanonicalPrefixBytes` and
`decodeAcceptance.mergeZoneNonCanonicalPrefixBytes`.

- Rust `MergeTransactIxData::deserialize` and `MergeZoneIxData::deserialize`
  **accept** those bytes (`mergeAcceptsNonCanonicalPrefix: true`,
  `mergeZoneAcceptsNonCanonicalPrefix: true`). The prefix is not part of the
  wire format; the shielded-pool program rejects the payload later with
  `InvalidMergeOutputScheme` (7014).
- `mergeTransactInstructionDataCodec.decode` and
  `mergeZoneInstructionDataCodec.decode` **throw** `INTERFACE_CODEC` at decode
  time.

This is the "TypeScript tightens a check" pattern the brief warns about, and
rows I08, I20, and I21 were previously flipped from `DIVERGENT` to `PARITY`
27 minutes apart with no fix commit between them, which is consistent with
someone closing it by tightening rather than by testing.

I did not change either side. I pinned the asymmetry in a test that fails if
Rust starts rejecting these bytes **or** if TypeScript starts accepting them
(`decoder acceptance > pins the merge encrypted-UTXO prefix asymmetry against
Rust`), with a comment stating it is a recorded divergence and not a target.

Practical impact is confined to reading, not writing: no valid transaction is
lost, because a payload with a non-canonical prefix is rejected by the program
on either path. What a TypeScript client cannot do is decode and inspect such an
instruction, for example while indexing or debugging a failed transaction. Both
behaviours are defensible; the choice belongs to the protocol owner, not to this
port.

## 4. Rows closed with evidence

All test names below are in
`sdk-libs/ts/interface/test/vectors/rust-oracle.test.ts`.

| Rows | Backed by |
| --- | --- |
| I01 | `errors > matches every Rust error code and message`, plus a set-equality test that the package exports no code Rust does not define and omits none it does. 29 codes, names, and messages. |
| I02 | `shape > matches the Rust supported-shape list in order` and `selects the first shape that covers the request`. Order matters and is asserted, not just membership. |
| I03 | `merge utils > matches Rust ciphertext_hash across chunk boundaries`, `matches Rust pk_field, owner_pk_field, and pack33`, and two rejection tests pinning the chunk counts and compressed prefixes Rust rejects. |
| I04 | `pda > derives every canonical address and bump Rust derives`, across all canonical routes with the Rust bump. |
| I05, I06, I12 | `instruction data codecs > round-trips the payload Rust builders emit for every remaining data type`. Decodes Rust's own bytes through `batchUpdateNullifierTreeDataCodec`, `createTreeDataCodec`, `addressTreeParamsCodec`, and the three zone-config codecs, then re-encodes to the same bytes. |
| I08, I09 | Exact `wincode` bytes for merge and merge-zone, plus the divergence in section 3. Byte-level parity holds; only decoder strictness differs. |
| I10, I22 | `builders > matches protocol-config creation, every update variant, and pause-tree`. All seven variants, their indices, and the incoming-authority co-signature on `protocolAuthority` alone. |
| I11 | `external data hash > matches the Rust transact external_data_hash`, `matches the Rust all-defaults hash`, and `distinguishes empty output data from absent output data, as Rust does`. The empty-versus-absent case is the one that silently produces a wrong hash. |
| I13, I28, I29, I36 | `re-export ledgers` (four tests). Set equality against the scraped Rust `pub use` lists for `instruction_data/mod.rs`, `builders/mod.rs`, `instruction/mod.rs`, and `state/mod.rs`. |
| I14, I15, I16, I17, I18 | `builders > matches create-asset-counter, create-spl-interface, and create-ATA`, `matches create-tree with default and custom nullifier parameters`, `matches batch-update-nullifier-tree`. Exact data bytes and account metas with signer/writable flags. |
| I20, I21 | `builders > matches merge transact and merge zone on both routes`. |
| I23 | `builders > matches transact with no withdrawal and both settlement rails`, including the SPL rail with and without an explicit CPI authority. |
| I24, I25, I27 | `builders > matches zone transact and zone-authority transact on both routes` and `matches zone-config creation and both updates`. |
| I30, I31, I32, I33, I34, I35 | `state > matches Rust discriminators, sizes, and tree parameters`, `matches the canonical Rust nullifier tree parameters`, and `decodes and re-encodes the exact bytes Rust writes for each account`, which round-trips the `bytemuck` image of every state account. |

Two rejection findings are also pinned where Rust and TypeScript agree, so
future work cannot loosen them unnoticed: trailing bytes after a deposit
payload, a non-canonical bool inside a merge payload, and a protocol-config
account with the wrong discriminator or a short buffer are refused by both
(`decoder acceptance > rejects exactly what the Rust decoders reject`).

One deliberate leniency is also pinned: `state > accepts the nonzero flag bytes
Rust decodes as true`. Rust reads any nonzero byte as `true`, so TypeScript must
not demand exactly `1`. Tightening that would be the same mistake as section 3.

## 5. Rows that close only partially

### I07, I19, I26 (deposit and zone-deposit data and builders)

These were `BLOCKED` on the `docs/spec.md` deposit conflict. The checklist
records both halves as settled (`b97b2a88` amended the spec, `1ff51a4c` and
`114a5140` applied the discovery-tag ruling) and waiting on wallet fixture
regeneration.

**That pending work cannot affect this package.** The interface treats the
discovery tag as an opaque 32-byte field on both sides:
`DepositIxData::view_tag: [u8; 32]` and `ZoneDepositIxData::view_tag: [u8; 32]`
in Rust; `writer.bytes(value.viewTag, 32, "viewTag")` in
`codecs/index.ts:82,130`. Neither side derives, validates, or interprets it.
Which value the wallet writes there is a `sdk-libs/wallet` question.

So the layout, codec, and builder parity is closed with evidence: exact
`wincode` bytes for both deposit forms (`encodes deposit data to the exact Rust
wincode bytes`, `encodes zone-deposit data to the exact Rust wincode bytes`) and
exact builder output for the SOL and SPL rails on both the outer and CPI routes
(`matches SOL and SPL deposits`, `matches SOL and SPL zone deposits on the outer
and CPI routes`). What I did **not** verify, because it is outside this package,
is that the wallet's regenerated fixtures write the ruled-on tag value. I count
these three as partial rather than closed for that reason alone.

### I37 (package root)

The root's children are now all evidenced, and root constants and the export
surface are checked (`constants and tags`, and the ledger tests). The residue is
the one the row itself names: the legacy frozen-revision fixture gate still
fails with `baseline fixture sources differ from revision 43fde8e4`. That is
package bookkeeping owned by the fixture-gate worker, it is not scoped to
interface behaviour, and I left it alone rather than re-freezing a baseline that
is not mine.

## 6. Verification

Run in this tree, all green:

| Command | Result |
| --- | --- |
| `npm run build` | pass |
| `npm run typecheck` | pass |
| `npm run test:unit` | 831 passed, 1 skipped |
| `npm run test:vectors` | pass, including the 41 new oracle tests |
| `npm run test:cross` | pass (rebuilt first) |
| `npm run test:exports` | pass |
| `cargo test -p zolana-interface` | 27 + 1 passed, 0 failed |
| `npx eslint` / `prettier` on the new test | clean |

## 7. Merge notes for the coordinator

The branch is purely additive against `c585faaf`; no existing line is modified,
so it should merge without conflict:

```
 Cargo.lock                                          |    3 +
 sdk-libs/ts/interface/test/rust-oracle.json         | 1756 +
 sdk-libs/ts/interface/test/vectors/rust-oracle.test.ts | 1072 +
 xtask/Cargo.toml                                    |    1 +
 xtask/src/bin/ts-interface-oracle.rs                | 1235 +
```

Two files fall outside the requested `sdk-libs/ts/interface/**` scope: the new
`xtask` oracle binary and the one-line `bytemuck` dependency it needs. Producing
Rust ground truth requires linking against the Rust crate, and there is no
`sdk-libs/interface` crate in this tree to host it. Both changes are additive
and no other code path imports them; the committed JSON means the TypeScript
suite runs without cargo.
