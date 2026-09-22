# Program IDLs

Codama IDLs for the shielded-pool and user-registry programs in this source revision.

| File                | Program                                       | Instructions |
| ------------------- | --------------------------------------------- | ------------ |
| `shieldedPool.json` | `sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6` | 22           |
| `userRegistry.json` | `regyS5rkAcw2YzDJCmTwCTHs2s246FXxbmuRZ42u2PD` | 3            |

The schemas describe instruction tags, arguments, fixed account roles, program errors,
and supported account data. The pool IDL includes all four self-CPI event bodies,
protocol/ring configuration, and SPL asset registry/counter accounts. Full tree
internals and nullifier-PDA account decoding are outside this initial scope.
Variable account groups and conditional accounts are documented in the instructions.
Output payloads remain bytes; these IDLs do not interpret transfers or encrypted values.

## Generate and validate

From the repository root, with Node 24 and the workspace Rust toolchain:

```sh
npm ci
cargo run -p zolana-idl-fixtures --locked -- --write
npm run generate:idl --workspace @heliuslabs/zolana
cargo test -p zolana-idl-fixtures --locked
npm run check --workspace @heliuslabs/zolana
```

The generator maintains explicit Codama layouts for the custom wincode and Borsh
encodings; it does not derive every field from Rust automatically. Changes require
reviewing the schema and regenerating independent Rust byte fixtures. Tests decode
those fixtures using the generated IDLs and check expected fields, exact byte
consumption, all instruction tags, event kinds, and supported account layouts.

`manifest.json` records the fixture source commit, source-file hashes, and each IDL's
SHA-256 over `JSON.stringify(JSON.parse(contents))`. It is source provenance, not a
verified deployment record. CI checks deterministic generation and Rust fixture drift.

The SDK package includes the files under `@heliuslabs/zolana/idl/*`:

```ts
import poolIdl from "@heliuslabs/zolana/idl/shieldedPool.json" with { type: "json" };
import registryIdl from "@heliuslabs/zolana/idl/userRegistry.json" with { type: "json" };
```

## Publication

These files have not been uploaded on chain. Before publication, match the intended
cluster's deployed executable to this source revision and verify its metadata authority.
Publish each matching IDL under its program's canonical `idl` seed through the
[Program Metadata Program](https://github.com/solana-program/program-metadata),
then fetch it back and compare it with the release file. Publication requires separate
approval. Do not use these layouts for older deployments with different tags or bytes.

Explorer discovery and Codama support must be confirmed with each explorer. An IDL
can expose named instructions and fields; it does not create a custom transfer summary.
Decoding an event does not authenticate it: the `emitEvent` instruction itself performs
no validation.
