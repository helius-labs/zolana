# Program IDLs

Codama IDLs for the shielded-pool and user-registry programs in this source revision.

| File                | Program                                       | Instructions |
| ------------------- | --------------------------------------------- | ------------ |
| `shieldedPool.json` | `ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW` | 24           |
| `userRegistry.json` | `regy3WAeRXMYuMYxr5iK3Bf9Arr3PcxGxyzAddbiqDQ` | 3            |

The schemas describe instruction tags, arguments, fixed account roles, program errors,
and supported account data. The pool IDL includes all four self-CPI event bodies,
protocol/ring configuration, SPL asset registry/counter accounts, and the fixed cache
account. Full tree internals and nullifier-PDA account decoding are outside this initial scope.
Variable account groups and conditional accounts are documented in the instructions.
The circuit selector describes all nine current variants, including fixed cache read/write
selections and the anonymous/confidential Ed25519 proof payloads. Merge instructions
carry Poseidon-CTR ciphertext and an optional cache slot. The registry describes the
100-byte record and separate registration payer; key updates carry only the viewing key.
Output payloads remain bytes; these IDLs do not interpret transfers or decrypt values.

## Generate and validate

From the repository root, with Node 22.12 or newer and the workspace Rust toolchain:

```sh
npm ci
cargo run -p spr-idl-fixtures --locked -- --write
npm run generate:idl --workspace @heliuslabs/spr
cargo test -p spr-idl-fixtures --locked
npm run check --workspace @heliuslabs/spr
```

The generator maintains explicit Codama layouts for the custom wincode and Borsh
encodings; it does not derive every field from Rust automatically. Changes require
reviewing the schema and regenerating independent Rust byte fixtures. Tests decode
those fixtures using the generated IDLs and check expected fields, exact byte
consumption, all instruction tags, event kinds, signed cache expiry boundaries, registry
account roles, and supported account layouts.

`manifest.json` records the fixture source commit, source-file hashes, and each IDL's
SHA-256 over `JSON.stringify(JSON.parse(contents))`. It is source provenance, not a
verified deployment record. CI checks deterministic generation and Rust fixture drift.

The SDK package includes the files under `@heliuslabs/spr/idl/*`:

```ts
import poolIdl from "@heliuslabs/spr/idl/shieldedPool.json" with { type: "json" };
import registryIdl from "@heliuslabs/spr/idl/userRegistry.json" with { type: "json" };
```

## Publication

These files have not been uploaded on chain. Before publication, match the intended
cluster's deployed executable to this source revision and verify its metadata authority.
Publish each matching IDL under its program's canonical `idl` seed through the
[Program Metadata Program](https://github.com/solana-program/program-metadata),
then fetch it back and compare it with the release file. Publication is a separate
on-chain operation signed by the appropriate authority. Do not use these layouts for
older deployments with different tags or bytes.

Solana Explorer resolves canonical PMP IDLs and decodes Codama instructions; Solscan
also documents PMP publication and Codama account decoding. Verify discovery and
representative transactions on the intended cluster after publishing. For devnet:

```sh
npx @solana-program/program-metadata@latest write idl <program-id> ./idl.json --keypair <upgrade-authority-keypair> --rpc https://api.devnet.solana.com
npx @solana-program/program-metadata@latest fetch idl <program-id> --output ./published-idl.json --rpc https://api.devnet.solana.com
```

See the [Explorer resolver](https://github.com/solana-foundation/explorer/blob/master/app/entities/idl/api/resolve-program-idls.ts)
and [Solscan publication guide](https://info.solscan.io/solana-program-idl-on-solscan/). An IDL
can expose named instructions and fields; it does not create a custom transfer summary.
Decoding an event does not authenticate it: the `emitEvent` instruction itself performs
no validation.
