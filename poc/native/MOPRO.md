# Native proving on iOS/Android with mopro

This is the one place mopro genuinely fits, and the one place it is genuinely
needed. It is not usable for the web PoC — see the "Why not on web" note at the
bottom.

## What the module has to provide

Two things, not one:

1. **Poseidon.** Hermes has no WebAssembly, and the SDK's hasher
   (`@lightprotocol/hasher.rs`) is a wasm module. Without a native Poseidon the
   SDK cannot compute a UTXO commitment, a nullifier, or a view tag, so nothing
   works on device — not just proving. Reuse `program-libs/hasher`
   (`zolana_hasher`), which is already a Rust crate.
2. **gnark Groth16 proving**, over Zolana's own key and witness formats.

## The gap in mopro's stock gnark adapter

`mopro init --adapter gnark` wires `rust-gnark = "0.0.2"` and generates:

```rust
generate_gnark_proof(r1cs_path: String, pk_path: String, witness_json: String)
verify_gnark_proof(r1cs_path: String, vk_path: String, proof: GnarkProofResult)
```

That signature does not fit Zolana:

- A Zolana `.key` file is **one** `TransferProofSystem` blob — a
  `nInputs`/`nOutputs`/`requiresP256` header followed by the proving key,
  verifying key, and constraint system (see
  `prover/server/prover/common/marshal.go`, `UnsafeReadFrom`). There is no
  separate `.r1cs`/`.pk`/`.vk` triple to hand over.
- The witness is built by `TransferParameters.CreateWitness()` from typed proof
  inputs, not from a flat JSON map of variable names.
- The confidential rail's circuit is selected per shape and variant
  (`newVariantCircuit`), so the prover must know which of the ten shapes it is
  proving.

So the native module needs a **Zolana-specific entry point** that reuses
`prover/prover/transfer_eddsa_only`, exposed through mopro's UniFFI bindings —
not the stock adapter's generic file-path API. Keep the JSON contract identical
to `POST /prove`, exactly as `prover/server/cmd/prover-wasm` does for the
browser, so the TypeScript side stays transport-agnostic.

## Suggested shape

```
mopro init --adapter gnark --project-name zolana-mobile-prover
```

Then in the generated crate expose, over UniFFI:

```rust
fn poseidon(inputs: Vec<Vec<u8>>) -> Result<Vec<u8>, ProverError>;
fn load_key(file_name: String, key: Vec<u8>) -> Result<String, ProverError>;
fn prove(request_json: String) -> Result<String, ProverError>;
```

`load_key`/`prove` mirror `cmd/prover-wasm/main.go` one-for-one, so the in-memory
key registry, the filename-derived circuit type, and the error-instead-of-panic
behaviour can be ported directly rather than redesigned.

Build and link:

```sh
mopro build --platforms ios android --mode release
mopro create --framework react-native
```

Then install the generated module in this app and register it as
`globalThis.__zolanaNativeProver`, which is what `src/native-prover.ts` looks
for.

## Proving-key delivery on device

Transfer keys are 7.6–37.3 MB each and 10 shapes total ~223 MB, so they must not
all be bundled. Fetch on demand from the same version-hashed CloudFront prefix
the server uses (`prover/server/prover/provingkeys/proving-keys.lock` pins the
prefix and every `sha256`), verify the hash, and cache to the app's document
directory. `EnsureProvingKey` in `key_downloader.go` is the reference behaviour.

## Why not on web

mopro's gnark adapter is declared
`#[cfg(not(target_arch = "wasm32"))]` (`cli/src/template/gnark/lib.rs:1`) because
`rust-gnark` binds Go gnark through cgo, which cannot target
`wasm32-unknown-unknown`. mopro's web build runs `wasm-pack --features wasm`,
which enables only its circom, halo2, and noir adapters. Its own web setup doc
is Halo2-specific.

The browser PoC therefore uses gnark's **own** `GOOS=js GOARCH=wasm` target
(`prover/server/cmd/prover-wasm`), which was verified to compile, prove, and
verify. mopro is not on that path and cannot be without porting the circuits to
noir/halo2/circom — which would produce proofs the deployed on-chain Groth16
verifier would not accept.
