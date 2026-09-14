# Zolana mobile SDK and Flutter demo

This directory contains a narrow mobile SDK rather than bindings for every Rust
type. Its API keeps ownership, encryption, transaction layout, hashing, and
proving inside Rust and exposes Flutter-friendly records:

- `prepareTransfer` builds a compact private SOL transfer with
  `zolana-keypair` and `zolana-transaction`.
- `poseidonHash` uses the protocol's native `zolana-hasher` implementation.
- `inspectProvingKey` reads a combined Zolana gnark key.
- `proveAssignment` generates and verifies a Groth16 proof locally with
  Arkworks and returns the existing `POST /prove` JSON encoding.

The generated Flutter package and example app live under
`zolana-mobile/mopro_flutter_bindings`. Mopro uses Flutter Rust Bridge to build
the Rust static library for iOS and shared library for Android.

## Prerequisites

- Rust targets: `aarch64-apple-ios`, `aarch64-apple-ios-sim`,
  `x86_64-apple-ios`, `armv7-linux-androideabi`, `aarch64-linux-android`, and
  `x86_64-linux-android`
- Flutter, Go, Python 3, and the platform toolchain you want to run
- Mopro CLI 0.3.7: `cargo install mopro-cli --version 0.3.7`

## Generate bindings

Run this whenever the public API in `zolana-mobile/src/lib.rs` changes:

```sh
cd mobile/zolana-mobile
mopro build --platforms flutter --mode release
```

The generated output is checked in. When regenerating, retain these compatibility
changes:

- Keep the `zolana-mobile` dependency path relative and preserve its exact
  Solana wire crate versions. A newer `solana-address` pulls `wincode` 0.6 while
  this workspace uses 0.5.
- Keep `cc` 1.2.16 in the bridge crate. The older lockfile version emits
  host-architecture C helpers when compiling an Intel iOS simulator slice.
- Keep the Cargokit Gradle 9 `ExecOperations` calls and accept either
  `source.properties` or `package.xml` when detecting an installed Android NDK.
- Keep the Android plugin on compile SDK 36.

## Run the demo

The proof button uses a committed 2→3 request. The staging script downloads and
checks its proving key, solves the request with Go/gnark, and copies both large
ignored artifacts into the Flutter asset directory:

```sh
mobile/stage-demo-assets.sh
cd mobile/zolana-mobile/mopro_flutter_bindings/example
flutter pub get
flutter run
```

The proof button does not need a prover server; key parsing, Groth16 proving,
and verification all run in the app process. Transfer preparation remains
available through the SDK API but is not shown in this minimal demo.

## Current boundary

The Arkworks prover consumes a solved gnark assignment. Zolana's circuit solver
is still Go/gnark, so `proveAssignment` accepts an assignment file rather than a
raw `POST /prove` request. The next step for production transfers is to package
the solver plan in the mobile library, then connect the resulting proof to
`zolana-wallet` RPC/indexer synchronization and submission.
