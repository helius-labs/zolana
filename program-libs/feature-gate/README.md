# feature-gate

Compile-time circuit gates and indexable metadata for Solana program binaries.
Cargo features and their enabled-state checks live in `src/features.rs`.
`confidential-eddsa` is off by default. Programs forward their own Cargo
features to this crate explicitly.

The program uses a `CircuitFeature` descriptor to check proving-key hashes and
exports its encoded bytes as a public static with a unique `export_name`.
Do not add `#[used]`: it sets GNU-retain ELF flags rejected by the SBF loader.
An indexer finds records between the versioned `BEGIN` and `END` delimiters.
The record contains NUL-terminated `name`, `enabled` and repeated
`proving_key_sha256` fields. Hashes are 64 hexadecimal digits. Disabled gates
retain their associated hashes and record `enabled=false`; linked VK metadata
alone does not mean a circuit is enabled. Missing feature metadata means unknown.

The default build is `no_std` with no dependencies. The `std` feature enables
binary parsing and rejects malformed or duplicate feature records. Read the
descriptor from the inspected binary, not the inspection tool's Cargo features.

For shielded-pool builds:

```sh
just build-programs       # confidential-eddsa off
just build-test-programs  # explicitly enables confidential-eddsa
just test-feature-gate    # checks off and on independently
cargo run -p spr-protocol-cli -- circuit-features --so target/deploy/shielded_pool_program.so
cargo run -p spr-protocol-cli -- circuit-features --program-id <id> --rpc-url <url>
```
