# Final core ceremony keys

This rotation installs the finalized November 2, 2026 ceremony keys for 38
`transfer_confidential` circuits and three `merge` circuits. Each contains 15
accepted contributions. Custom rings, in-circuit confidential EdDSA, batch 10,
batch 4999 and all other keys retain their existing hashes.

[Final export and verification evidence](https://github.com/helius-labs/spr-ceremony/releases/tag/core-keys-2026-11-02)
contains the frozen manifest, checkpoint and signed quicknet round. The
[local provenance record](core-ceremony.json) identifies the source revisions,
compiled R1CS hashes, final export and packaged-key hashes.

The 41 current-main circuit compilations reproduce the ceremony's R1CS bytes.
All packaged keys load through the real Go prover. Real fixture proofs pass
both gnark and the application Rust verifier; changed public inputs fail.
`program-libs/interface/tests/core_ceremony.rs` retains those public proof vectors.
These are host checks; they do not claim a deployed-program transaction test.

## Distribution

The new gnark key set is `proving-keys/78751f5d1c591777` on the existing public
CDN, `https://d3gbdb0egjwcw9.cloudfront.net`. It contains 41 replacement keys
and 95 unchanged objects copied from the previous set. The separate zopro
manifest pins converted core keys to the same gnark hashes. All 41 converted keys also
generate and verify proofs with the mobile prover engine. All 136 gnark and
41 zopro objects passed full-byte CDN size and SHA-256 verification; the
[publication record](core-ceremony-publication.json) lists the checked objects.

The unchanged 73.9 GB batch-4999 file requires ranged CDN downloads; this
rotation does not regenerate it or add it to the core ceremony.

## Rollout

1. Verify the publication report and CI, then merge the coordinated prover,
   verifier, TypeScript and mobile catalog changes.
2. Build the prover and on-chain program from the same reviewed source. Run
   the normal program integration and deployment checks for the target cluster.
3. Pause proof-producing clients while switching the verifier and prover;
   proofs generated with the previous keys cannot verify against the new keys.
4. Release the matching SDKs, resume clients, and exercise transfer and merge
   transactions against the deployed program.

Keep the old key set and program/prover artifacts for a coordinated rollback.
Do not run the all-key rotation scripts: those generate unrelated local setups.
No running program, prover service or mobile release is changed by this draft.

## Local checks

```sh
cargo test --locked -p spr-interface --test core_ceremony --test vk_proving_key_lock
(cd prover/server && go test ./prover/provingkeys ./prover/common ./prover/fingerprint)
npm run check --workspace @heliuslabs/spr
```
