# tee-policy

Builds, signs and verifies the signed TEE prover policy (`prover/tee/WIRE_CONTRACT.md`,
signed policy), and keeps it in force. Every check is `spr-prover-tee`'s own verifier
against the release keys the Rust client pins in
`sdk-libs/client/src/prover/tee/signers.json`, so it accepts exactly what clients accept.

```sh
cargo run -p spr-tee-policy --bin tee-policy -- build  devnet.json --manifest <release manifest>
cargo run -p spr-tee-policy --bin tee-policy -- sign   devnet.json --key alias/zolana-tee-policy-signer-1
cargo run -p spr-tee-policy --bin tee-policy -- verify devnet.json --previous <the part it replaces>
cargo run -p spr-tee-policy --bin tee-policy -- verify-served https://d3gbdb0egjwcw9.cloudfront.net/tee-policy/devnet.json
```

`build` approves the generations the zolana-infra release manifest serves, names the
network's freshness key (`alias/zolana-tee-policy-freshness-<network>` unless
`--freshness-key` names others) and lasts at most 90 days. `sign` asks KMS for one
signature and attaches it once it verifies; nothing here holds a private key. Keys
default to eu-north-1.

`tee-policy-freshness` is the Lambda (image `zolana-tee-policy-freshness`, built by
`publish-image`) that zolana-infra runs daily per network. Each run reads
`tee-policy-release/<network>.json`, signs a freshness part with the network's KMS key,
checks the whole file with `SignedPolicyFile::verify`, and writes
`tee-policy/<network>.json` only over the object it read, never with an older release
than the one served.
