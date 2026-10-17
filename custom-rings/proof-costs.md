Ordinary payments still prove auditor disclosure against the committed outputs. Recipient encryption remains wallet-side.

| Circuit | Before | After |
|---|---:|---:|
| Ordinary auditor disclosure | 95,610 | 62,345 |
| Anonymous-capable auditor disclosure | 95,610 | 80,833 |
| Policy and audit | 339,469 | 328,105 |
| Delegate policy and audit | 337,209 | 325,845 |

An ordinary one-input, two-output transfer adds 30,987 settlement constraints. Its total is **93,332**, down from 126,597. Policy and anonymous transfers have larger totals. These numbers do not claim a 100k bound for those paths.

The ordinary audit circuit fixes anonymous mode to zero at compilation. It proves the same public statement and emits the same auditor ciphertext and disclosure. It omits the hidden input and identity machinery that ordinary rings never use. The program chooses the key from its stored ring configuration. The request cannot choose a cheaper verification mode.

The general circuit selects the complete output opening before hashing it. The selected hash binds both disclosure and the anonymous transaction commitment. Previously it hashed both candidate openings before selecting. The anonymous mode still constrains the sender, spent notes and recipients.

Canonical field serialization now uses 32 bounded bytes and a bounded complement. Let `B = 2^128` and let `q` be the native field modulus. The circuit constrains both byte halves, both 128-bit complement limbs and one Boolean carry:

```text
x_low  + gap_low         = (q - 1)_low + carry × B
x_high + gap_high + carry = (q - 1)_high
x_high × B + x_low        = input   in the native field
```

Each of the first two equations is smaller than `2^129 + 1`, far below BN254's modulus. They therefore hold over the integers. Together they prove `x + gap = q - 1`. Since the gap is nonnegative, `x < q`. The final equality binds that unique encoding to the input. An encoding of `input + q` cannot pass. Hints supply candidates only. Constraints check their bytes, bounds, carry and equations.

The bounded-complement approach was informed by `../zk-experiments/gnark-gadgets/p256/emfield/canonical.go`. [zk.golf](https://zk.golf/llms.txt) and its [scalar multiplication work](https://zk.golf/api/agent/v1/submissions/42a0c2fb-2d99-4ea4-8441-9e484970954e) informed the approach of computing only consumed results while preserving every bound. This implementation has algebraic reasoning and adversarial tests. It does not claim a Lean proof.

Tests cover modulus aliases, byte and complement carries, invalid carry bits, incorrect disclosure fields, omitted outputs and mode substitution. Real Groth16 proofs verify under the regenerated keys. An ordinary proof fails under the anonymous-capable key. Existing cross-language disclosure vectors remain unchanged.

Run the payment benchmark from `prover/server`:

```sh
go test ./circuits/spp_transaction/shared -run '^$' -bench '^BenchmarkPaymentProofs$' -benchtime=5x -count=3
```

On an Apple M5 Pro, the median batch times were 61.4 ms for the default ring, 62.4 ms for custom settlement and 158.6 ms for ordinary audit. Three batches of five proofs give a combined 221.1 ms for the custom transfer.

The benchmark measures CPU proving wall time on one input and two outputs. It excludes compilation, setup, witness encoding and verification. Every timed proof is verified outside the timer. Adding the settlement and audit times gives sequential proving time, not transaction latency. The SDK may request the proofs concurrently.

The base, policy and delegate keys were rotated locally. A new `custom_ring_base_confidential.key` was added. Verifying keys, fingerprints and Rust and TypeScript key pins must ship together. The historical release manifest remains unchanged because these artifacts have not been published.
