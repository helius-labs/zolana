Ordinary payments prove auditor disclosure against the committed outputs. Recipient encryption remains wallet-side.

## Full-policy 2-input, 3-output probe

A fixed 2×3 policy circuit preserves the current policy and audit statements. It pins the input count, output count and ring mode in the verifying key. The existing general circuits and keys remain available. This probe is not wired into production key selection because it misses the 100k custom-proof target.

| Policy and audit proof | General key | Fixed 2×3 probe |
|---|---:|---:|
| Ordinary | 326,293 | 235,600 |
| Anonymous | 326,293 | 245,661 |
| Delegate | 324,033 | 233,421 |

For the ordinary probe, cumulative compile differences attribute about 123,448 constraints to registry openings and 54,191 to audit. Policy table checks add 22,451, transaction checks add 11,153 and rule and limit checks add 17,291. The attribution test omits part of the final statement hash, so its component sum is not the exact production count. All three full counts above are exact compiled R1CS sizes.

The existing 20-level member registry authenticates each owner or asset against the ring registry and, when configured, a curator registry. The 2×3 circuit still supports eight subject slots and up to sixteen authenticated openings. Even deleting registry verification entirely from the attribution circuit leaves over 100k constraints after the audit and other policy checks. A batch Merkle proof alone cannot meet the target. A safe sub-100k design needs measured savings in audit, policy evaluation and registry authentication together. Until one passes the full gate, the current proving path stays in service.

| Circuit | Before optimization | Now |
|---|---:|---:|
| Ordinary auditor disclosure, two outputs | 95,610 | 58,645 |
| Anonymous-capable auditor disclosure | 95,610 | 79,021 |
| Policy and audit | 339,469 | 326,293 |
| Delegate policy and audit | 337,209 | 324,033 |

A one-input, two-output payment adds 30,987 settlement constraints. The ordinary custom-ring total is **89,632**, down from 126,597. Other output counts use the general audit circuit. Policy and anonymous payments have larger totals.

The remaining two-output audit cost breaks down as follows. These are cumulative compile differences, including deferred lookup arguments. The order matters because the curve operations share range tables.

| Work | Added constraints |
|---|---:|
| Transaction viewing public key | 5,916 |
| Auditor X25519 key agreement | 25,424 |
| Envelope transcript, KDF and AES | 9,373 |
| Disclosure stream, ciphertext hashing and framing | 12,699 |
| Two note commitments and output hash | 2,595 |
| Public statement hash | 2,638 |
| Total | **58,645** |

The default ring already compiles for the transaction's output count. The ordinary audit circuit now pins two outputs at compile time and hashes only those two note openings. The program chooses this key only for a two-output, nonanonymous transfer without policy. It chooses the general key for one, three or four outputs. The circuit independently checks its count is two. The Rust and TypeScript clients make the same selection.

The auditor envelope now uses the two-hash stream KDF from `../zk-experiments/gnark-gadgets/encryption/kdf.go`. The first Poseidon output supplies 31 key bytes. The second supplies the last key byte and 12 nonce bytes. Exact canonical encoding admits every native field value, including `q - 1`. The older four-hash schedule remains in other encryption paths. A standalone compilation measures 824 constraints for the two-hash schedule against 2,490 for the older schedule. In the complete audit circuit, shared lookup costs make the saving about 1,812. The new ciphertext is pinned by the rotated proof keys and a common Go, Rust and TypeScript vector.

The spread-lane AES implementation already has shared tables, reused key expansion, cached first-round columns and fused final XOR. Those savings are already in the totals above.

A two-output audit still encrypts four output slots because the published disclosure has a fixed 36-field layout. Shortening that layout needs coordinated circuit, program, Rust and TypeScript changes, plus a message version for auditor recovery. An inactive witness flag alone does not reduce circuit constraints.

The auditor still recovers the transaction viewing key. It opens both the checked note disclosure and the transaction's output data. Encrypting the disclosure directly from auditor ECDH would remove the envelope, but would remove that output-data recovery path. It is a different audit guarantee and is not counted as an optimization here.

Reproduce the measured circuit breakdown from `prover/server`:

```sh
go test ./custom_rings/circuits/base -run '^TestAudit(CostBreakdown|KDFStructuralCost)$' -v
```

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

`just check-custom-ring-keys` re-exports every ring verifying key from its pinned local proving key and compares the committed constants. It passed for the rotated audit, policy and delegate keys and the unchanged ring keys.

Security review: the program selects the verifying key from the stored ring mode and settled output count. The proof binds the configured auditor key, encrypted viewing key, disclosure, output commitments and SPP transaction hash in one public statement. The two-output circuit independently fixes its mode and count. The auditor can decrypt the committed note fields. Recipient ciphertexts still have no delivery proof. Reusing an ephemeral key with the same auditor key reuses the AES-CTR stream. Reusing a viewing key with the same salt reuses the disclosure stream. The Rust and TypeScript constructors generate fresh ephemeral keys. Proving keys and verifying keys must be deployed as one matching set.

Run the payment benchmark from `prover/server`:

```sh
go test ./circuits/spp_transaction/shared -run '^$' -bench '^BenchmarkPaymentProofs$' -benchtime=5x -count=3
```

On an Apple M5 Pro, the median batch times were 70.0 ms for the default ring, 76.1 ms for custom settlement and 161.7 ms for ordinary audit. Three batches of five proofs give a combined 237.8 ms for the custom transfer.

The benchmark measures CPU proving wall time on one input and two outputs. It excludes compilation, setup, witness encoding and verification. Every timed proof is verified outside the timer. Adding the settlement and audit times gives sequential proving time, not transaction latency. The SDK may request the proofs concurrently.

The base, policy and delegate keys were rotated locally. A new `custom_ring_base_confidential.key` was added. Verifying keys, fingerprints and Rust and TypeScript key pins must ship together. The historical release manifest remains unchanged because these artifacts have not been published.
