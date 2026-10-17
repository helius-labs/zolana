The full 2-input, 3-output policy and auditor proof is below 100k constraints. No policy feature was removed. Ordinary recipient encryption stays wallet-side.

| Custom-ring proof | General key | New 2×3 key | Reduction |
|---|---:|---:|---:|
| Ordinary policy and audit | 326,293 | **95,943** | 70.6% |
| Anonymous policy and audit | 326,293 | **98,809** | 69.7% |
| Delegate policy and audit | 324,033 | **95,217** | 70.6% |

These are exact compiled R1CS counts. The new keys retain sixteen rules, eight list sources, eight per-mint amount thresholds, eight outflow rows, curator lists and key escrow. Each rail keeps its existing semantics. The delegate still requires authorization and escrow and remains exempt from outflow limits.

The 100k budget covers the custom-ring proof. SPP settlement is separate. Three published outputs use its padded 2×4 circuit. Ordinary custom settlement adds 57,680 constraints, giving **153,623** across both proofs. The default-ring settlement circuit has 57,554 constraints at that shape.

The main savings come from avoiding repeated work.

```text
Before
  policy table → hash again inside proof
  each record  → separate 20-level Merkle path
  audit        → support every shape and both modes

After
  stored policy → verifier binds its public fields
  shared records → one upper path per registry
  audit          → prove exactly this shape and mode
```

The new proof has 78 public inputs. The program constructs them from its own PolicyConfig account and the transaction's resolved tree slots. The table is already public. It does not enter the instruction payload. The proof still occupies 192 bytes. Policy creation and every policy edit validate the table and update its hash.

Registry openings share a private sparse Merkle frontier. Every queried leaf must have a complete chain of expanded ancestors. The proof binds each active record to the same subtree and index prefix, then authenticates that subtree against the existing height-20 root. Present records, absence witnesses and repeated subjects all work. Existing paths supply the frontier. No extra indexer query is needed.

**Eligibility matters.** Within each registry, all queried record indices must fit in one aligned block of eight leaves. An absence query uses its predecessor record's index. The own registry and curator can use different blocks. The registry itself can be much larger than eight records. Scattered records and other shapes keep the unrestricted proof. Indexed requests also keep that route because the client does not yet know their record positions.

The smaller arithmetic gadgets preserve the same integer bounds. Absence uses four nonnegative gaps that partition `q - 1`, proving strict canonical order without decomposing three full field elements into bits. Amount checks range-check the low limb and constrain the comparison bit. Packed rules decompose only the masks that evaluation needs as bits. Canonical X25519 keys check byte bounds and the short exceptional range at the top of the field.

Fixed keys also remove unused slot checks, repeated rule decoding and unused anonymous disclosure groups. They keep the existing X25519, AES, KDF and ciphertext formats. The auditor still recovers the transaction viewing key and the checked note disclosure. Anonymous disclosure still covers the sender, spent notes and recipients.

Security checks cover forged hint outputs, modulus wraparound, limb carries, out-of-range key bytes, false comparison bits, missing Merkle expansions, wrong upper paths, mixed prefixes and substituted disclosure fields. Full-policy fixtures reject unapproved recipients and assets, frozen senders, exceeded guards and caps, false approval flags and wrong escrow keys. Rust accepts the generated proofs under the committed keys and rejects changes to every one of the 78 public inputs. It also rejects cross-mode proofs and missing commitments.

The SBF verifier test uses 488,137 CU through the 78 public inputs and Groth16 pairing. Its deliberately invalid proof stops before the commitment pairing and SPP CPI. This is not a complete transaction CU measurement. Full valid proofs pass native Rust verification. A live end-to-end transfer was not run.

Fresh ephemeral keys and a fresh viewing-key/salt pair remain necessary. Reuse repeats the encryption stream. Both SDKs generate fresh ephemeral keys.

The table/hash relationship now relies on the program's authenticated account state. A verifier must never take the public policy fields from the prover. Recent accepted registry roots can still predate a list update. This is the existing root-history policy. Recipient ciphertext delivery remains outside the ordinary transfer proof. These are implementation tests and a source review, not an independent cryptographic audit.

The prover serves three new circuit types. Program tags 33 and 34 select them, with anonymous mode chosen from the stored ring configuration. Rust selects all three modes. TypeScript selects the ordinary and delegate variants it supports. Both retain the existing path for ineligible transfers.

Keys were generated locally. The verifying keys, local proving-key hashes, client pins and release tooling agree. The historical release manifest stays unchanged. Deployment must ship the program, prover keys and clients together.

Reproduce counts and full proof checks from `prover/server`:

```sh
go test ./custom_rings/circuits/policy -run '^TestPublicTable' -v
go test ./custom_rings/circuits/base ./custom_rings/circuits/registry
go test ./prover/custom_ring ./prover/fingerprint
```

| Proof for a 2-input, 3-output payment | Constraints | Proving time |
|---|---:|---:|
| Default-ring settlement | 57,554 | 146.6 ms |
| Custom-ring settlement | 57,680 | 159.7 ms |
| General policy and audit | 326,293 | 575.6 ms |
| New ordinary policy and audit | 95,943 | 237.8 ms |
| New anonymous policy and audit | 98,809 | 267.9 ms |
| New delegate policy and audit | 95,217 | 271.9 ms |
| Custom settlement + new ordinary policy and audit | **153,623** | **397.5 ms** |

Proving benchmarks use an Apple M5 Pro with 18 Go threads. Times are medians of three batches of five proofs. They exclude compilation, setup, witness encoding and verification. Every timed proof is verified outside the timer. The combined time adds the two medians. It is not transaction latency. The default and custom settlement measurements use the padded 2×4 circuit. The policy fixtures contain two real inputs, three real outputs and full tables.

```sh
go test ./prover/custom_ring -run '^$' -bench '^BenchmarkFullPolicyTwoByThree$' -benchtime=5x -count=3
go test ./circuits/spp_transaction/shared -run '^$' -bench '^BenchmarkTwoByThreeSettlement$' -benchtime=5x -count=3
```

The existing two-output audit-only path remains 58,645 constraints. With its 30,987-constraint settlement proof, that one-input, two-output transfer totals 89,632. Its two-hash Poseidon KDF came from `../zk-experiments`. The bounded-limb work follows the same principle used there and in [zk.golf](https://zk.golf/llms.txt). The new path changes proof structure, not the auditor's encryption format.
