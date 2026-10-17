The full 2-input, 3-output policy and auditor proof is below 100k constraints. No policy feature was removed. Ordinary recipient encryption stays wallet-side.

| Custom-ring proof | General key | New 2×3 key | Reduction |
|---|---:|---:|---:|
| Ordinary policy and audit | 326,293 | **95,943** | 70.6% |
| Anonymous policy and audit | 326,293 | **98,809** | 69.7% |
| Delegate policy and audit | 324,033 | **95,217** | 70.6% |

These are exact compiled R1CS counts. The new keys retain sixteen rules, eight list sources, eight per-mint amount thresholds, eight outflow rows, curator lists and key escrow. Each rail keeps its existing semantics. The delegate still requires authorization and escrow and remains exempt from outflow limits.

The 100k budget covers the custom-ring proof. SPP settlement is separate. An ordinary three-output payment uses SPP's padded 2×4 circuit. Ordinary custom settlement adds 57,680 constraints, giving **153,623** across both proofs. The default-ring settlement circuit has 57,554 constraints at that shape.

The same optimizations now cover eighteen ordinary settlement capacities. Each has a general registry path and a shared-subtree path. The table below counts the complete policy and auditor proof. It excludes SPP settlement. Smaller live counts can use a capacity through settlement's normal padding.

| Input capacity | 2 outputs, general | 2 outputs, shared | 4 outputs, general | 4 outputs, shared |
|---:|---:|---:|---:|---:|
| 1 | 124,234 | 87,884 | 174,017 | 99,243 |
| 2 | 136,919 | 90,963 | 186,703 | 102,323 |
| 3 | 149,605 | 94,043 | 199,388 | 105,402 |
| 4 | 162,290 | 97,122 | 212,074 | 108,482 |
| 5 | 174,976 | 100,202 | 224,760 | 111,562 |
| 6 | 187,661 | 103,281 | 237,445 | 114,641 |
| 8 | 213,032 | 109,440 | 262,816 | 120,800 |
| 12 | 263,774 | 121,758 | 313,558 | 133,118 |
| 16 | 314,517 | 134,077 | 364,269 | 145,405 |

| Other settlement rail | Capacity | General | Shared |
|---|---|---:|---:|
| Anonymous | 2×2 | 135,993 | 90,037 |
| Anonymous | 2×4 | 193,237 | 108,857 |
| Anonymous | 3×4 | 207,283 | 113,297 |
| Anonymous | 4×2 | 164,048 | 98,880 |
| Delegate | 2×2 | 136,274 | 90,318 |
| Delegate | 4×4 | 211,195 | 107,603 |

This adds 48 keys. The dedicated 2×3 keys remain available and keep their smaller exact-shape costs above. The new capacity keys also support smaller live prefixes, so their counts are not identical to the exact 2×3 keys.

The exact keys require two published inputs and three published outputs, plus eligible shared registry paths. Compact padding omits the trailing dummy slots from the public transaction. It reveals the actual input and output counts. The SDK defaults keep those slots padded. Delegate callers opt in with Rust's `.with_compact_padding()` or TypeScript's `compactPadding: true`. Anonymous transfers permit compact outputs but still reject compact inputs and cached slots. SPP retains its full witness capacity, 2×4 for ordinary and anonymous transfers and 4×4 for delegates.

Transaction limits exclude every 8-output and 16-output capacity and every capacity with 24 or more inputs. The serialized V1 transaction must fit 4,096 bytes and 64 accounts. Even 16×4 is conditional on the account set and payload. The [ring overview](changes-overview.md) gives measured byte sizes and the policy storage layout. Core transfer size is checked before proving. Final assembly checks the complete transaction again.

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

**Eligibility matters.** Within each registry, all queried record indices must fit in one aligned block of eight leaves. An absence query uses its predecessor record's index. The own registry and curator can use different blocks. The registry itself can be much larger than eight records. Scattered records use the general key for that capacity. Indexed requests also use the general key because the client does not yet know their record positions.

The smaller arithmetic gadgets preserve the same integer bounds. Absence uses four nonnegative gaps that partition `q - 1`, proving strict canonical order without decomposing three full field elements into bits. Amount checks range-check the low limb and constrain the comparison bit. Packed rules decompose only the masks that evaluation needs as bits. Canonical X25519 keys check byte bounds and the short exceptional range at the top of the field.

Fixed keys also remove unused slot checks, repeated rule decoding and unused anonymous disclosure groups. They keep the existing X25519, AES, KDF and ciphertext formats. The auditor still recovers the transaction viewing key and the checked note disclosure. Anonymous disclosure still covers the sender, spent notes and recipients.

Security checks cover forged hint outputs, modulus wraparound, limb carries, out-of-range key bytes, false comparison bits, missing Merkle expansions, wrong upper paths, mixed prefixes and substituted disclosure fields. Full-policy fixtures reject unapproved recipients and assets, frozen senders, exceeded guards and caps, false approval flags and wrong escrow keys. Rust accepts the generated proofs under the committed keys and rejects changes to every one of the 78 public inputs. It also rejects cross-mode proofs and missing commitments.

All 48 new keys generated and verified real proofs. Full-capacity fixtures exercise the last input, last recipient and last asset. They also reject policy violations after recomputing the transaction statement, so a stale hash cannot explain rejection. The ten existing keys still match their serialized circuits.

All 48 capacity keys also passed [live settlement](test/tests/ring_shapes.rs) on the final SBF programs. Each case proves policy and auditor disclosure, settles through SPP, checks note and nullifier updates, then decrypts the settled outputs. Both general and shared-subtree paths run at every supported capacity.

| Live transfer mode | Keys exercised | Transaction bytes | Complete transaction CU |
|---|---:|---:|---:|
| Ordinary | 36 | 2,612–3,980 | 678,407–735,252 |
| Anonymous | 8 | 2,323–3,309 | 736,921–756,662 |
| Delegate | 4 | 2,839–3,349 | 679,298–688,433 |

The three exact 2×3 keys passed the same settlement and auditor checks. That brings live coverage to all 51 policy keys. The TypeScript delegate path also settled with the exact key.

| Exact 2×3 mode | Instruction tag | Transaction bytes | Complete transaction CU |
|---|---:|---:|---:|
| Ordinary | 33 | 2,867 | 683,173 |
| Anonymous | 33 | 2,735 | 745,650 |
| Delegate | 34 | 3,028 | 679,041 |

These measurements include both proof verifiers and the SPP state transition. They are fixture measurements, not worst-case bounds. Accounts, owner-tag encoding and fee settings affect size. The 16×4 ordinary fixture settles at 3,980 bytes. Adding a separate payer and co-signer makes it 4,204 bytes. The SDK rejects that case before contacting the prover and leaves the input tree unchanged.

Fresh ephemeral keys and a fresh viewing-key/salt pair remain necessary. Reuse repeats the encryption stream. Both SDKs generate fresh ephemeral keys.

The table/hash relationship now relies on the program's authenticated account state. A verifier must never take the public policy fields from the prover. Recent accepted registry roots can still predate a list update. This is the existing root-history policy. Recipient ciphertext delivery remains outside the ordinary transfer proof. These are implementation tests and a source review, not an independent cryptographic audit.

Tags 33 and 34 retain the exact 2×3 path. Tags 35 and 36 select general capacity proofs for members and delegates. Tags 37 and 38 select their shared-subtree equivalents. The program selects the key from the settlement capacity and its stored ring mode. Rust selects all supported rails. TypeScript selects the ordinary and delegate rails it supports. Both reject excluded capacities before requesting proofs.

Keys were generated locally. The verifying keys, local proving-key hashes, client pins and release tooling agree. The historical release manifest stays unchanged. Deployment must ship the program, prover keys and clients together.

Reproduce counts and full proof checks from `prover/server`:

```sh
go test ./custom_rings/circuits/policy -run 'TestPublicTable|TestShaped|TestGeneralShape' -v
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
