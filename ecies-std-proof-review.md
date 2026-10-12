# ECIES std branch — proof completion review

Reviewed branch: `jorrit/merge-std-ecies`, commit `c255c6400c0c824cf46b42b6e1f48dfd03becff5`, in `/Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2`. Date: 2026-10-10.

Static source review, with three GPT-6.1 Sol subagents examining the public theorem/assumption boundary, KDF/serialization, and multi-block envelope composition. No tests, builds, Lean execution, extraction, or generators were run. Proof infrastructure was excluded. This assessment does not certify that the current proof terms elaborate.

## Verdict

**The previously missing functional-soundness composition for the ECIES envelope is now present.** The 40-byte merge theorem starts with the actual extracted envelope predicate and connects P-256 key agreement, the context-bearing shared-secret hash, KDF, three AES-CTR blocks, packed public elements, and derived blinding. I found no new concrete circuit defect or premise that simply assumes the desired encryption result.

“Done” is accurate for that conditional envelope-correctness scope. It is not completion of all the additional strengthening proposals: circuit completeness, concrete lookup security, eliminating parameter axioms, and repairing the separate Merkle assumption remain outstanding.

## Previously missing connections now present

| Connection | Source evidence | Assessment |
| --- | --- | --- |
| Extracted field-to-byte conversion → canonical big-endian bytes | [FieldBytesBE_32_sound][bytes] | Starts from `FieldBytesBE_32 V k` and proves the continuation receives the bytes of `V.val`. The proof follows Boolean digits, recomposition, modulus comparison, and zero padding. It does not assume canonical hint output. |
| Extracted KDF → specified key and nonce | [KeySchedule_32_12_sound][kdf] | Takes the actual extracted predicate and concludes equality with `kdf poseidon S tmecInfo`. Domain values, fixed TMEC label, key-high/key-low byte slices, and nonce suffix are accounted for. |
| 40-byte AES stream, including the tail | [envelopeMerge_aes][aes] and [ctrEncrypt_40][ctr40] | Covers counters 2, 3, and 4, cached first-round contributions, and the eight-byte final block. Preserves the actual remaining constraints on output packing/blinding. |
| Whole 16-byte envelope | [envelope16_sound][env16] | Composes the P-256, shared-secret, KDF, AES and public-coordinate results from `Envelope_32_65_16_16`. |
| Whole merge envelope | [envelopeMerge_sound][mergeproof] | Composes `EnvelopeMerge_32_65_40_4`, including `Ctx`, all four packed elements, and `Bl = Poseidon(TMEB, sharedSecret)`. |
| Link to extracted constraints | [envelopeMerge_body][body] | The conversion to the shared key-agreement body is `:= h`: a definitional connection, not a new assumption asserting equivalence. Subsequent proofs derive semantics while preserving the continuation. |
| Link to production specialization | [EnvelopeMerge Go wrapper][wrapper] | Calls the same envelope implementation, production merge domain constants, output-packing helper, and blinding helper. The old 16-byte/no-context specialization mismatch is closed. |

The public merge theorem establishes both `sQ` and `sG`, canonical recipient and ephemeral coordinates, plaintext byte bounds, and exact output-field formulas. Its packed head combines two 16-bit coordinate suffixes with 27 ciphertext bytes; the remaining ciphertext suffix is packed separately. These match the production helper's 31-byte head field and 13-byte tail field.

The actual Rust merge host also uses the corresponding TMEC label: [MERGE_ENVELOPE_INFO][rustlabel] is six zero bytes followed by `TMEC`, packed as one big-endian field element. That is the same integer as Go's four-byte `TMEC`; the different source-string lengths are not a mismatch. The inspected key/nonce slicing and shared-secret preimage order also agree with the merge host. This is source comparison, not a proof of Rust implementation equivalence.

## Important limits of the completed statements

### Poseidon is defined from the extracted implementation

[Kdf/Poseidon.lean][poseidon] defines each arity-specific `poseidon` function as the unique output of the corresponding extracted gadget. Its rewrite lemmas establish determinism and functional semantics of those concrete gates. They do **not** prove agreement with a separate HADES/iden3/light_hasher specification.

This is sufficient for a meaningful proof of how the envelope uses that hash: changing its preimage order, context, KDF domain, or byte slicing can contradict the fixed outer specification. But a deterministic internal Poseidon constant or matrix error can change both the implementation and the function used by the conclusion. The current envelope proof is therefore not an independent check of Poseidon's internal parameters or interoperability. No such concrete parameter error was found in this review.

### Lookup correctness and mathematical parameters remain assumptions

[LookupAssumptions][lookups] bundles range, row and AES lookup semantics. Moving them into a structure makes their use explicit; it does not prove them from the production commitment/log-derivative arguments. The top statements genuinely remain conditional on these properties.

The BN254 primality axiom and the three P-256 parameter/group axioms remain. No new hidden encryption-result axiom was found. The separate impossible Merkle injectivity axiom remains in `Main.lean` and is explicitly acknowledged in the lookup-assumption documentation; the VE proofs do not import it.

### Soundness is still one-way

The envelope theorems say that satisfying constraints imply the specified outputs. They do not construct satisfying witnesses for every valid input or prove the Go hints always succeed. The previously reported inverse-four guard mechanism remains addressed by the earlier ladder change; the new envelope proofs do not add general completeness.

### The full merge transaction is a larger statement

The formal wrapper accepts an arbitrary 40-byte plaintext and context. Production supplies the amount/mint serialization and first nullifier, then consumes the four envelope elements in its larger public-input hash and the blinding in its output commitment. Those choices match the inspected Go callers, but the envelope theorem itself does not prove that complete transaction composition, nullifier uniqueness/freshness, Merkle state validity, or cryptographic confidentiality.

## Status against the suggested strengthening work

| Proposal | Current status |
| --- | --- |
| Compose P-256, KDF, AES, production-sized envelope and packed outputs | **Implemented for the extracted 40-byte merge envelope**, conditional on the stated assumptions. |
| Constructive completeness and hint-generator correctness | **Not implemented by these soundness theorems.** |
| Prove concrete lookup arguments secure | **Still assumed through `LookupAssumptions`.** |
| Replace impossible Merkle injectivity by a collision reduction | **Not done; explicitly left separate.** |
| Prove primality/group-order parameter facts | **Still axioms.** |

The new source materially strengthens the proof coverage. The remaining items are different mathematical/security obligations, rather than missing links in the newly completed envelope soundness chain.

[bytes]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/formal-verification/VerifiableEncryption/Kdf/FieldBytes.lean:2436
[kdf]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/formal-verification/VerifiableEncryption/Kdf/KeySchedule.lean:35
[aes]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/formal-verification/VerifiableEncryption/Aes/EnvelopeAes.lean:319
[ctr40]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/formal-verification/VerifiableEncryption/Aes/MultiBlock.lean:81
[env16]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/formal-verification/VerifiableEncryption/Envelope.lean:58
[mergeproof]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/formal-verification/VerifiableEncryption/Envelope.lean:89
[body]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/formal-verification/VerifiableEncryption/Envelope/Bodies.lean:496
[wrapper]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/circuits/formal/ve/circuits.go:130
[rustlabel]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/sdk-libs/keypair/src/derivation.rs:156
[poseidon]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/formal-verification/VerifiableEncryption/Kdf/Poseidon.lean:123
[lookups]: /Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/prover/server/formal-verification/VerifiableEncryption/LookupAssumptions.lean:36
