# Poseidon strengthening component — source-only report

Date: 2026-10-11. Reviewed `ecies-std-proof-review.md` first, then rechecked
`Kdf/Poseidon.lean`, the extracted `Circuit/Kdf.lean` and `Circuit/Prelude.lean`,
production `circuits/gadget/poseidon.go`, and the locally installed primary
dependency sources `github.com/iden3/go-iden3-crypto@v0.0.17/poseidon/{poseidon,constants}.go`.
No tests, builds, Lean, generators, extraction, or cryptographic evaluation ran.
The declarations below are proof source; elaboration is unperformed, so this
report does not certify any newly written term as kernel-checked.

## Concrete changes

* `Kdf/Poseidon/Parameters.lean` freezes the literal optimized C/S/M/P tables
  for widths 3, 4, 8 and 9, independently of extracted K_* constants. These are
  the widths for input arities 2, 3, 7 and 8. The tables were copied textually
  from upstream hexadecimal string literals, retaining matrix orientation.
  A textual editing script selected existing source arrays and changed their
  delimiters; it did not calculate or generate cryptographic parameters.
* `Kdf/Poseidon/Specification.lean` defines the intended optimized permutation
  from those tables. It fixes the BN254 scalar modulus, x^5 S-box, initial
  zero capacity, ordered inputs, column-major mixing, sparse head/tail wiring,
  eight full rounds, partial counts 57/56/64/63, and coordinate-zero output.
  Finite table types and finite indices account for all constant/sparse slices.
  This module imports no extracted Poseidon predicate or evaluator.
* `Kdf/Poseidon/Width3.lean` contains independent full/P/final/partial round
  semantics and rewrite proofs for the extracted width-three gadgets. Fixed
  M/P literals are checked against the extracted matrices through definitional
  equality. ARK and sparse coefficients remain arbitrary in the round lemmas.
  `mix3_get` and `partialRound3_get` connect the explicit expressions to the
  mathematical finite-sum and sparse-layer definitions.
* `Kdf/Poseidon/Layers.lean` contains generic vector-valued dense/final/sparse
  layer bridges for widths 4, 8 and 9, with all twelve extracted round rewrite
  proofs. Their independent semantics live in `Specification.lean`.
* `Width3.Poseidon_2_spec_rw` and `Layers.Poseidon_3/7/8_spec_rw` attempt the
  complete four schedule bridges, including independent C/S pinning: rewrite
  the extracted round predicates, expand the finite reference schedule, and
  compare the resulting terms. The state operations remain opaque during
  these comparisons; the proofs do not inline coordinate expressions across
  all 56–64 partial rounds. Width-three pointwise lemmas connect its explicit
  three-term expressions to these generic vector-valued layers.
* All public `poseidon₂/₃/₇/₈` functions now denote independent specification
  functions, and the existing `Poseidon_2/3/7/8_rw` theorem interfaces use the
  schedule bridges. Width-three assignment proofs also use the independent
  layer rewrites. Continuation interfaces are retained for downstream KDF
  and envelope proofs. All new proofs remain unelaborated source candidates.

## Parameter identity and limits

The primary source is `cs.C/S/M/P` at indices `t - 2` in the pinned Go module.
Upstream parses these strings base 16 before conversion into field elements;
they are regular representatives, not Montgomery encodings. `M[input][output]`
and `P[input][output]` match both inspected Go mixing implementations.

`prover/server/go.sum` records module digest
`h1:NdkceRLJo/pI4UpcjVah4lN/a3yzxRUGXqxbWcYh9mY=`. The locally inspected
`poseidon/constants.go` has SHA256
`784271613dcfaa99912b009f7dbe2570ea7782930589c950464123f47cc8e6bc`.
The report records identity; no dependency download or checksum-database
verification was performed.

The independently written Clean constants/specification files were inspected
as supplementary material, not imported or treated as authoritative. In
particular, a dense permutation reusing the optimized C table while replacing
P/S by M is not a justified unoptimized HADES reference. Sample evaluations
would not establish a universal equivalence theorem, and none were run.

## Exact proof boundary still open

1. Complete extracted-to-independent bridges are now written for all four
   input arities, but none has been elaborated. In particular, finite constant
   slice normalization, finite-fold normalization, and the exact tactic/API
   compatibility require Lean validation before claiming verified integration.
2. No optimized-to-unoptimized HADES equivalence is claimed. This needs an
   independently justified unoptimized constant schedule and the round-key
   transformation/sparse matrix factorization proof. The present specification
   instead fixes the pinned upstream optimized algorithm directly.
3. No parameter-generation correctness, MDS/security property, collision
   resistance, Rust/light_hasher equivalence, or concrete hash test-vector
   correctness is proved by these declarations.
4. Lean elaboration, proof resource use, downstream compatibility and every
   runtime/test/build check remain unperformed at the user's instruction.
   The schedule proofs now preserve state-layer sharing instead of expanding
   every coordinate; their elaboration/resource use still must be checked.

No `sorry`, `admit`, new axiom, assumed hash-correctness premise, native-decide
bypass, or build/custom-tactic infrastructure was introduced. The strengthening
has source candidates for the requested independent hash bridges at all four
arities. Verified integration and the separate optimized/unoptimized-reference
equivalence obligation remain unfinished.
