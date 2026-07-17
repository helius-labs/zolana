# Spec Best Practices (RFC / standards conventions)

Authoritative conventions for a production cryptographic-protocol spec, distilled
to what `docs/spec.md` (a ZK confidential-transfer protocol on Solana) must
satisfy. `docs/SPEC_GUIDE.md` covers house structure; this file covers the
standards-body conventions on top of it. Each item states the rule, its source,
and what the audit flags (`spec-quality` unless noted). Apply the same
density discipline as everywhere else — these add rigor, not bulk.

## Normative language (RFC 2119 + RFC 8174)

- The spec MUST carry a Conventions section stating that MUST / MUST NOT /
  REQUIRED / SHALL / SHOULD / SHOULD NOT / MAY / OPTIONAL are RFC 2119 keywords,
  and — per RFC 8174 — are normative ONLY when in uppercase. A lowercase "must"
  is prose, not a requirement.
- Each normative statement is atomic and testable: one assertion, verifiable by
  inspection or a test. "The verifier MUST reject X and SHOULD log Y" is two
  requirements; split them.
- Audit: flag a missing Conventions section; flag a normative-sounding lowercase
  keyword in a checks/validation list (an implementer could miss the
  requirement).

## Security Considerations (RFC 3552 / BCP 72)

A cryptographic protocol spec MUST have a Security Considerations section that
states, concisely:

- The threat model: which parties are adversarial and their capabilities (ties
  to [Trust Assumptions](../../../docs/spec.md); do not duplicate the table,
  reference it).
- What each mechanism protects and against whom (double-spend, forgery,
  linkability, front-running).
- Residual risks and explicitly out-of-scope threats (RFC 3552 requires stating
  what is NOT protected — e.g. metadata timing, RPC-operator tag linkage,
  server-side-prover disclosure).
- Known unresolved weaknesses. Open `design-weakness` findings belong here as
  documented residual risk, not hidden.

Audit: absence is a `spec-quality` finding (medium — a crypto spec without it is
not review-ready). A design weakness that exists in code but is undocumented in
Security Considerations is a `spec-gap`.

## Cryptographic assumptions and construction identification

State once, explicitly (norm from RFC 9180 §9, ZK review practice):

- Proving system, curve, and field: Groth16 over BN254, with the field modulus
  named. For each circuit: the ordered public-input vector, the trusted-setup
  assumption (per-shape structured reference string), and that security rests on
  knowledge-soundness plus a correctly-run setup ceremony.
- Every KDF/hash is identified with its primitive and domain-separation label:
  HKDF-SHA256 (RFC 5869) with the exact `info`/label string; hash-to-curve is
  `P256_XMD:SHA-256_SSWU_RO_` (RFC 9380); SHA-256 is FIPS 180-4; P-256/SEC1 for
  point encoding. Tabulate every label and context string once (a labeled-
  derivation registry), so an implementer reproduces bytes exactly.
- Audit: an unnamed primitive, an underivable label, or a missing field modulus
  is a `spec-gap`.

## Wire format and encoding

- State endianness once and apply it uniformly; every multi-byte integer's
  encoding must be unambiguous (RFC 8446 presentation-language discipline).
- Every serialized struct that crosses a trust boundary has a visibility table
  (SPEC_GUIDE 10) and a fixed field order matching the code.
- Length prefixes, presence bytes, and discriminators are specified exactly (a
  decoder built from the spec must round-trip the code's bytes).

## Interoperability: test vectors (RFC 9180 §A style)

Cryptographic derivations SHOULD ship known-answer test vectors (or link to
where they live in the repo) for: `owner_hash`, `nullifier`, each view-tag
family, the transaction-viewing-key derivation, and the HPKE/merge encryption.
A vector fixes inputs → expected output so independent implementations agree.
Audit: absence is a low-severity `spec-quality` finding; do not fabricate
vectors — flag them for generation from code.

## Versioning and downgrade (RFC 8446 / RFC 9000 discipline)

- State how verifying keys and circuits rotate, how a client selects the version
  in force, and the behavior when parts of the stack are stale.
- Every extensible wire object carries a version/type discriminator, and every
  hash domain over it folds the discriminator in (SPEC_GUIDE 21). Default-deny
  unknown discriminators (SPEC_GUIDE 20).

## References

A production spec cites the external standards it depends on (RFC 7322): list
RFC 2119, RFC 8174, RFC 5869, RFC 9380, RFC 9180, FIPS 180-4, SEC1, and the
proving-system / BN254 references. Cite the standard, not a tutorial; keep the
list to what the protocol actually uses.

## Informative vs normative

Mark examples, diagrams, and size tables as informative; the normative text is
the source of truth. An example that contradicts the normative text is a defect
in the example, not the rule.
