# Spec Prose Style

Rules for any text written into `docs/spec.md`. Derived from `docs/SPEC_GUIDE.md`,
`docs/CLAUDE.md`, and the avoid-ai-writing skill (docs/technical profile).
Violations in existing spec text are fair game to fix during an edit pass, but
never rewrite prose that carries no defect.

## Worked examples (imitate these)

The single most useful calibration. Each pair is a real defect class → its fix.

Restated size (delete the comment; the type/constant already says it):
- Before: `encrypted_utxo: Vec<u8>, // single ciphertext bundle, exactly 110 B`
- After:  `encrypted_utxo: Vec<u8>,` — with the 110 B named once, in [Constants].

Field narration (delete; the field name already says it):
- Before: `blinding: [u8; 31], // random blinding for the output`
- After:  `blinding: [u8; 31],`

Copula avoidance → plain copula:
- Before: "The nullifier serves as the double-spend guard and features a
  per-owner secret."
- After:  "The nullifier is the double-spend guard; it binds the owner's
  `nullifier_secret`."

Correction that appends instead of replaces (rewrite in place, no growth):
- Before: "The proof is 192 bytes. (Note: the eddsa rail is 128 bytes.)"
- After:  "The proof is 128 bytes on the eddsa rail, 192 on the P256 rail."

Overloaded table cell → row plus a note:
- Before: one cell with four sentences of caveats.
- After:  a two-clause cell, and the caveats in a notes list under the table.

## Information density

- Every sentence states a fact, constraint, or rationale. If a sentence
  restates the previous one in fresh words, cut it.
- Prefer "X is Y" and "X has Y" over "X serves as Y", "X features Y",
  "X represents Y".
- No filler: "it's worth noting", "importantly", "note that", "in order to",
  "at its core", "comprehensive", "robust", "leverage", "seamless", "delve".
- No hedge stacks ("could potentially", "may eventually"). Normative text uses
  RFC 2119 keywords; descriptive text states what the code does.
- No significance inflation. State the mechanism; the reader judges importance.
- One idea per sentence. Imperative mood for procedures. Numbered steps for
  entry-point checks.
- Repeat the precise term instead of cycling synonyms. If the word is
  `nullifier`, write `nullifier` every time.
- Bold sparingly; never bold-label bullet lists that restate their own label.
- Tables for enumerable facts only. A cell holds at most two short sentences;
  longer rationale goes in a notes list after the table. A cell that needs a
  paragraph is a section, not a row.
- Correcting text replaces it in place. Never leave the stale claim beside a
  parenthetical fix; a corrected passage should not be longer than the original
  unless the added length is new fact.

## Banned vocabulary (docs/CLAUDE.md)

- "the wire" (write: instruction data, transaction data, serialized form)
- "written by" for chain data (transactions are sent, not written)
- "wall time"
- "folded into"

## Definitions and links

- Define every type, constant, and derivation exactly once; link `[term](#anchor)`
  everywhere else. Never restate an encoding, size, or derivation that a type,
  the glossary, or a linked definition already states.
- Links target anchors inside `docs/spec.md` or files under `docs/` only.
  Never link repository code, the findings ledger, review tooling, or external
  URLs that duplicate in-repo content.
- The spec describes the protocol. It never mentions the review process, its
  own revision history, open findings, or implementation-status caveats framed
  as review output. Behavior that exists is specified; behavior that does not
  exist is absent or marked as a plain normative requirement.

## Implementation-status markers

A production spec may describe an interface that is designed but not yet built.
Mark it once, at the top of its section, as a plain fact:

> **Status.** Interface specification; not implemented in this repository.

Do not scatter "not yet", "TODO", or "will be" through the prose, and never
frame the marker as review output. An interface with no status marker is
asserted to exist and match the code. Remove a marker only when the code lands.

## Comments in spec code blocks

Every comment must justify its existence by adding protocol understanding a
reader cannot get from the code itself. The test: delete the comment — if the
struct field, type, glossary entry, or linked definition already conveys it, the
comment was noise and stays deleted. A comment earns its line ONLY by stating a
protocol invariant, a security constraint, a role/purpose, or a non-obvious
layout decision.

Markdown comments (`<!-- ... -->`) are exempt from the no-review-process rule:
the fix mode annotates each edit site with one — `<!-- ZSR-NNNN: why -->` — so
the commit diff carries its own justification. They never render; keep each to
one sentence.

Strip, even when the same comment exists in the implementation code:

- Narration of the field it sits on (`// the user's pubkey` on `user_pubkey`).
- Restatement of an encoding, size, or derivation the type or a linked
  definition already gives (`// 32 bytes` on `[u8; 32]`, `// SHA-256 of ...`
  next to a field whose derivation is defined elsewhere — link instead).
- Comments carried over from source that describe the implementation rather than
  the protocol.

The spec is not the code with prose around it; a comment that survives into the
spec must teach the protocol. Code-block comments obey the same
banned-vocabulary rules as prose.
