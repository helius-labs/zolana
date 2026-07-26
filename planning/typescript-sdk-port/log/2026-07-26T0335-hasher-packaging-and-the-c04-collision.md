# 2026-07-26 01:35 UTC | reconciliation: the hasher packaging strengthens `H01`, and the C04 collision is over | `H01`, `C04`, `A01`

- Baseline: HEAD `7eb5dce8`, the `ts-sdk-port` tip merged into `port/reconcile3`
- Worker: reconciler, fourth holder of the role
- Explanation: folding in the last three backlog reports. One strengthens a row that was already closed, one reports a failure that no longer exists, and one is an audit of the rulings rather than row work
- Evidence: the three named test files run here (42 cases, no failures), `npm run fixtures:check` re-measured clean, and `git worktree list` compared against the README table

## `hasher-packaging.md`: `H01` keeps its verdict and gains a forcing function

`H01` has been `done` / `PARITY` since the Poseidon parity work, on
`xtask/src/bin/poseidon-parity.rs` and 312 tests across five TypeScript copies.
The packaging report does not change that verdict, and it does not claim to.
What it changes is whether the verdict can quietly stop being true.

`src/artifact.ts` was a 1.9 MB base64 module that only `npm run embed` wrote,
and nothing ran that. A change to `program-libs/hasher` left every TypeScript
package hashing to digests no verifier reproduces, which is the exact defect
class the WebAssembly work exists to close, reintroduced by the packaging. The
compile is now part of the build: `config/build.mjs` runs a package's
`scripts/build-hooks.mjs`, and `@zolana/hasher`'s hook compiles
`sdk-libs/hasher-wasm` when `artifact.lock.json`'s hash over eleven pinned
inputs has moved.

The evidence is a control edit rather than a description, which is why it counts
here: with `hash_bytes_be` changed to `hash_bytes_le` in
`program-libs/hasher/src/poseidon.rs` and nothing else touched, the build
recompiled unprompted and the parity suites failed 107 of 118 assertions.
Reverting restored the artifact byte for byte and `artifact.lock.json` came back
identical. That is the end-to-end demonstration `H01`'s row had for the
TypeScript copies but not for the artifact they hash against.

Two things it does not close, recorded rather than folded into a verdict. The
committed artifact can lag its Rust, deliberately ungated on the owner's ruling,
and the visible consequence is that `typescript / static`, `suites`, and
`packaging` have no Rust toolchain, so a change to the Rust hasher without a
regenerated artifact turns those three jobs red on the build's refusal. That is
a true failure with an actionable message, and installing Rust in those jobs
would convert it into a green build over a stale cache. It bears on criterion 4
of the entry gate, so it is now in the baseline's CI note. Separately,
`@zolana/hasher/slim` is not wired into the six packages above it, so no
consumer reaching them can take the file-loading path.

## `ci-green-indexer-c04-collision.md`: the report is correct and the failure is gone

The report is a clean piece of work and it should not move a row, because the
condition it describes no longer holds. It recorded `schema.test.ts` "decodes a
u64 above the safe-integer bound carried as a decimal string" failing on
`leaf_index`, with the test arriving from `876c5bf5` and the decoder that
rejects it from `c631594e` on top of `0f4a4ca4`, two trees answering the C04
question differently and both merged.

The coordinator did what the report asked: the per-field answer was kept and the
uniform one dropped. Verified here rather than assumed. `schema.test.ts` no
longer sends a string `leaf_index` at all, and the three files that carry this
behaviour, `indexer-api/test/schema.test.ts`,
`indexer-api/test/integer-domain.test.ts`, and `api/test/transport.test.ts`,
pass together, 42 cases with no failures. `C04` already records the resolution
and stays `DIVERGENT` for an unrelated reason, the specification entry at
`docs/spec.md:1897` that the implementation now contradicts.

Worth keeping the report's scope note visible for the next dispatcher: the two
trees were dispatched at the same row six minutes apart and neither was told
about the other, and the tree that found the collision correctly refused to pick
a winner inside a third tree.

## `rulings-audit.md`: no row moves on it

The audit checked 27 rulings on four counts and closed every gap in the ledger
or the plan, all of it in `authority-rulings.md` and `remaining-work.md` rather
than in the checklist. Its one finding that pointed at a row, that C04's first
implementation applied the union to every integer where the ruling applies it
per field, is superseded: the per-field form is what is merged, and `C04` says
so. Its README finding is acted on separately in this pass.

## Verdicts

- Verdict: `PARITY` for `H01`, unchanged, with the artifact forcing function added
- Verdict: `DIVERGENT` for `C04`, unchanged, and the reported collision is closed
- Verdict: `PARITY` for `A01`, unchanged
- Row transitions: none
- Progress: `105/145`
- Exact next file: `K11`, first at `needs_re_review` in queue order
- Full SDK parity claim: unsupported
