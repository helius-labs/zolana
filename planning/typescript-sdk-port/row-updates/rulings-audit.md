# Rulings audit: recorded, reflected, queued, landed

Branch `port/rulings-audit`, tree `zolana-ts-rulings-audit`, off `ts-sdk-port`
at `083424c8`. The owner asked whether every ruling made during this port is
reflected and queued.

**Answer: 27 rulings exist, 19 were clean on all four counts, and 8 had a gap.
Every gap is now closed in the plan or the ledger. No ruling was recorded
wrongly: the ledger says what the owner decided in all 27 cases.** Three
rulings were not in the ledger at all, three had no owner, and one
implementation departs from the ruling it implements.

Each column below was checked against the tree rather than against a report.
"Landed" means the code or the specification text was read on this branch.

## The four questions per ruling

| Ruling | Recorded | Reflected | Queued | Landed |
| --- | --- | --- | --- | --- |
| G7-1 owner-hash encoding | yes | yes | closed | yes: `docs/spec.md:264-286` defines both encodings and restates rail separation |
| X01 indexer-api schema authority | yes | **added** | `port/interface-b`, plus new packet 8b | partial: port correct as ruled; `get_nullifier_queue_elements` still absent from the spec |
| K11 least-powerful capability | yes | partial, **now full** | **none, now packet 7a** | no: the three call sites still bind the concrete `ViewingKey` |
| T23 confidential owner tag | yes | yes | closed | yes: `docs/spec.md:900`, `:901`, `:960`, `:982-987` carry the variant split |
| G2-1 ECDSA malleability | yes | yes | closed | yes: `lowS: false` at `signing-key.ts:122` and `:142`, `p256-malleability.test.ts` |
| G2-2 Ed25519 acceptance | yes | yes | closed | yes: `verify_strict` at `signing_key.rs:142`, `ed25519-acceptance.test.ts` |
| C04 `Context` field | yes | **added** | closed | yes: `docs/spec.md:1910` is `block_time: i64` |
| C04 integer domain | yes | **none, now full** | **none, now packet 8a** | no: `876c5bf5` is unmerged and applies the union uniformly |
| DataRecord::Memo tag 3 | yes | yes, row T07 | closed | yes: `docs/spec.md:607` |
| CI tiering | yes | yes | closed | yes: `typescript.yml` runs five sub-scripts behind a merge gate |
| Custody seam | yes | yes | closed | yes: `security-and-release.md:94`; the two `*Like` interfaces require nullifier and viewing material |
| Indexer error `method` detail | yes | not needed | not needed | yes: the ruling was to change nothing |
| Breaking changes to SDK crates | yes | yes | not needed | yes: neither error enum is `#[non_exhaustive]` |
| Merge order against PR #158 | yes | yes | **none, now step B** | no: PR #158 is open |
| Zone-authority withdrawals | yes | yes, step 5 | step 5 | yes: no such guard exists in either language |
| Padding nullifier, PR #142 | yes | yes, `PD-1` | own pull request | not this branch's, as ruled |
| Where `user_record` lands | yes | yes, `PD-2` | `fix/merge-user-record-binding`, PR 160 | partial: PR open, `a811b20e` not on `main` |
| Zone prover built now | yes | yes | closed | yes: `assembleZone`, `assembleZoneP256`, `assembleZoneAuthority` |
| C07 forester builder withdrawn | yes | yes, step 6 | closed | yes: builder gone from `interface/src/instructions/index.ts`, codec kept |
| Poseidon to WebAssembly | yes | yes | closed | yes: five packages consume `@zolana/hasher`, no hand-written copy remains |
| Initializer instead of module-scope await, plus CommonJS | yes | yes | closed | yes: `initializePoseidon` at `hasher/src/index.ts:95`, `require` conditions in each package |
| WebAssembly artifact CI gate withdrawn, 2026-07-26 | implied only, **now explicit** | yes | `port/hasher-pkg` | in flight |
| T21 external-data length prefix | yes | stale, **now correct** | step 5 | yes: `8ded1d7a`, guard plus the boundary vector |
| C08 rail inference | yes | yes, step 6 | closed | yes: the rail travels with the request |
| M01 indexed-array sentinel | **batch file only, now in ledger** | no | half on an unpushed branch | partial: SDK half at `4d9a39f1` |
| Deposit discovery tag | **batch file only, now in ledger** | yes, steps 3 and 4 | closed | yes: both the code and `docs/spec.md:373` |
| Transaction size check | **nowhere, now in ledger** | step A said it awaited the owner, **now correct** | `port/open-questions`, unmerged | partial: measures, does not diagnose |

## Nothing was recorded wrongly, and here is what that rests on

The owner asked for a mis-recorded ruling to be flagged prominently. There is
none. For each of the 27 I compared the ledger's `Ruling` cell against the
evidence section above it and against the artifacts the ruling names, and in
every case the recorded decision is the decision the artifacts show being
carried out. The two closest calls are worth naming so a later reader does not
mistake them for mis-recording:

- **The ledger's contents list called G7-1, T23 and C04 open** after all three
  were ruled, and its anchors pointed at headings that no longer exist. That is
  the index being stale, not the ruling being wrong; every one of those sections
  carries the correct ruling in its own `Ruling` block. It mattered anyway,
  because X01 and K11 were absent from the list entirely, so two rulings were
  unreachable from the register's own index.
- **T21's ruling says the boundary vector "is owed by both and exists in
  neither".** That was true when written, at `3cacdb4c`, and false thirteen
  minutes later when `8ded1d7a` generated it. Superseded, not wrong.

## The gap that matters most: C04 is implemented against the wrong half

`876c5bf5` on `port/open-questions` adopts the union, a decimal string or a JSON
number with unsafe numbers still refused, and routes every integer through one
`wireInteger`. The ruling says the opposite of uniformly:

> Follow Light in applying the coercion only to fields whose domain can actually
> exceed `2^53`, rather than uniformly, so a field that cannot overflow does not
> acquire a parse path it never needs.

Light's own split is per field. `lamports`, `seq`, `slotCreated` and
`discriminator` take `BNFromStringOrNumber`; `slot` and `leafIndex` are plain
`number()` with no coercion at all
(`js/stateless.js/src/rpc-interface.ts:316-328`, `:429`, `:83`). Over this codec
the same split puts `seq`, `root_seq` and `start_seq` on the union and leaves
`block_time`, `slot`, `leaf_index`, `low_element_index`, `high_element_index`,
`tree_type` and `root_index` reading a plain safe JSON number. The branch as it
stands grants the escape hatch to seven fields the ruling excludes.

This is not a mis-recorded ruling. It is the per-field half being dropped in
retelling, which is what the owner predicted would happen, and it happened
inside a single evening.

## Three rulings were not in the ledger

Each was made in conversation, recorded in the batch file of whoever
implemented it, and never reached the register that exists to hold every ruling.
All three are now sections in `authority-rulings.md`.

- **The deposit discovery tag.** The tag is the recipient's signing pubkey, not
  the viewing pubkey x-coordinate. Fully landed, in the code and at
  `docs/spec.md:373`, and it was recorded only in
  `row-updates/deposit-tag-change.md`.
- **The transaction size check, ruled into this pull request.** Recorded
  nowhere. `remaining-work.md` step A still asked the owner to accept or reject
  the recommendation the owner had already accepted.
- **M01, the indexed-array sentinel.** Rust is the defective side and the
  TypeScript guard stands. Recorded in `row-updates/hashers-b.md`. Its
  `program-libs` half is on `fix/indexed-array-exclusive-highest-value`, which is
  local, unpushed, and has no worktree.

## Three rulings had no owner

"Someone should do this" is not queued, and these three had nothing more than
that. Each now has a packet in `remaining-work.md` naming the work and what
closes it.

- **K11's remaining call sites**, now packet 7a. The plan recorded the
  behavioural half as settled and said nothing about the three call sites that
  keep any consumer from passing a viewing-key backend.
- **The rebase onto PR #158**, now step B. The word "rebase" appeared nowhere in
  `remaining-work.md` or `README.md`, for a ruling that orders this port behind
  another pull request and names a hazard that compiles and passes while leaving
  the confirmation path unable to retry.
- **The specification entry X01 leaves owed**, now packet 8b.
  `get_nullifier_queue_elements` exists in Rust, in the port and in Photon, and
  in no version of the spec.

## Two documents that disagree with each other

`row-updates/wasm-verification.md` says a CI gate proving the committed
WebAssembly artifact came from the tree's Rust is "still owed". That gate was
withdrawn on 2026-07-26 in favour of the packaging change a worker holds on
`port/hasher-pkg`, and the withdrawal was recorded only as an implication of the
"Corrected 2026-07-26" paragraph in `poseidon-wasm-and-packaging.md`. The ledger
now states the withdrawal and names the superseded paragraph.
`wasm-verification.md` is another worker's file and was left alone.

## The worktree table was missing nine trees

A ruling counts as queued when a named branch owns it, and `README.md`'s
topology table is where a coordinator reads that. It listed nine trees while
`git worktree list` showed eighteen on this port. The two omissions that cost
something were `port/interface-b`, which steps 7 and 8 both wait on, and
`port/hasher-pkg`, which holds the packaging change that replaced the withdrawn
gate. Both read as unowned to anyone using the table.

## What this branch changed

Plan and ledger only. No ruling was implemented here; that is other workers'
work and would collide.

| Commit | Change |
| --- | --- |
| `936a96d8` | Repaired the ledger's contents list and dropped the two orphan table rows |
| `2436124c` | Carried the C04 integer-domain ruling into step 8, with the per-field split |
| `c87d991b` | Packets 7a and step B, the size-check correction to step A, and T21's correction |
| `140ac2b7` | The nine missing worktrees |
| `5d75f4ff` | Packet 8b |
| `365072dc` | The deposit tag and size-check rulings, the T21 landing, the gate withdrawal |
| `f6fc9ef7` | The M01 ruling |

## A fourth collision, during this audit

While this report was being written, a second agent committed it from this
worktree onto this branch as `a95e5be4`, with the message "salvaged from a
dropped agent". This agent was not dropped; it was mid-edit. Nothing was lost,
because the file it committed was this file and no other path moved, but the
commit message is wrong and the record should say so.

That is the fourth instance of the failure `README.md` documents three of, and
it fits the pattern the branch guard misses exactly: the branch name stayed
right the whole time, so a `git branch --show-current` check would have passed.
What surfaced it was `git log` showing authorship and a message this agent did
not write, which is the signal that section names.

The trigger was also the documented one. A coordinator judged an agent dead
during a quiet interval and acted on it, and the plan already warns that
transcript writes lag the work by as much as seventeen minutes and that quiet is
a reason to check the branch rather than a death certificate.

## Not counted as a ruling

"Resolve an open question the way Light Protocol resolved it" is a standing
instruction from the owner, dated 2026-07-26 and binding on everyone working
this port. It is recorded in `remaining-work.md` rather than in the ledger, and
that is the right place: the ledger holds one section per disputed behaviour,
and this decides how to settle disputes rather than settling one.
