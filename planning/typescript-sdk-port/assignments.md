# Who is working on what

**This table is only worth reading if it is written at dispatch time.** The
coordinator adds a row when it launches an agent and deletes the row when that
agent's branch is merged and its tree released. A registry filled in afterwards
records what already happened, which is the thing nobody needed.

Before dispatching, read the Owns and Paths columns. If the subject or a path
is already claimed, do not dispatch; resume the agent that holds it, or wait
for its merge. That check takes one read and is the whole point of the file.

When it is not written, `node sdk-libs/ts/config/port-health.mjs` is the
backstop. It reports a file claimed by two live branches, reading uncommitted
worktrees as well as commits, so a duplicate surfaces in minutes instead of at
merge. The backstop is strictly worse than the registry: it fires once the work
is already duplicated.

## Running now

Seeded 2026-07-26 02:45 from `git worktree list`, `git reflog show <branch>`,
and each branch's commits.

| Agent | Branch | Worktree | Owns | Paths | Dispatched |
| --- | --- | --- | --- | --- | --- |
| `cb05915c`† | `port/rulings` | `zolana-ts-rulings` | C04 integer domain; the 1232-byte transaction size limit | `ts/indexer-api/src/codec.ts`, `ts/indexer-api/test/integer-domain.test.ts`, `ts/interface/src/transaction-size.ts`, `ts/client/src/client.ts` | 02:13 |
| `4dd92437`† | `port/c04-reconcile` | `zolana-ts-c04` | C04 integer domain, per-field. **Same row as `port/rulings`** | `ts/indexer-api/src/codec.ts`, `ts/indexer-api/test/integer-domain.test.ts`, `ts/api/src/index.ts` | 02:19 |
| `e6381add`† | `port/hasher-pkg` | `zolana-ts-hasher-pkg` | Hasher package: slim build, embedded artifact, packaging gates | `ts/hasher/**`, `ts/config/{build,pack-check,packages,workspace-check}.mjs` | 02:15 |
| `648a48f8`† | `port/rulings-audit` | `zolana-ts-rulings-audit` | Audit of the rulings ledger; the worktree topology table | `authority-rulings.md`, `README.md`, `remaining-work.md` | 02:17 |
| `867c860e`† | `port/stragglers` | `zolana-ts-stragglers` | Straggler rows C01, C02, T14, T15, W02, W04 | `ts/transaction/**`, `ts/wallet/**`, `ts/client/test/**`, `xtask/src/bin/wallet-actions.rs` | 01:50 |
| `192a17a4`† | `port/ci-green` | `zolana-ts-ci` | The failing CI jobs | `.github/workflows/**`, `Cargo.toml`, `package.json`, Rust build breaks | 23:02 |
| `21159ea7`† | `port/overlap-detect` | `zolana-ts-overlap` | Overlap detection, and this registry | `ts/config/port-health.mjs`, `assignments.md` | 02:21 |

Paths are relative to `sdk-libs/` or to this directory, whichever the leading
segment names.

**`port/rulings` and `port/c04-reconcile` are the collision this file exists to
prevent, live.** Both were dispatched at the C04 integer domain six minutes
apart, both rewrote `codec.ts` and `integer-domain.test.ts`, and neither was
told about the other. It is the fourth time that row has been handed out twice.
The health check now names it; the coordinator still has to pick one and stop
the other.

† **The agent column is reconstructed, not recorded.** Each id was matched to
a tree by which worktree path its transcript mentions most, which is evidence
and not a registration. `192a17a4` is the weakest: its transcript names
`zolana-ts-ci` once and has been quiet for an hour while the branch kept
moving. Treat the ids as leads to confirm, and write the real one at dispatch.

Dispatch times are branch-creation times from the reflog. They are when the tree
started work, which is close to but not the same as when the agent was launched.

## Trees held but not working

`port/open-questions`, `port/spec-amend`, `port/reconcile`,
`port/plan-rewrite`, `port/versioned-tx`, `port/wasm-verify`,
`port/merge-prefix`, `port/interface-b`, `port/client-b` and
`port/transaction-b` are merged, and their trees are retained because their
agents may still be resumable.

Do not reassign one of these trees to a new batch. Reusing a tree whose agent
could still be resumed, and reusing it under a name that describes the old
batch, are the two mistakes behind the three worktree collisions recorded in
[`README.md`](README.md#one-tree-one-branch-one-agent). A new tree costs a
copy-on-write clone of `node_modules`; a collision costs an hour.
