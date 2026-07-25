# 2026-07-25 22:50 UTC | client RPC and transport batch, six rows judged, none closed | `sdk-libs/client/`

- Baseline: HEAD `01fc62bd`; batch report [row-updates/client-package.md](../row-updates/client-package.md) at `15c6d3ea`; fixes `3aef2c6f`, `ec3ddabe`, `1d69313d`, `5713f9f1`, `60bf506a`
- Worker: Opus 5 reconciliation subagent
- Explanation: This batch marked no row `PARITY` and said why in its own report: of the six rows in its half, each covers more surface than the behaviours it tested, and reading two files and finding them similar is what produced the thirty-five unsupported marks this queue is still paying off. I did not have to downgrade anything here. Two rows still move off `DIVERGENT`, because the specific difference each named is now closed under test, and a verdict of `DIVERGENT` should mean a live conflict rather than a row that has not finished.
- Evidence: The batch's own standard was that a fix carries a test run against the pre-fix code and observed to fail. Ten behaviours meet it. I checked that the named artifacts exist at this HEAD: `client/test/vectors/legacy-message-order.test.ts`, the two oracles `legacy-message-order-v1.json` and `merge-message-order-v1.json`, and the named cases in `indexer-client.test.ts`, `retry.test.ts`, and `solana-rpc.test.ts`. The Rust half of the retry pair lives in `sdk-libs/client/src/indexer.rs`.

## Two rows move off `DIVERGENT` without closing

- Verdicts: `PARTIAL` for `C01` and `C21`

`C01` named one reachable difference: a malformed indexer field is retryable in Rust and was fatal in TypeScript. `5713f9f1` maps `CLIENT_INVALID_RPC_RESPONSE` and the five other `ClientError::Rpc` narrowings onto the RPC cause, and the evidence is a matched pair, three attempts to `PollTimedOut { last_cause: Rpc }` in Rust and three attempts to `CLIENT_POLL_TIMED_OUT` with the RPC cause in TypeScript, both failing if the case is removed. The row stays open because one code's classification is not the retry surface.

`C21` is the more interesting one, because two of its four fixes ran in the direction this branch keeps getting wrong. `confirmPrivateTransaction` required each requested view tag to reappear in the indexed record while Rust accepts on the signature alone, so TypeScript burned its whole schedule and raised `CLIENT_INDEXER_TIMEOUT` on a record Rust confirms. A configured client also polled a hard-coded default, so setting `indexerConfig` did nothing. Both are TypeScript refusing or ignoring what Rust honours, which is the failure mode worth hunting, and both are now under test. The account ordering fix replaced a hand-built TypeScript expectation with an oracle `Message::new` produced. The row covers `client.rs` end to end, and four behaviours do not reach that far.

## Four rows stand where they were

- Verdicts: `DIVERGENT` for `C02`, `C04`, and `C22`; `PARTIAL` for `C05`

`C04` is the one to read carefully. The batch verified this row's three findings by re-reading `indexer.rs` against `indexer.ts`, and then wrote that re-reading is not evidence and left the row adverse. That is the correct call and it is worth naming as the behaviour the protocol wants, since the same sentence from a different worker would have arrived as a `PARITY` claim. What is newly under test here is the indexer-config substitution, nothing more.

`C02` needs a change in `sdk-libs/ts/wallet/`, outside the batch's package. `C22` got one third of its smallest fix from the transaction batch, which exported `MERGE_INPUTS`; the client still declares its own private copy at `prover/merge.ts:31`, so the constant now lives in three places rather than two. `C05` closed the resubmission gap and recorded the `searchTransactionHistory` difference as deliberate, because TypeScript is the more permissive side there and narrowing it would create the defect the fix workflow forbids.

`C03` is not this batch's row and stays where it is. Closing it means porting 19 `Rpc` methods plus versioned-transaction decoding, and PR #158 adds a twentieth.

- Gap and smallest fix: `C02`, wrap the `signNativeTransaction` rejection or split `NO_TYPESCRIPT_PRODUCER`. `C04`, a fixture over the decode path, after the #158 merge rather than before it. `C05`, retry any failure in `getConfirmedTransaction` and generate the grouping oracle. `C21`, evidence for the validation orders and the two reversed rejection orders. `C22`, import the exported `MERGE_INPUTS` and record it in the ledger
- Row transitions: `DIVERGENT -> PARTIAL` for `C01` and `C21`, both to `needs_re_review` against a landed fix; `C21` also moves from `proposed` to `committed`. Evidence and fix commits recorded on `C02`, `C04`, `C05`, and `C22` with no verdict change
- Progress: `64/145`, unchanged, which is the honest outcome of a batch that closed no row
- Exact next file: `planning/typescript-sdk-port/row-updates/prover-subtree.md`, rows `C06` through `C20`
- Full SDK parity claim: unsupported
