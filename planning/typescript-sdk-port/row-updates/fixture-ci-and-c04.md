# Fixture CI gate and the C04 merkle-proof wait

Branch `port/fixture-ci`, from `ts-sdk-port` at `9c713b91`. Two independent
pieces of work: every Rust fixture generator now fails CI when its committed
oracle drifts, and the C04 merkle-proof completeness divergence is settled by
matching Light Protocol.

## Task A: every fixture generator is gated

`xtask/src/bin/` holds eleven binaries. All eleven already supported `--check`;
none needed a new mode. The generators are `merkle-semantics`, `poseidon-parity`,
`program-libs-parity`, `retry-schedule`, `solana-rpc-groups`, `solana-rpc-reads`,
`solana-rpc-send`, `ts-fixtures`, `ts-interface-oracle`, `wallet-actions`, and
`wallet-sync-tags`.

CI only ran `ts-fixtures -- --check` through `npm run check:fixtures`. The other
ten committed oracles could drift after a Rust change and leave TypeScript tests
green on stale data. `sdk-libs/ts/config/fixtures-check.mjs` now runs every
`--check` in turn, `package.json` points `fixtures:check` at it, and the
existing `typescript / fixtures` job is the place a drift failure lands. The
job keeps the same Rust toolchain and cache setup it already had.

All eleven `--check` runs passed at this HEAD. No committed fixture had already
drifted.

## Task B: C04 proof-wait closes at PARITY

### Revalidation

The finding is real. Blocking `ZolanaIndexer::get_merkle_proofs`
(`sdk-libs/client/src/indexer.rs:253-302`) takes two paths. When
`wait_for_indexer` is true it uses the shared block-time lag wait. When that
flag is absent or false, it falls into a hard-coded loop that polls every
500 ms for up to 60 s until `response.proofs.len() >= leaves.len()`, and on
expiry returns the last transport error or a synthesized
`ClientError::Rpc("merkle proofs for N leaves not indexed within …")`.
`AsyncZolanaIndexer::get_merkle_proofs` (`:409-439`) has no equivalent loop: it
is one call through `wait_for_indexer_async` and returns whatever arrived.

The claim that no caller argument turns the completeness loop on is correct.
The loop is the fallback when `wait_for_indexer` is not asked for; asking for
`waitForIndexer` buys the block-time wait both twins share, which is a
different guarantee. There is no config field that selects the per-leaf poll.

TypeScript `getMerkleProofs` already matched the async twin: `pollIndexer`, one
request when `waitForIndexer` is unset.

### What Light does

Light does not poll inside a merkle-proof read for leaf coverage.

In the TypeScript SDK, `getCompressedAccountProof`
(`js/stateless.js/src/rpc.ts:929-958`) makes one JSON-RPC call and throws if the
result is an error or null. Indexer catch-up is a separate helper,
`confirmTransactionIndexed` (`rpc.ts:1671-1687`), which the send-and-confirm
path calls explicitly after a transaction lands
(`js/stateless.js/src/utils/send-and-confirm.ts:106-107`).

In the Rust client, `PhotonIndexer::get_multiple_compressed_account_proofs`
(`sdk-libs/client/src/indexer/photon_indexer.rs:1108-1139`) retries transport
failures and `IndexerNotSyncedToSlot` when the response slot is behind
`IndexerRpcConfig.slot` (default 0). It does not wait until the number of
returned proofs matches the number of requested hashes.

So Light's answer is: fail or return what the indexer has on the proof method
itself, and expose an explicit wait for indexer catch-up that the caller (or a
higher-level send-and-confirm helper) invokes. That maps onto Zolana's existing
`waitForIndexer` block-time wait, not onto the blocking twin's hidden 60-second
completeness poll.

### What the port does

The TypeScript port keeps the non-polling behaviour. No new `ClientError` code
was required. A pin in `client/test/indexer-client.test.ts` requests two leaves,
receives one proof, and asserts a single HTTP call and an incomplete proof set.
A short note on `getMerkleProofs` records why the blocking twin's loop is not
carried.

**C04's merkle-proof wait divergence closes at PARITY** with the async Rust twin
and with Light. The blocking twin's completeness poll is deliberately not
ported: a hidden 60-second retry inside a read is a poor fit for a browser SDK,
and a caller who wants to wait already has `waitForIndexer` for catch-up or can
poll. Any remaining C04 residuals the checklist still names (integer-domain
quoting on the API transport, and so on) are outside this finding and stay with
their owners.
