# Open threads left by the wallet batch and the Light comparison

**Four items that belong to someone and currently belong to nobody. One is a row the reconciler can route, two are questions for the owner, and one is an architectural cost that rises the longer it waits.**

Written by the coordinator rather than by a review worker, so nothing here claims a verdict. Each item names who should pick it up.

## W02, unowned rather than blocked

The wallet worker left W02 at `STALE` and was explicit that nothing blocks it: the finding behind it was already re-reviewed to parity, and the fixture regeneration it waited on has landed. It stayed open because it lives in `wallet/src/deposit.ts` and the wallet deposit fixture, outside the packages that worker touched, and it declined to record a verdict it had not measured.

That is the right call and the reason this project has a reconciler. The row needs one worker to read the deposit path and either produce evidence or say what evidence would close it. It is small.

## `ShieldedKeypair.fromEd25519` takes a different argument in each language

TypeScript's `fromEd25519(secret, account)` takes an account index where Rust's `from_ed25519` takes a viewing key. The practical effect is that no TypeScript caller can pair a chosen viewing key with a chosen signing secret, which Rust callers can do.

This belongs to the `K` rows and therefore to the hashers batch, which owns `sdk-libs/ts/keypair/`. It was found by a worker in another package and recorded rather than fixed, correctly, since fixing another batch's files mid-flight is how this project lost work three times. Route it when that batch next has capacity. Confirm the direction before changing anything: Rust is the authority, so the likely fix is widening the TypeScript signature rather than narrowing the Rust one.

## Two Rust entry points disagree about waiting, and nothing says why

`sync_wallet` blocks waiting for the indexer and `sync_wallet_async` does not, because one is built from `SyncWalletConfig::new()` and the other from `SyncWalletConfig::default()`. No comment or document explains the split, and it reads as an accident of which constructor each entry point reached for rather than a decision.

Nothing was changed. The generated fixture records both values, so whoever rules on this has the numbers in front of them. This is an owner question, not a parity question: the port currently matches Rust, and it should keep matching Rust whichever way the ruling goes.

## The Solana dependency question, which gets more expensive with time

The Light comparison at [light-protocol-comparison.md](../light-protocol-comparison.md) puts this first among eleven findings, and the reasoning holds up. Light reuses `@solana/web3.js` for the transaction message, its serialized byte encoding, and the RPC client. Zolana hand-wrote each: `compileLegacyTransaction` in `client/src/client.ts`, a compact-u16 serializer at `client/src/solana-rpc.ts:464-473`, and its own JSON-RPC transport.

The consequence that matters is not the duplicated effort. It is that Zolana produces legacy messages only, so it has no address lookup tables and no `VersionedTransaction`. Light produces v0 messages and threads lookup tables through, and it did so under pressure: a transaction touching several state trees and queues exceeds the legacy account limit. Zolana's shielded transfers touch pool trees and nullifier queues in the same pattern, so the same limit is ahead of us, reached later and with a transaction compiler nobody outside this repository maintains.

There is already a visible second-order cost: a base58 decoder that recovers an unknown instruction length by trying each value from 1 to 1232.

This is an owner decision and a large one. It is listed here rather than dispatched because it is out of scope for a parity pass and choosing it changes what the remaining rows mean.
