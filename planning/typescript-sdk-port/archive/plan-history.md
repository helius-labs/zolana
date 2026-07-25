# Plan history

> Archived from the README on 2026-07-26. It records how the plan reached its
> current baseline and what the first version of it got wrong. Nothing here is
> current instruction; for that, read
> [`../remaining-work.md`](../remaining-work.md).

## The three Rust baselines

1. The first inventory used local commit
   `2e1d7c815691054f79ac2cbfb372190e61747696` (`2e1d7c8`). It counted 170
   tracked `sdk-libs` paths and assigned wallet actions to `zolana-client`.
2. Public workflows were then inspected at
   [`helius-labs/zolana-examples@4d8c2d1`](https://github.com/helius-labs/zolana-examples/tree/4d8c2d16487a653d163d80b8c7f6e3702ebfdadc/rust-client/examples).
   That examples revision pins Zolana
   `2eba04498ab852e2c3135bf25e20f11e9d28bb2c` (`2eba044`). It provided concrete
   deposit, transfer, withdrawal, private-transaction signing, and confirmation
   workflows.
3. The selected parity baseline is `origin/main`
   `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`), with 182 tracked
   `sdk-libs` paths. It separates wallet state and actions into `zolana-wallet`
   and includes `zolana-indexer-api` and `zolana-smart-account-client`.

The first plan became stale because it combined an older 170-path inventory with
names learned from examples pinned to a different Rust revision. It listed
exports and broad responsibilities but did not define complete callable
signatures or the create, prove, build, sign, submit, confirm, and sync stages.
It also retained the old `signTransaction` name and client-owned wallet boundary
after current Rust had changed both.

## What the refresh changed

| Concern | First plan | Refreshed plan |
| --- | --- | --- |
| Rust baseline | Local `2e1d7c8` | Frozen `origin/main` `43fde8e4` |
| Tracked SDK paths | 170 | 182 |
| Wallet ownership | Included in `@zolana/client` | Separate `@zolana/wallet` |
| Indexer schema | Included in generated `@zolana/api` | `@zolana/indexer-api` schema and `@zolana/api` transport |
| Action contract | Export names and broad responsibilities | Exact functions, methods, types, stages, errors, and examples |
| Signing name | `signTransaction` | `signPrivateTransaction` |
| Instruction flow | Deferred to final examples | Defined before implementation and tested independently |

## The implementation reading order

Superseded by [`../remaining-work.md`](../remaining-work.md), which states what
is left rather than what to build. It is kept because the archived
[`work-packets.md`](work-packets.md) refers to it.

1. [Architecture and API contract](../architecture-and-api.md) for package
   boundaries and dependency direction.
2. [Public export manifest](../public-exports.md) for the exact callable surface.
3. [Action and instruction API](../action-and-instruction-api.md) for complete
   action-level and instruction-level workflows.
4. The six inventories for frozen-path coverage and implementation disposition:
   [client](../inventory-client.md), [wallet](../inventory-wallet.md),
   [transaction](../inventory-transaction.md),
   [keypair](../inventory-keypair.md),
   [supporting crates](../inventory-support.md), and
   [indexer and smart account](../inventory-indexer-and-smart-account.md).
5. [Examples and PR #111 assessment](examples-and-pr111.md).
6. [Testing and conformance](../testing-and-conformance.md), then
   [security, dependencies, and release](../security-and-release.md).
7. [Implementation work packets](work-packets.md).
8. [Proof and key-handling parity certification](../proof-and-key-parity.md).
9. [Production-readiness issues](../production-readiness-issues.md).
