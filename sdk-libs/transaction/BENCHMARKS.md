# Wallet Sync Benchmarks

Benchmarks of the wallet sync primitives, composed decrypt operations, and
a full first-time sync scenario. Regenerate the operation benches with
`cargo bench -p spr-transaction --bench wallet_ops` and the scenario with
`cargo test --release -p spr-test-utils --test bench_scenarios --features parallel -- --ignored --nocapture`.

Operation times are criterion medians (bench profile). The scenario times are
single measured `Wallet::sync` / `Wallet::sync_parallel` calls over a pre-built
transaction history (release profile); generation of the history is excluded.

Host: `Darwin 25.4.0 arm64`  
CPU: `Apple M5 Pro`  
Date (UTC): `2026-06-11`

## Primitives

One X25519 scalar multiplication (`ecdh`) is the unit every EC-bound row reduces
to. Sender and request tags are HKDF-only streams; shared tags pay one ECDH per
derivation, and the recipient side additionally recomputes `self.pubkey()` (a
base-point multiplication) per call.

| Operation                    | Time        |
|------------------------------|-------------|
| `sender_view_tag`            | `1.6 µs`    |
| `recipient_request_view_tag` | `1.6 µs`    |
| `utxo_hash`                  | `161.5 µs`  |
| `nullifier`                  | `24.7 µs`   |

## Decrypt

`decrypt_transfer` opens the sender slot plus all `R` sibling recipient slots
(one ephemeral ECDH each) after re-deriving the transaction viewing key.
`decrypt_transfer_recipient` opens a single slot.

Run `wallet_ops` on an idle host to record these times.

## Full Sync: DeFi Trader Scenario

First-time sync of a fresh wallet over ~1 year of activity
(`tests/bench_scenarios.rs`, window `DEFAULT_TAG_WINDOW = 64`, index gaps up to
5 on every stream):

| Dimension                | Value                                          |
|--------------------------|------------------------------------------------|
| Own transactions         | 9,920                                          |
| Outgoing transfers       | 6,770 (50 recipients, top 5 at 500–300 each)   |
| Splits                   | 200 × 8 outputs                                |
| Bootstrap receives       | 100 (one per sender)                           |
| Request receives         | 400                                            |
| Shared receives          | 2,450 (100 senders, top 5 at 450–150 each)     |
| Stored UTXOs             | 11,320 (6,970 spent)                           |

Run the scenario on an idle host to record the `Wallet::sync` and
`Wallet::sync_parallel` times.
