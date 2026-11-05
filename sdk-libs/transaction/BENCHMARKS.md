# Wallet Sync Benchmarks

Benchmarks of the wallet sync primitives and confidential decrypt operations.
Regenerate them with `cargo bench -p spr-transaction --bench wallet_ops`.

Times are criterion's point estimates (bench profile).

Host: `Darwin 27.2.0 arm64`, `Apple M5 Pro`, 18 cores  
Date (UTC): `2026-11-05`  
Load: other builds were running (load average 19 to 35), so treat these as
upper bounds; rerun on an idle host for tighter numbers.

## Primitives

One X25519 scalar multiplication (`ecdh`) is the unit every EC-bound row reduces
to. Sender and request tags are HKDF-only streams; shared tags pay one ECDH per
derivation, and the recipient side additionally recomputes `self.pubkey()` (a
base-point multiplication) per call.

| Operation                    | Time        |
|------------------------------|-------------|
| `ecdh`                       | `37.3 µs`   |
| `recipient_shared_view_tag`  | `59.9 µs`   |
| `send_shared_view_tag`       | `39.3 µs`   |
| `sender_view_tag`            | `1.8 µs`    |
| `recipient_request_view_tag` | `1.4 µs`    |
| `transaction_viewing_key`    | `1.7 µs`    |
| `utxo_hash`                  | `126.3 µs`  |
| `nullifier`                  | `19.9 µs`   |

## Decrypt

`decrypt_transfer_recipient` opens the recipient's slot of a confidential
transfer. `decrypt_self_outputs` opens all eight confidential outputs of a
self-transfer of one UTXO into eight.

| Operation                    | Time        |
|------------------------------|-------------|
| `decrypt_transfer_recipient` | `37.7 µs`   |
| `decrypt_self_outputs`       | `287.7 µs`  |
