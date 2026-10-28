# Wallet Sync Benchmarks

Benchmarks of the wallet sync primitives and confidential decrypt operations.
Regenerate them with `cargo bench -p spr-transaction --bench wallet_ops`.

Operation times are criterion medians (bench profile).

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

`decrypt_transfer_recipient` opens a single confidential slot.
`decrypt_self_outputs` opens all confidential outputs of a split.

Run `wallet_ops` on an idle host to record these times.
