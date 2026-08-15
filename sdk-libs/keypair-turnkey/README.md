# zolana-keypair-turnkey

Turnkey-backed implementations of `zolana_keypair::ShieldedKeypairTrait`. The
shielded signing key stays in a Turnkey sub-organization and is used remotely;
the nullifier and viewing secrets are derived and held in-process, which is what
the trait's custody boundary requires — both are private proof inputs, so no
signing device can hold them on our behalf.

## What Turnkey can and cannot root

Both role secrets expand from a rail-specific `derivation_seed`, so whether
Turnkey can root an identity reduces to whether it can produce that seed:

| Rail | Seed | Turnkey |
| --- | --- | --- |
| ed25519 | RFC 8032 signature over a fixed message | yes, `SIGN_RAW_PAYLOAD_V2` |
| P-256 | `ECDH(signing_sk, P_derive)` | no key-agreement activity exists |

Turnkey's API has no key-agreement operation of any kind — signing and
transaction signing are the only cryptographic primitives — so there is no
Turnkey equivalent of AWS KMS `DeriveSharedSecret`, and the P-256 rail cannot be
rooted there.

## The two backends

`TurnkeyEd25519ShieldedKeypair` is rooted entirely in Turnkey. One
`SIGN_RAW_PAYLOAD_V2` at bootstrap yields the seed, and both role secrets expand
from it bit-identically to `ShieldedKeypair::from_keypair`. Nothing secret needs
to be persisted: a `TurnkeyKeyRef` (sub-organization id + private key id, neither
secret) plus a Turnkey credential rebuilds the whole identity. The same key is
the wallet's owner-signer and its Solana address.

`TurnkeyP256ShieldedKeypair` uses Turnkey only as the spend-signing device and
takes both role secrets from the caller. That is a genuine split-custody design —
it is what the AWS KMS three-key backend does — but the roles are *not*
recoverable from the signing key, so whoever supplies them must persist them.
Prefer the ed25519 rail unless the P-256 owner rail is specifically required.

## What this is not

Turnkey here is a key-availability and policy boundary, not a privacy boundary.
On the ed25519 rail the seed is a signature the key can always produce, so any
credential authorized to sign with that key can re-derive the viewing and
nullifier secrets and obtain both full view and full spend. The signing methods
refuse
derivation-shaped payloads via `derivation::is_derivation_input`, but that guard
binds this process, not the credential. Narrowing it requires a Turnkey policy
that denies the derivation payload once bootstrap is done, which depends on
`activity.params.payload` being matchable in the policy language — verify that
against a dedicated test organization before relying on it.

## Layout

- `activities.rs` — the `TurnkeyActivities` transport seam and `TurnkeyKeyRef`.
- `api.rs` (feature `api`, default) — the seam over `turnkey_client`. The only
  module that knows about it.
- `codec.rs` — signature reassembly. Ed25519 components are little-endian and
  must never be re-padded; ECDSA scalars are big-endian and must be. Getting this
  backwards on the derivation path silently produces a different wallet.
- `blocking.rs` — the async-to-sync bridge the synchronous `sign_message` /
  `sign_hash` trait methods need.
- `ed25519_rail.rs`, `p256_rail.rs` — the backends.

## Tests

```bash
cargo test -p zolana-keypair-turnkey
```

No network and no HTTP stack: the tests replace only the transport, so the code
under test is the code that talks to the live API. The central assertion is
byte-for-byte parity with a software `ShieldedKeypair` — a backend that derives a
*different* identity still produces valid signatures and correct-looking
addresses, so nothing weaker catches it.
