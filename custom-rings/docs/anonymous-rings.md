# Anonymous rings

An anonymous ring is a custom ring whose config sets `RingMode::Anonymous`. A
transfer inside it hides the sender, the recipients, the amounts and the assets
from a chain observer. The ring auditor reads all of them. The protocol spec
holds every byte layout and derivation this guide names, see
[Ring Address](../../docs/spec.md#ring-address),
[View Tags](../../docs/spec.md#view-tags),
[Ring Anonymous outputs](../../docs/spec.md#ring-anonymous-outputs) and
[Anonymous outputs](../../docs/spec.md#anonymous-outputs).

## Roles

The **hidden owner** spends. Its Ed25519 key signs inside the proof and never
signs the Solana transaction. The **recipient** holds the signing, nullifier and
viewing secrets behind an address. The **payer** is the public fee payer. The
**co-signer** is the key the ring config names, when the ring has one. The
**auditor** holds the ring's X25519 key and opens every transfer. The
**indexer** (Photon) serves outputs by tag and the ring's history. A wallet
trusts it to return every transaction.

## Addresses and the `zolana:` URI

A `RingAddress` is a `ShieldedAddress`, the ring program id and one inbox
secret. A wallet issues addresses in order, `i = 0, 1, 2, ..`.
`ViewingKey::inbox_secret(i)` derives the inbox secret of address `i`.
Address `0` is the standing address.

The inbox secret is a capability. Its holder derives the tags of first payments
to that address. Share an address only with payers. Never publish it.

The text form is `zolana:<base58>?amount=&mint=&label=`. The base58 part carries
a version byte and a four-byte SHA-256 checksum. `RingPaymentRequest` parses it.
The parser rejects another scheme, version, length or checksum, an address the
`ShieldedAddress` decoder rejects, an unknown query key and a repeated query
key. The checksum does not cover `amount`, `mint` or `label`.

Two addresses of one wallet carry the same three public keys. Anyone who
compares them sees one recipient. Separate inbox secrets only stop one payer
from deriving the inbox tags of another payer's address.

## Tags and their allocation

Each scheme-9 output slot publishes a 32-byte view tag as its owner tag. The
builder takes the tag from one stream per slot:

- A first payment to an address takes the inbox stream of that address.
- A payment to a paired recipient takes the pair stream toward its viewing key.
  The sender's tag key on that stream is a pseudonym, `pair_pk`, unique to that
  recipient.
- The sender's own output takes the change tag of the transaction's first
  nullifier and the slot index.
- A deposit takes the deposit stream of the receiving keys.
- A padding slot takes `0x00` and 31 random bytes.
- An exit to the default ring publishes its owner's Solana key.

The builder fixes the slot order first, with `pad_to_canonical_shape`. For each
stream it reads one window of 64 indices from the indexer. Each slot then takes
the lowest index with no output under its tag that no earlier slot of the
transaction reserved. An exhausted window moves the stream to the next one. An
output nobody can decrypt still occupies its index.

Two senders can take the same free index before either transaction confirms.
The two outputs then share a tag, and an observer sees that link. The reader
opens every output under a tag, so neither payment is lost. Inside one
transaction the ring program refuses a repeated scheme-9 tag.

## Proven delivery

For every real scheme-9 slot the base and policy circuits prove one statement.
The published body is the AES-256-CTR encryption of the committed note under a
key that only the transaction secret and the recipient's viewing secret derive.
The opening carries the mint address, the amount, the canonical blinding and the
sender's `pair_u`. The circuit ties the note's owner hash to the signing key and
the nullifier key of the address the sender used. It encrypts under that
address's viewing key. It requires zero data hashes and the public ring. The
ring program hashes each 105-byte body into the statement, so a proof covers
those exact bytes.

The holder of the three secrets behind that address therefore recovers the note
from ring history. It opens the body, checks the opening against the on-chain
commitment and spends the note under the ring's policy.

The proof does not show that the sender chose the address it intended. It does
not show that anyone holds the keys of an address. It proves `pair_u` encrypted,
not derived from the sender's keys.

The proof assumes an honest builder for key freshness. It proves that the
transaction secret is clamped and matches the published `tx_viewing_pk`. It does
not prove that the secret derives from the first nullifier, or that the salt is
new. The SDK derives the secret from the first nullifier and draws a random salt
per transaction viewing key. A shared `TransactSession` keeps that salt for a
retry of the same outputs and refuses a different output set under the same
key (`AnonymousStreamReuse`). Two plaintexts under one key, salt and slot leak
their XOR.

## Uniform slot encoding

Every scheme-9 slot, real or padding, has the same public form. The ring program
enforces it for every slot:

1. The transaction carries the full output count of its shape. Compact output
   padding is refused.
2. Every slot carries data. A scheme-9 slot ends with the scheme byte `9` and
   104 ciphertext bytes.
3. A scheme-9 tag is inline, starts with `0x00` and is not zero.
4. No two scheme-9 slots of the transaction share a tag.
5. No slot publishes a zero output hash.

A padding body is 104 fresh random bytes. A padding tag is resampled until it
differs from every other tag of the transaction.

For an honest builder, these rules remove every structural marker that tells a
real output from padding. A sender who wants to signal can still do so through
fields it controls. A scheme-3 exit publishes its owner and is outside the
claim. The observer still sees the ring, the shape, the fee payer, the Solana slot and
any public leg. Tags shared across transactions and other public metadata
still inform guesses.

## Wallet sync

`UtxoScan::with_anonymous_ring` reads the anonymous streams of the current
viewing key next to the default-ring scan. The wallet keeps an
`AnonymousRingState` between scans, the count of issued addresses and the known
counterparties.

The fast path reads exact tags and never trial-decrypts:

1. The scan opens the deposit stream, the inbox stream of every issued address
   plus `ADDRESS_GAP` more, and the pair stream of every known counterparty.
2. Each round reads one 64-index window per open stream. A window with no
   occupied index closes its stream.
3. A note on the inbox stream of address `i` raises the used count to `i + 1`
   and keeps `ADDRESS_GAP` unused addresses open past it. Its `pair_u` adds a
   counterparty and opens that pair stream.
4. For every transaction that spends an owned note, the scan derives the change
   tag of each output slot and opens those slots.
5. The scan opens at most `DECRYPTIONS_PER_INDEX` outputs under one tag. A tag
   past that cap marks its ring for a recovery scan.

A wallet accepts an output only when the recomputed commitment equals the
published `utxo_hash`. The commitment covers its own keys, the mint address, the
amount, the blinding, the public ring and the tree id. AES-CTR has no
authentication tag, so this check is the integrity check. A `pair_u` that is no
X25519 point is reported in `bad_pair_hints` and the note stays.

A verified note in a mint the asset registry does not know becomes a
`PendingNote` in `pending_assets`. `DecryptionResult::resolve_pending` admits it
after the mint is registered, without a rescan, and reports whether its
nullifier was already spent.

`RingRecovery` is the scan that needs no tag. It pages the ring's confirmed
history from ring creation, or from a checkpoint, through a stated head slot. It
tries every scheme-9 slot under every held viewing key, with one key agreement
per transaction and key. It fails at its page limit, by default
`DEFAULT_RECOVERY_PAGE_LIMIT`, or on a page that ends without a stated
frontier. The report carries the checkpoint of the next recovery. Paging cannot detect a transaction the indexer omits, so
the scan is as complete as the indexer. Its cost grows with ring history.

The fast path covers the current viewing key only. After a key rotation, notes
sent to an earlier key come back through `RingRecovery`.

## Auditor disclosure

The auditor message seals the transaction viewing secret to the auditor and
carries the masked disclosure fields. In an anonymous ring the disclosure names
the sender identity, every disclosed input opening and, per output, the
recipient identity, nullifier key and viewing key. A padding slot discloses
zeros. A known disclosure field reveals no other field, because each field has
its own pad from a secret seed.

The auditor reads the amount, mint and blinding of a real output from its
scheme-9 body. It runs the key agreement between the recovered transaction
secret and the disclosed viewing key, opens the body and checks the commitment.
`TransactionAudit::run_with_mode` reports a slot that fails as a
`payload_errors` entry. Nothing a sender controls outside the proof changes
what the auditor reads from a real scheme-9 slot.

## The anonymous SPP rail

An anonymous ring accepts only the `AnonymousRingEddsa` rail in its supported
shapes. The hidden owner signs the 84-byte ring spend message. It holds the
`"zolana ring spend v1"` prefix, the ring program id and the SHA-256 digest of
`private_tx_hash || external_data_hash`. The circuit verifies that signature.
The prefix keeps the signature from serving another message. The ring id keeps
it from spending in another ring. `AnonymousSpendSigner` lets a key that lives
elsewhere, such as a hardware wallet, produce it.

SPP derives three public parties and the circuit proves each one distinct from
the hidden owner:

1. The fee payer.
2. The ring's configured co-signer, appended by the ring program, zero without
   one.
3. The destination of the withdrawals, zero without one. Every withdrawal of
   the transaction must go to one account.

The ring program refuses any signer other than the payer among the SPP
accounts. The SDK refuses a payer or co-signer equal to the owner before it
proves.

## Exits and deposits

An exit is an output to the default ring. It uses the confidential scheme 3,
publishes its owner's Solana key as the tag and chains a zero body hash. The
delivery proof does not cover its body. The circuit refuses an exit to the
hidden owner while the transaction spends a ring note of that owner. A
withdrawal publishes its amount, its mint and its destination.

An anonymous `RingDeposit` credits a keypair the depositor holds and tags it on
that keypair's deposit stream. The deposit amount and mint are public. The
deposit proof discloses the owner key to the auditor. The payer and the
co-signer must differ from the owner, and the ring data hash must be zero.

## Policies and membership

A policy ring in anonymous mode proves its list and asset rules over the
private openings of the hidden sender and the recipients. The policy statement
publishes the policy hash, the registry roots, the ring context and the
`approval_required` bit, never a member. An absent record fails only a rule
that requires list membership. A recipient needs no enrollment beyond holding
an address.

An outflow cap is per asset and per transaction. A limited transfer has one
sender. Its outflow is the sum of its inputs in that asset minus the change
returned to the sender inside the ring. The proof requires the outflow at most
`cap`. An outflow above `cosign_above` sets the public `approval_required` bit,
and the ring program then demands the configured co-signer. A zero `cap` or
zero `cosign_above` turns that bound off. The ring keeps no counter across
transactions. Key registration and the permanent delegate are
refused in anonymous mode, so key escrow stays off. See
[`docs/ring-policy.md`](../../docs/ring-policy.md) for the rule grammar.

## Integration

A payer parses a `RingPaymentRequest` and passes its address to
`with_recipient` as `AnonymousRecipient::Address` for a first payment.
`AnonymousRecipient::Paired` uses the pair stream and still carries the full
address. `with_anonymous_signer` takes the hidden owner's signer and viewing
key. `with_session` shares one `TransactSession` across the wallet's transfers.

A recipient learns the sender's pseudonym from a first payment. It finds a
paired payment on the fast path only after one first payment from that sender.
Pay a new recipient on its inbox stream first. Otherwise only `RingRecovery`
finds the payment.

The TypeScript SDK carries the same address, tag allocation, stream sync and
recovery scan, the last as `recoverAnonymousRing`. Rust, Go and TypeScript
share the `test-vectors/` files for the body key, the disclosure and the spend
message. Rust and TypeScript share the address vector.

## Limits

- Owners are Ed25519 keys. The SDK refuses an output owner of another key type.
- Anonymous outputs carry no data records, memo, data hash or ring data hash.
- Caches and compact padding are refused on the anonymous rail.
- Supported shapes are `ANONYMOUS_RING_SHAPES` in the custom-ring interface crate.
- Fast-path cost grows with issued addresses, known counterparties and owned
  spends. Recovery cost grows with ring history.
