# Auditing a ring

Every ring has one auditor, an X25519 key that the ring config fixes at
creation. The auditor reads every transfer, deposit and merge of the ring.
The audit proof binds what the auditor reads to the notes SPP settles, and the
ring program forwards no transfer without it. The disclosure layouts and the
audit statements are in [Audit disclosure](../../docs/spec.md#audit-disclosure)
and [Audit proof](../../docs/spec.md#audit-proof).

## The envelope

A ring transfer publishes one auditor message under the auditor's view tag, the
`u` coordinate of the auditor key. The message seals the transaction's viewing
secret `tx_viewing_sk` to the auditor under a fresh ephemeral key. The audit
proof shows that `tx_viewing_sk` is clamped and is the secret of the published
transaction viewing key. It also shows that the envelope seals `tx_viewing_sk`
to the configured auditor key. The auditor therefore recovers `tx_viewing_sk`
from every transfer.

The rest of the message is the disclosure, a run of field elements. Each field
is masked by a pad that only the holder of `tx_viewing_sk` computes. The pad
derives from `tx_viewing_sk`, the salt and the field index. A known field
reveals no other field. The ring program refuses a disclosure with a zero field.

## What the auditor reads

The rail, the output count and whether a spent note is a default-ring note
select one of four disclosure layouts. In each one the auditor rebuilds the
hash of every ring output and exit from what it reads. The proof shows that
the rebuilt hash is the settled one.

A **packed** disclosure serves the
[packed form](../../docs/spec.md#ring-outputs) of the confidential and
delegate rails. Per published output it carries the owner key, the nullifier
key, the asset, the amount and the two data hashes. The auditor derives every
ring output blinding from `tx_viewing_sk`, so no blinding is published.

A **delivered** disclosure serves the delivered form of the same rails. Per
output it carries the owner key and the nullifier key. The
auditor reads the asset and the amount of a ring output from its body. The proof
shows that the body encrypts them to the recipient key the output publishes. The
auditor opens the body with the X25519 agreement of `tx_viewing_sk` and that
key, as the recipient does with its own secret.

An **anonymous** disclosure serves the anonymous rail. Per ring output it adds
the key the body is sealed to. That key is an address key or the sender's ring
change key. The auditor again reads a ring output's asset and amount from its
body. The first spent note is disclosed as its UTXO hash and each later spent
note as the first 16 bytes of its hash. Every ring note is an output of an
operation the ring audited, so the auditor already holds the opening of each
spent note. The proof shows that the hidden owner owns every spent note. The
auditor takes the owner of the first note as the sender and finds each later
note among the sender's ring notes by its prefix. When more of those notes
carry a prefix than the transfer spends under it, the audit names them all as
candidates for each such input.

An **anonymous entry** disclosure serves an anonymous transfer that spends a
default-ring note of the hidden owner. The auditor does not always hold that
note's opening, so the disclosure opens every spent note fully. Every spent note
shares the sender's nullifier key. The disclosure carries the hidden owner's
key, that nullifier key and each note's amount, asset and blinding.

An exit to the default ring carries its owner in its public owner tag. Its
disclosure slot carries its asset and amount. Its blinding derives from the
output seed, the first disclosure field of a transfer with an exit.

A transfer whose outputs carry no data drops the data hashes from a packed
disclosure. The proof then shows that both data hashes of every output are
zero. A delivered or anonymous output never carries data.

## Escrowed nullifier keys

A ring under key escrow does not disclose the output nullifier keys in the
packed and delivered layouts. Its policy proof shows instead that each output
owner's member record escrows the nullifier key of that output. The auditor
reads the key from the owner's `RegisterKey` instruction, which carries the
nullifier key and its secret sealed to the auditor. With the secret the
auditor also computes the nullifier of every note the member owns.

See [the delegate rail](../README.md#rings-and-rails) for the start of key
escrow, and [member records](member-records.md) for key registration.

## Deposits

Every ring deposit is an audited deposit. Each deposited output carries a
capsule that encrypts its owner hash and blinding to the auditor, and on an
anonymous ring also its owner key. The proof binds the exact SPP deposit, the
destination tree and every capsule. The deposited mint and amount are public.
Under key escrow the proof also shows each deposited owner's escrow record.

## Merges

A merge consolidates notes of one owner, one asset and one ring into one
output, and SPP proves that value and owner stay unchanged. On a confidential
ring the merge proof opens the owner's member record and shows that it
escrows the nullifier key the inputs spend under. The output ciphertext is
keyed by that nullifier secret, and the merge names no owner. The auditor
opens each escrowed key of the registry and tries it on the output until one
opens it. An owner without a registered key cannot merge.

On an anonymous ring a separate disclosure proof encrypts the merged note to
the auditor. It covers the owner key, the nullifier key, the mint, the amount,
the output blinding and every input UTXO hash. That proof opens no member
record, because an anonymous ring escrows no key.

## Reading a ring

The ring RPC holds the auditor key and serves the
[readers](../README.md#roles). A reader is a Solana key or a passkey, and the
config authority has no implicit read access.
[Ring RPC](../../docs/spec.md#ring-rpc) states the methods and how a reader
signs a request.

An auditor that holds its own key reads the ring with `zolana-ring-client`.
`RingScan` opens transfers, `MergeAudit` opens merges, and `RingRecovery`
rebuilds one member's notes for a delegate move. In TypeScript `auditRing`,
`auditRingMerges` and `recoverRingMemberNotes` do the same. Each one checks its
openings and trusts the indexer for completeness, as
[Ring RPC](../../docs/spec.md#ring-rpc) states.

A scan needs an opening it already holds for each spent note that an anonymous
disclosure names by hash or prefix. An auditor with its own key therefore reads
the ring's deposit and merge notes first, with `CreatedUtxoScan` in Rust or
`scanCreatedRingUtxos` in TypeScript. It passes them, with the openings of
earlier pages, to `RingScan::with_known_utxos` or to the `knownUtxos` of
`auditRing`.

## Limits

The packed layout does not prove recipient delivery, and no layout proves an
exit's payload. A sender can send such an output its recipient cannot decrypt,
while the auditor still reads it.

The auditor holds no spending key. A delegate, a separate key, moves notes.
See [the delegate rail](../README.md#rings-and-rails).
