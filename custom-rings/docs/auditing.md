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

A **packed** disclosure serves the confidential and delegate rails at 2 and 4
outputs. Per published output it carries the owner key, the nullifier key,
the asset, the amount and the two data hashes. The auditor derives every
ring output blinding from `tx_viewing_sk`, so no blinding is published.

A **delivered** disclosure serves the confidential and delegate rails at 8 and
16 outputs. Per output it carries the owner key and the nullifier key. The
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
default-ring note of the hidden owner. The ring never audited that note, so
the disclosure opens every spent note fully. It carries the hidden owner's key
and the nullifier key that every spent note shares, and each note's amount,
asset and blinding.

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
record, because a merge moves no value between parties.

## Reading a ring

The ring RPC holds the auditor key and serves signed reads. A reader is a
Solana key or a passkey with a read access record the config authority
granted. The reader signs each request with a timestamp and a nonce. The
service refuses a timestamp more than 60 seconds off its clock and a nonce it
has seen. The config authority has no implicit read access.

`getDecryptedTransactions` pages the opened transfers, and `getAuditedMerges`
pages the opened merges. `getAuditedNotes` returns the opening of each requested
UTXO hash the service has audited. Its openings resolve the inputs an anonymous
transfer names by UTXO hash. `ringStatus` is an unsigned read. It reports the
ring's activation, the registry's root history, floors and queue, and whether
the service holds the ring's auditor key.

An auditor that holds its own key reads the ring with `zolana-ring-client`.
`RingScan` opens transfers, `MergeAudit` opens merges, and `RingRecovery`
rebuilds one member's notes for a delegate move. In TypeScript `auditRing`,
`auditRingMerges` and `recoverRingMemberNotes` do the same. Each one checks
every opening against the confirmed SPP instruction and its settled hashes.
A scan sees only the transactions the indexer returns, so it trusts the
indexer for completeness.

## Limits

The packed layout at 2 and 4 outputs does not prove recipient delivery. A
sender on those shapes can send an output its recipient cannot decrypt, while
the auditor still reads it.

The auditor holds no spending key. A delegate, a separate key, moves notes.
See [the delegate rail](../README.md#rings-and-rails).
