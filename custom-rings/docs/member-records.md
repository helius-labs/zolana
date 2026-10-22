# Member records

A ring keeps its lists in member records, and a registered owner's record binds
its escrowed nullifier key. The records form the ring's member registry, a
4-ary indexed Merkle tree that belongs to the ring alone. The ring program
keeps the tree's recent roots on chain, and Photon stores the records. Members
queue their writes on chain, and an apply proof moves the tree to its next
root. The config authority's writes apply in their own instruction and raise
the registry's root floor, so a revocation applies to every later transfer. A
policy proof opens records under a root the registry holds and reveals no
record it opened. The records themselves are public. The account layouts, the
queue chain and the apply statement are in
[Member registry](../../docs/spec.md#member-registry), and the constants this
guide names are in
[Ring Program Interface](../../docs/spec.md#ring-program-interface).

## Members and lists

A **member** is an owner or an asset. See
[Member registry](../../docs/spec.md#member-registry) for its value. One list
holds both kinds, and an owner key and a mint with equal bytes stay distinct
members.

A record holds the member, the next member in sort order, a bitmap of lists
and an escrow key. Eight lists exist, and each list has one writer:

- The config authority writes `Allow`, `Block`, `Frozen`, `Reader` and
  `Approval`.
- The member itself writes `RingViewing` and `Recovery`.
- Only a key registration sets `Escrow`, and it also fills the escrow key.

[The policy guide](../../docs/ring-policy.md#rules) says which of these lists
a rule reads.

The tree starts with a sentinel record at leaf 0. Every member lies strictly
between the sentinel and the largest field element, so every absent member has
a present low record that brackets it. A proof of absence opens that low
record. An absent member reads as an empty bitmap and no escrow key.

## Writes

Every write is masked. It changes the list bits inside its mask to the bits of
its value and keeps every other bit. A write over an absent member inserts a
record at the next free leaf, unless the new record would be empty. A record
is never removed. A cleared record stays in the tree with an empty bitmap.

A member writes its own record with `WriteRecords`. The member's Solana key
signs, and the program derives the record from that key, so no member can
write another member's record. The mask names only `RingViewing` and
`Recovery`. The write enters the queue and changes no root.

A member escrows its nullifier key with `RegisterKey`. The proof shows that a
32-byte ciphertext seals the member's nullifier secret to the ring auditor, and
that the secret matches the published nullifier key. The program queues a write
that sets `Escrow` and the escrow key over the nullifier key and the ciphertext.
The escrow key fills once. A second registration for the same member applies as
a no-op on the key. Once the first registration applies, the SDKs refuse a
second one before proving. An anonymous ring refuses key registration. See
[Creating an anonymous ring](anonymous-rings.md#creating-an-anonymous-ring).

The config authority writes with `AuthorityWriteRecords`. One instruction
carries 1 to `APPLY_BATCH` writes over the authority lists and an apply proof.
The program appends the writes behind every pending write. The proof then
applies the whole queue in one step, so the authority's writes apply in the
same transaction.

## Applying the queue

`ApplyRecords` applies every pending write and needs no signer. Anyone may
send it once the queue is due. A queue is due when it holds
`MEMBER_QUEUE_LIMIT` writes, or when its oldest write waited
`APPLY_DELAY_SLOTS` slots. At least `APPLY_DELAY_SLOTS` slots separate two
permissionless applications. An authority write neither waits for nor moves
that window.

The proof binds the old root, the new root, the next free leaf before and
after, and the hash chain of exactly the pending writes. The program keeps the
chain of every queued write, so an application cannot drop, reorder or invent
a write.

## Queue and leaf limits

The tree holds `2^20` leaves, the sentinel included, so a registry holds at
most `2^20 - 1` member records. One application covers at most `APPLY_BATCH`
writes. The queue holds at most `MEMBER_QUEUE_LIMIT` pending writes, member
writes and key registrations alike, and one more fails with `QueueFull` until
an application runs. An authority write adds up to `APPLY_BATCH` writes less
the pending ones, so the authority can always write
`APPLY_BATCH - MEMBER_QUEUE_LIMIT` records in one instruction.

The last `AUTHORITY_RESERVED_LEAVES` leaves are the authority's reserve. A
member write or a key registration is refused with `AuthorityLeafReserve` once
it could enter that reserve. The program counts every pending write as a
possible insert, because only the application knows whether a member exists. No
leaf check applies to an authority write, so a registry whose member share is
full still accepts `Block` and `Frozen` writes over existing members.

## The insert fee

A member write or a key registration pays the ring's insert fee to the config
authority. It names the most it pays, and a higher fee refuses it with
`InsertFeeAboveMax`. Both SDKs name the fee they read from the config, so the
program refuses the write when the fee rises before it lands. A new config
starts at `DEFAULT_INSERT_FEE`. The config authority changes the fee with
`SetInsertFee`, which refuses a nonzero fee below the rent minimum of an empty
account. A paid write therefore lands even when the authority account holds no
lamports. A write that the config authority signs pays no fee and ignores its
maximum. With a fee of zero the write takes no payer, authority or system
account.

## Roots, floors and curators

The registry keeps the last `ROOT_HISTORY` roots. Each root records the queue
position it applied and its slot. A policy transfer names the history index of
each registry root its proof binds. A merge on a confidential ring and an
audited deposit under key escrow do the same.

Every authority write raises the registry's floor to the queue position it
applied. A transfer that binds a root of the ring's own registry below the
floor fails with `RootBelowFloor`. A revocation by the authority therefore
applies to every later transfer of the ring immediately. A member write raises
no floor.

A ring that reads a list from a curator's registry accepts a curator root at
or above the curator's floor. It also accepts a root at or above the curator's
previous floor for `GRACE_SLOTS` slots after the curator raised it. A root
outside both fails with `CuratorRootStale`. A curator's revocation therefore
applies to its subscribers within `GRACE_SLOTS`, and a transfer proven shortly
before a curator write still lands.

## Indexing

Photon reads the queued writes from the write instructions and replays every
application over its copy of the tree. It compares the resulting root and
next leaf with the instruction's values. A mismatch stops the ring's
projection, and Photon then refuses the ring's record reads. Clients check
every opening against a root the registry holds before they prove.

## With the CLI and the SDKs

`zolana-ring list add|clear <list> --owner <address>` or `--asset <mint>`
sends authority writes. Each batch carries its apply proof, and the first
batch takes the room the pending writes leave.
`list join|leave ring-viewing|recovery` sends the member write of
`keys/sender-keypair.json`, then applies the queue once it is due.
`list apply` sends the permissionless application, and `key register` escrows
the sender's key. `insert-fee set|show` writes and reads the fee, and `status`
prints the newest root, the floor and the queue.

In Rust, `MemberListWrite { ring, payer, member, lists }.instruction(&config)`
builds a member write. `AuthorityListWrite::new(ring, authority)` takes one
`with_write(member, write)` per record. `batches` splits the writes to fit
beside the pending ones, and `prove` proves one batch.
`RecordApplication::new(ring).prove(client)` returns `None` while the queue is
not due or the last permissionless application is under `APPLY_DELAY_SLOTS`
slots old. `RegisterKey` proves a key registration, and `MemberRecords` reads
openings it checks against the registry's root. The TypeScript ring module
exports `memberListWriteInstruction`, `AuthorityListWrite`,
`RecordApplication` and `RegisterKey` with the same roles.

## Pitfalls

An authority write proves over the current queue. A member write or a key
registration that lands between the proof and the authority's transaction
changes the queue, and the authority's proof fails. Rust's `RingSubmission`
proves the batch again over the new queue. A batch that does not fit beside
the new queue fails with `AuthorityBatchSplit`.

A transfer that binds an old root fails once `ROOT_HISTORY` later applications
replace it in the history. Both SDKs prove again when a bound root leaves the
history.
