# Anonymous rings

An anonymous ring is a custom ring whose config holds `RingMode::Anonymous`. A
transfer inside it hides the sender, the recipients, the amounts and the assets
from a chain observer. Each output that stays in the ring carries a
**scheme-9** body, its note encrypted to the recipient. The ring auditor reads
every transfer, and the proofs bind what the auditor reads to the settled
notes.

The protocol spec sections [Ring Address](../../docs/spec.md#ring-address),
[View Tags](../../docs/spec.md#view-tags),
[Ring Anonymous outputs](../../docs/spec.md#ring-anonymous-outputs),
[Anonymous disclosure](../../docs/spec.md#anonymous-disclosure) and
[Anonymous outputs](../../docs/spec.md#anonymous-outputs) hold every byte
layout and derivation this guide names.

## Roles

A **member** holds a shielded keypair, its signing key, nullifier key and
viewing key. It is the **sender** when it spends and the **recipient** when it
holds the secrets behind an address. The **hidden owner** is the sender of an
anonymous spend. Its Ed25519 key signs inside the proof and never signs the
Solana transaction. A recipient learns the mint, the amount and the blinding of
each note it receives. It also learns the sender's pseudonym `pair_pk`, and
nothing else of the sender beyond what a chain observer sees.

The **auditor** holds the X25519 secret key whose public key the ring config
stores. It opens every transfer, deposit and merge of the ring. It reads the
hidden owner, every spent note and every recipient address. It learns
nullifier public keys, never a nullifier secret, and auditor access does not
authorize a spend. No instruction changes the auditor key after the config is
created.

The program's upgrade authority creates the config and the policy, replaces
the rule table and signs `set_delegate`. The **ring authority** signs every
other administrative change, among them the co-signer, the pause state, the
policy source, read access and the authority lists. The upgrade authority is
the first ring authority, until `set_authority` moves that role to another
key. Neither authority holds a key that opens a transfer. The ring authority
still decides, through `grant_read_access`, whom the Ring RPC serves. The Ring
RPC holds the auditor key and serves opened transfers to each granted reader.

The **co-signer** is the address the ring's co-signer account names, when the
ring has one. It signs every transfer or deposit its scope covers, a merge
counting as a transfer, and every transfer whose proof sets
`approval_required`. A covered withdrawal needs it only above its mint's
threshold or in a mint without one.

The **fee payer** is the SPP payer account and signs the transaction. The
proof shows the payer and the co-signer distinct from the hidden owner.
Nothing checks a Solana fee payer outside the SPP accounts. A wallet must pay
the fees from the SPP payer, or a separate fee payer with the hidden owner's
key names the owner.

The **indexer** (Photon) serves outputs by exact tag and the ring's full
history. It sees which tags a wallet asks for. A wallet trusts it to return
every transaction.

A **chain observer** sees the ring, the shape, the fee payer, the co-signer,
the Solana slot, every tag and every public deposit and withdrawal. Nothing it
sees names the recipient of a scheme-9 output. The hidden owner shows when a
transfer spends its default-ring notes or pays fees with its key.

## Creating an anonymous ring

The anonymous mode is fixed when the ring's config is created. With the CLI,
set `mode = "anonymous"` at the top of `ring.toml`, or pick it in
`zolana-ring new`, before the first `init` or `pipeline`. The accepted values
are `confidential`, the default, and `anonymous`. `init` then creates the
config with `CustomRing::create_anonymous_config`. A later `init` against a
deployed config of the other mode fails. On chain only `set_delegate` changes
a ring's mode, and it refuses an anonymous ring.

## Addresses and payment requests

A `RingAddress` is a shielded address, the ring program id and one inbox
secret. `ViewingKey::inbox_secret(i)` derives the inbox secret of address
index `i`. A wallet issues indices in order from `0`. It records each index
with `AnonymousRingState::issue` and stores the state before a payer receives
the address. The fast path reads only `ADDRESS_GAP` addresses past the highest
recorded or used one. Every scan opens the inbox stream of each issued address,
so `issue` refuses an index at or above `MAX_ISSUED_ADDRESSES` and
`AnonymousRingState::restore` refuses a stored count above it, both with
`TooManyIssuedAddresses`.
Two addresses of one wallet carry the same three public keys, so
anyone who compares them sees one recipient. Separate inbox secrets only stop
one payer from deriving the inbox tags of another payer's address. A wallet
therefore gives each payer its own index.

The inbox secret is a capability. Its holder derives the tags of first
payments to that address. A wallet shares an address only with payers and
never publishes it.

The text form is a `RingPaymentRequest`, `zolana:` followed by the base58
address and an optional query of `amount`, `mint` and `label`. The address
carries a checksum, and the parser rejects an unknown or a repeated query key.
The checksum does not cover the query, so a payer treats it as a suggestion.

`zolana-ring address` issues the keypair's next index, records it under
`keys/anonymous-ring/` and then prints the payment request for the ring of the
CLI workspace. It prints the index to stderr. `--index` prints an issued
address again or issues one of the `ADDRESS_GAP` indices past the issued ones.
A farther index needs `--beyond-gap`, and a state file above
`MAX_ISSUED_ADDRESSES` fails to load. Without `--keypair` it uses the CLI's
sender keypair and creates one when the file is missing. It does not read the
ring's mode, so it also prints a request for a confidential ring.

## Tags

Each scheme-9 output publishes a 32-byte view tag as its owner tag. A wallet
finds its outputs by asking the indexer for exact tags it derived. Outside a
recovery scan it opens only outputs under those tags. Inbox, pair and deposit
tags are index `n` of one stream, and a spend derives one change tag per
output slot:

- The **inbox stream** of an address carries first payments to that address.
  Its tags derive from the address's inbox secret.
- The **pair stream** of a sender and a recipient carries later payments. The
  sender's key on it is `pair_pk`, a pseudonym unique to that recipient.
- The **deposit stream** of a keypair carries anonymous ring deposits to it.
- The **change tag** derives from `sender_view_tag_secret`, the transaction's
  first nullifier and the output slot index. It tags builder-generated
  change.

A slot is **real** when it holds a note of the ring. An **exit** holds a note
of the default ring. A **padding** slot holds no note. Its tag is `0x00` and
31 random bytes, drawn again until it differs from every other tag of the
transaction.

### Allocation

The builder fixes the slot order before it derives a tag. For each stream it
reads one window of `DEFAULT_TAG_WINDOW` indices from the indexer. Each slot
then takes the lowest index that has no output under its tag and that no
earlier slot of the same transaction reserved. An exhausted window moves the
stream to the next window. An output nobody can decrypt still occupies its
index.

Each payment output is bound to the address it pays. In Rust `with_payment`
takes an `AnonymousPayment`, builds the output from the address and records
its slot. In TypeScript `AnonymousPreparedTransfer.prepare` takes the payments
and records their slots the same way. Two addresses of one wallet share a
shielded address and differ in the inbox secret. The builder therefore tags
each slot from the payment recorded for it, never from the output's owner. A
payment to an address of another ring fails with `ForeignRing` in Rust and
`RING_FOREIGN_RING` in TypeScript.

An explicit payment assignment takes precedence over the change tag. A payment
to the sender's own address takes the address's stream. So does a payment to
an address with the sender's signing and nullifier keys and another viewing
key. The change tag applies only to builder-generated change, a real output
with no payment assignment whose owner is the sender's address. An output the
caller adds to the sender's address without a payment counts as change too.
Any other real output without a payment assignment fails with
`UnknownAnonymousRecipient` in Rust and `RING_ANONYMOUS_RECIPIENT_UNKNOWN` in
TypeScript. In Rust a payment assigned to a slot that holds no ring output
fails with `AnonymousPaymentSlot`.

### Concurrent senders

Two senders can take the same free index before either transaction confirms.
The two outputs then share a tag, and an observer sees that link. A wallet
opens every output under a tag, so neither payment is lost. Inside one
transaction the builder and the ring program refuse a repeated scheme-9 tag.

## Proven delivery

Every output slot except an exit carries a 105-byte body, the scheme byte `9`
and 104 ciphertext bytes. A real body encrypts a 104-byte opening of the
note's mint address, its big-endian amount, its canonical blinding and the
sender's `pair_u`. `pair_u` is the `u` coordinate of `pair_pk` toward the
recipient. The sender's own output carries the pseudonym toward its own
viewing key.

The body key derives through Poseidon under the domain `CR_R`. One input is
the X25519 agreement of the transaction viewing key with the recipient viewing
key. The others are the two public keys, the salt and the slot index. The key
and nonce step and the label `"CRING/adt1"` are shared with the auditor
envelope, whose secret has its own domain `CR_S` and inputs.
`test-vectors/anonymous_recipient_encryption.json` pins the schedule and the
layout.

For every real slot the base and policy circuits prove that the body encrypts
the committed note to the address the auditor disclosure names:

- The note's asset is the hash of the opening's mint address.
- The amount is range-checked to 64 bits.
- The blinding is encrypted in its canonical encoding.
- The note's data hash and ring data hash are zero.
- The note commits the transaction's ring. The SPP proof binds a nonzero
  output ring to the public ring.
- The note's owner hash is the owner hash of the disclosed signing key and
  nullifier key. The key schedule runs on the disclosed viewing key.

The ring program hashes each 105-byte body into the statement, so a proof
covers those exact bytes. The holder of the three secrets behind the address
opens the body, recomputes the on-chain commitment and spends the note under
the ring's policy.

The proof does not show that the sender chose the address it intended. It
does not show that anyone holds the keys of an address. It bounds the bytes of
`pair_u` and does not show that they name a point or derive from the sender's
keys.

The proof shows that the transaction secret is clamped and equals the secret
of the published `tx_viewing_pk`. It does not show that the secret derives from
the first nullifier or that the salt is fresh. Key freshness therefore rests on
an honest builder. Both SDKs derive the secret from the first nullifier. A
shared Rust `TransactSession` keeps the salt for a retry of the same outputs.
It refuses a different output set under that key with `AnonymousStreamReuse`.
The TypeScript SDK draws a fresh salt on every encryption. Two openings under
one transaction key, salt, slot and recipient key leak their XOR.

## Uniform slot encoding

Every scheme-9 slot, real or padding, has the same public form. The ring
program enforces these rules on every anonymous transfer:

1. The transaction carries the full output count of its circuit, so compact
   output padding is refused.
2. Every slot carries data.
3. A scheme-9 slot's data is exactly the encrypted frame of one 105-byte body.
4. A scheme-9 tag is inline, starts with `0x00` and is not zero.
5. No two scheme-9 slots of the transaction share a tag.
6. No slot publishes a zero output hash.
7. Every other slot carries a scheme-3 body with a nonzero inline tag, a
   canonical X25519 recipient key and a ciphertext. The proof shows that such
   a slot is an exit.

The program does not check that a tag derives from a stream or that no earlier
transaction used it. It does not check that a body is an encryption. The proof
covers real slots. A padding body is the scheme byte and 104 fresh random
bytes.

For an honest builder, these rules remove every per-slot marker that tells a
real output from padding. Every SPP rail puts padding after every other slot,
so no slot before an exit is padding. A sender who wants to signal
can still do so through the bytes it controls, a padding body or a tag choice.
An exit publishes its owner and is outside the claim. Tags shared across
transactions and other public metadata still inform guesses.

## The anonymous SPP rail

An anonymous ring accepts a member transfer only on the `AnonymousRingEddsa`
rail, uncached, at a shape in `ANONYMOUS_RING_SHAPES`. The delegate rail
refuses an anonymous ring. The hidden owner signs the 84-byte
[ring spend message](../../docs/spec.md#ring-spend-message). The message holds
the prefix `"zolana ring spend v1"`, the ring program id and the SHA-256
digest of `private_tx_hash` and `external_data_hash`. The circuit verifies
that signature and binds the ring program id to the public ring. The prefix
keeps the signature from serving another message, and the ring id keeps it
from spending in another ring. `test-vectors/ring_spend_message.json` pins the
message.

Three parties are public, and the circuit proves each one distinct from the
hidden owner:

1. The SPP payer account.
2. The ring's configured co-signer, or the zero address when the ring has
   none. The ring program appends it to the SPP instruction data.
3. The key every withdrawal names, or zero when the transaction has none. A
   SOL withdrawal names its recipient, and SPP refuses a recipient other than
   a system account without data. An SPL withdrawal names the owner of its
   token account, and SPP refuses a token account with a delegate or a close
   authority, or one at an address on the ed25519 curve. An associated token
   account and every PDA are off the curve. SPP refuses withdrawals that name
   two different keys.

A transfer can spend the hidden owner's default-ring notes in place of ring
notes. It then publishes the owner's key as its default owner tag, and the
proof refuses to mix the two kinds of notes in one transfer.

The ring program refuses any signer other than the payer among the SPP
accounts. The SDKs refuse a payer or a supplied co-signer equal to the hidden
owner before they prove, with `AnonymousPublicSignerLinksOwner` in Rust and
`RING_ANONYMOUS_SIGNER_LINKS_OWNER` in TypeScript. They also read every
withdrawal destination before they prove. They refuse a destination SPP would
refuse, and one whose address or token account owner is the hidden owner or
that is the hidden owner's associated token account, with
`AnonymousExitLinksOwner` in Rust and `RING_ANONYMOUS_EXIT_LINKS_OWNER` in
TypeScript.

`AnonymousSpendSigner` produces the signature, so the hidden owner's Ed25519
key can live outside the process that builds the proof. In Rust `SigningKey`
and `ed25519_dalek::SigningKey` implement it, and a hardware or remote signer
implements it itself. In TypeScript `signingKeySpendSigner` wraps an
in-process `SigningKey` and `messageSignerSpendSigner` wraps a wallet adapter's
message signer.

## Exits and deposits

An exit is an output to the default ring. It uses the confidential scheme 3
and publishes its owner's Solana key as its tag. Its body enters the statement
as a zero hash, so the delivery proof does not cover it. The
[auditor disclosure](#auditor-disclosure) carries the exit's opening instead.
The circuit refuses an exit to the hidden owner while the transaction spends a
ring note of that owner. A withdrawal publishes its amount, its mint and its
destination account.

The Rust `RingDeposit` takes the recipient's keypair, because the
deposit-stream tag needs its viewing secret. It tags the note at the first
free index of the recipient's deposit stream. No check on chain ties the
credited key to the depositor. The ring program refuses a plain deposit in
every mode, so every deposit carries an auditor disclosure proof. In an
anonymous ring that proof binds the disclosed owner key to the note's owner.
The deposit amount and mint are public, and the ring data hash must be zero.
The Rust SDK refuses a payer or a co-signer equal to the credited owner.

## Wallet sync

### Fast path

`UtxoScan::with_anonymous_ring` reads the anonymous streams of the current
viewing key next to the default-ring scan. It takes an `AnonymousRingState`,
which holds the count of issued addresses and the known counterparties. The
wallet keeps that state between scans. Tags derive through `ShieldedKeys`, so
a wallet whose keys live in a remote key holder syncs the same way.
`zolana-ring merge`, `transact` and `transfer` read the sender's notes through
the fast path. Each scan stores the addresses and counterparties it finds in
the state under `keys/anonymous-ring/`.

1. The scan opens the deposit stream, the inbox stream of every issued address
   plus `ADDRESS_GAP` more below `MAX_ISSUED_ADDRESSES`, and the pair stream of
   every known counterparty.
2. Each round reads one `DEFAULT_TAG_WINDOW` window per open stream. A window
   with no occupied index closes its stream.
3. A note on the inbox stream of address `i` raises the used count to `i + 1`
   and keeps `ADDRESS_GAP` unused addresses open past it. Its `pair_u` adds a
   counterparty and opens that pair stream.
4. For every transaction that spends an owned note and carries a scheme-9
   slot, the scan opens each output slot under its derived change tag.
5. The scan opens at most `DECRYPTIONS_PER_INDEX` outputs under one tag. A tag
   past that cap marks its ring. Once the streams close, the scan runs a
   recovery scan of that ring and opens what the cap left.

The Rust recovery opens capped hits through the slot the indexer config
requires, else through the highest slot the scan read. Later hits wait for the
next scan. In Rust a note that the recovery opens raises no used count and
adds no counterparty. The TypeScript `syncWallet` opens every hit under a
capped tag at once and reports a capped inbox address in
`addressesUnderAttack`.

A wallet accepts an output only when the recomputed commitment equals the
published `utxo_hash`. The commitment covers the wallet's own keys, the mint
address, the amount, the blinding, zero data hashes, the public ring and the
tree id. AES-CTR has no authentication tag, so the commitment check is the
integrity check.

The scan keeps a note whose `pair_u` is not a canonical contributory X25519
key, a low-order key included. It reports the note in `bad_pair_hints` and
opens no pair stream for it. A scheme-9 slot under a derived tag can lack its
transaction key or salt, or carry other than 104 ciphertext bytes after the
scheme byte. The ring program refuses such a slot. The scan reports it in
`malformed_slots` and continues. The `AnonymousRingReport` also carries
`used_addresses`, `new_counterparties` and, per stream, the index after the
highest occupied one.

### Unknown assets

A verified note in a mint the asset registry does not know becomes a
`PendingNote` in `pending_assets`, its commitment already checked.
`DecryptionResult::resolve_pending` admits every pending note whose mint is now
registered, without a rescan, and reports whether its nullifier was already
spent. A failed resolution leaves every note pending. `UtxoScan` keeps no
`DecryptionResult`, so a wallet on it registers the mint and scans again.

The TypeScript `syncWallet` resolves pending notes during every sync, and
`resolvePendingNotes` resolves them on demand with the spent state of each.
Wallet snapshots of version 5 keep the pending notes.

### Recovery scan

`zolana_client::RingRecovery` needs no tag. It pages the ring's confirmed
history from ring creation, or from a checkpoint, through a head slot the
caller states. It tries every scheme-9 slot under every held viewing key, with
one key agreement per transaction and key. It also decodes the ordinary
outputs of that history, so the output of a merge that spent a recovered note
opens. The report carries the checkpoint of the next recovery.

The scan fails closed and returns no partial result in each of these cases:

- It reaches its page limit, `DEFAULT_RECOVERY_PAGE_LIMIT` unless
  `with_page_limit` sets another.
- The last page states no frontier.
- The indexer reports a slot below the head.
- The indexer does not reach the slot that `with_indexer_config` requires.
- A page returns a transaction of another ring.
- A scheme-9 slot of the history is malformed.
- A cursor does not advance.

The TypeScript `recoverAnonymousRing` reads from ring creation through a
stated head and takes no checkpoint. Its page limit is the `maxPages` option,
and pages past the head count toward it. It also fails on a page without a
frontier, an indexer behind the head and a row of another ring. A malformed
slot and a cursor that does not advance fail it too. On an empty index Photon
reports the stream origin as the frontier, so a recovery of a ring without
history completes.

Paging cannot detect a transaction the indexer omits, so the scan is as
complete as the indexer. The fast path covers the current viewing key only.
After a key rotation, notes sent to an earlier key come back through the
recovery scan.

## Auditor disclosure

Each transfer appends one auditor message, tagged by the auditor's X25519 `u`
coordinate. It seals the transaction viewing secret to the auditor and carries
the masked disclosure fields. In an anonymous ring each region is zero padded
to whole 31-byte chunks, one field per chunk:

- The hidden owner's tagged Ed25519 key fills two fields.
- Each input slot packs its tree id, amount, asset and blinding into three
  fields.
- Each output slot fills five fields with a kind byte, the tagged identity and
  the nullifier public key. A ring output adds its viewing key, an exit adds its
  amount, asset and blinding.

An input dummy and a padding output disclose zeros. Each field `j` has its own
pad `Poseidon(seed, j)`. The seed derives from the transaction secret and the
salt and is never published, so a known field reveals no other field.
`test-vectors/audit-disclosure-anonymous.json` pins the layout.

A ring output's slot names only the address. The auditor reads the mint,
amount and blinding of a ring output from its scheme-9 body. It runs the key
agreement between the recovered transaction secret and the disclosed viewing
key, opens the body and checks the recomputed commitment.
`TransactionAudit::run_with_mode` reports a slot that fails in
`payload_errors`. A bad pair hint, low-order keys included, is a pair-hint
payload error in both auditors. Nothing a sender controls outside the proof
changes what the auditor reads from a real scheme-9 slot.

An exit has no proven body. The circuit requires its data hash and ring data
hash to be zero, and its ring program id is zero. Its slot carries the owner,
amount, asset and blinding, so both auditors rebuild its `utxo_hash` from the
slot and the published tree id. A slot that does not match fails the audit of
its transaction, with `OutputCommitmentMismatch` in Rust and
`RING_AUDIT_OUTPUT_MISMATCH` in TypeScript. The scheme-3 body only supplies
delivery metadata. A body that disagrees with the opening is a payload error,
and the opening stays.

Every audit scan fails closed on a page that names neither a next cursor nor a
frontier, in Rust and in TypeScript.

## Anonymous merges

A merge consolidates notes of one owner, asset and ring into one output
without an owner signature. A ring merge in another mode proves that the
owner's member record escrows the nullifier key to the auditor. The auditor
opens the merged note with that key. An anonymous ring refuses key
registration, so no record escrows a key and that path does not apply.

Instead the ring program sets the `anonymous` flag of SPP `merge_ring` from its
own mode. The flag enters the merge proof's public input, and the proof skips
the escrow relation under it. SPP does not read the ring's mode and trusts the
signing ring program for the flag. A ring program that sets the flag must
prove its own disclosure. The ring program refuses an anonymous merge request
without a disclosure and an ordinary merge request with one.

The ring merge disclosure is a separate proof the ring program verifies before
its SPP call. From one owner key, one asset and the owner's nullifier secret,
it recomputes `private_tx_hash`, the output commitment and the first
nullifier. The statement therefore names one exact SPP merge. It proves the
owner's member record present under the registry root the ring program
selected. A present record suffices, so a frozen member still consolidates its
own notes.

The disclosure encrypts the merged note to the ring auditor. It carries the
owner key, the nullifier public key, the mint, the merged amount, the output
blinding and every input commitment. Its pad uses its own domain and the SPP
output ciphertext salt. `test-vectors/ring-merge-anonymous.json` pins the
statement.

`MergeAudit` opens an anonymous merge from that disclosure and checks the
recomputed output commitment. Its `MergeKeys::Disclosed` carries the input
commitments, and the nullifier key stays hidden from the auditor.

The disclosure covers the merge widths in `ANONYMOUS_MERGE_WIDTHS`, 8 and 24.
A width-52 merge with its disclosure and nullifier accounts does not fit one
transaction. The Rust SDK refuses it with `AnonymousMergeTooWide`. The
TypeScript SDK refuses more than 24 inputs with `RING_BUILD_MERGE`, cause
`RING_ANONYMOUS_MERGE_TOO_WIDE`.

The TypeScript `buildRingMergeTransaction` requires a `nullifierKey` in an
anonymous ring. Without one it fails with `RING_BUILD_MERGE`, cause
`RING_ANONYMOUS_NULLIFIER_KEY_REQUIRED`. The disclosure proof takes the
nullifier secret as a private input, and `ShieldedKeys` exposes no nullifier
secret. A wallet whose nullifier secret stays in a remote key holder cannot
build an anonymous merge.

`merge_ring` indexes the output by the first input's published nullifier. A
wallet finds the merge through the nullifiers of the notes it holds. It
derives the output key from its nullifier key and the merge's first nullifier.
[Limits](#limits) names what the build lacks to settle these merges.

## Policies and membership

A policy ring in anonymous mode runs the same rule table as in the other
modes. List rules read the member records of the hidden owner and of the
output owners, exits included. Asset rules read the output assets. Both read
private openings. The policy statement publishes the policy hash, the
registry roots, the tree and ring context and the `approval_required` bit. A
shaped key also publishes the rule table. The statement never names a
member.

An absent record opens with no list bits. It fails a rule that requires
presence on a list and passes a rule that requires absence. A recipient
therefore needs no record unless a rule requires one. A merge needs the
owner's record present. A member gets a record through `update_members` as in
every mode. An authority list needs the authority's signature and a member
list the member's.

An outflow limit bounds one transfer in one asset. A limited transfer has one
sender. Its outflow is the sum of its inputs in that asset minus the change it
returns to the sender inside the ring. The proof requires an outflow of at most
`cap`. An outflow above `cosign_above` sets the public `approval_required`
bit, and the ring program then demands the configured co-signer. A zero `cap`
or a zero `cosign_above` turns that bound off, and the rule decoder refuses a
limit with both zero. [`docs/ring-policy.md`](../../docs/ring-policy.md) holds
the rule grammar.

## Integration

### Rust wallet

1. Keep an `AnonymousRingState` with the keys and persist it after every scan.
   It decides which inbox and pair streams the next scan opens.
2. To receive, take the next index `i`, record it with
   `AnonymousRingState::issue(i)` and persist the state. Then build a
   `RingAddress` from the shielded address, the ring program id and
   `inbox_secret(i)`, and hand the payer the `RingPaymentRequest` text. The
   recorded count keeps the scan reading that address.
3. To sync, run `UtxoScan::new(&keys, &assets)` with
   `with_anonymous_ring(state)`. Add
   `with_ring_deposit_payload(ring, zolana_ring_client::deposit_payload)` to
   read the ring's deposits and `with_indexer_config` to wait for a recent
   slot. Pass the result's `anonymous` report to `AnonymousRingState::absorb`.
4. To pay, wrap a `ConfidentialTransaction::new_with_ring` in a
   `CustomRingTransfer` and call `with_anonymous_signer` with the hidden
   owner's signer and viewing key. Add one `with_payment` per recipient,
   optionally pad with `with_shape`, share one `TransactSession` across
   transfers with `with_session`, then prove and submit.
5. Use `AnonymousRecipient::Address` for a recipient the wallet never paid. A
   `Paired` payment before any inbox payment from the paying wallet reaches the
   recipient only through the recovery scan.
6. After a restore or a key rotation, run `zolana_client::RingRecovery` per
   ring and store the checkpoint it returns. The next recovery resumes there.

### TypeScript wallet

1. Store an `AnonymousRingState` beside the wallet snapshot, because the
   snapshot does not hold it. Pass it as `anonymousRing` to `syncWallet`, with
   keys that implement `RingTagKeys`. Raise its `issuedAddresses` to
   `usedAddresses` and add `newCounterparties` to its `knownCounterparties`,
   both from `report.anonymousRing`.
2. Issue addresses with `viewingKey.inboxSecret(i)`, a `RingAddress` and a
   `RingPaymentRequest`. A payer reads one with `RingPaymentRequest.parse`.
   Raise `issuedAddresses` to at least `i + 1` and store the state before the
   payer receives the address.
3. To pay, prepare the transfer and its payments with
   `AnonymousPreparedTransfer.prepare`, then prove with
   `proveAnonymousRingTransfer` or `buildAnonymousRingTransferTransaction`.
   Pass a spend signer from `signingKeySpendSigner` or
   `messageSignerSpendSigner`.
4. Persist the wallet through its snapshot. Call `resolvePendingNotes` after
   registering a mint.
5. Run `recoverAnonymousRing` after a restore or a key rotation.

### Auditor service

1. Hold the auditor X25519 keypair whose public key the ring config stores, or
   run the Ring RPC with it.
2. Scan with `RingScan::new(ring_program_id, auditor_pubkey)` and
   `with_mode(RingMode::Anonymous)`, then `audit`. `audit` binds each match to
   its transaction through a `TransactionOrigin`. With the `solana-rpc`
   feature the Solana RPC clients implement it. Resume from the returned
   cursor with `with_cursor`.
3. Treat each `payload_errors` entry as a finding on that slot. Treat a scan
   error as incomplete coverage and retry, never as an empty page.
4. Open merges with `MergeAudit`. In TypeScript use `auditRing` and
   `auditRingTransaction` with the anonymous mode, and `auditRingMerges`.

Rust, Go and TypeScript share the vectors for the body key, the disclosure,
the spend message and the merge disclosure in `test-vectors/`. Rust and
TypeScript also share the address vector and the anonymous settlement.

## Limits

- Owners are Ed25519 keys. Both SDKs refuse an anonymous output owner of
  another key type, and the Rust SDK refuses such a deposit recipient.
- Anonymous outputs carry no data records, data hash or ring data hash.
- The anonymous rail refuses caches and compact padding. The ring program
  refuses a cached spend and a short output count, and both SDKs refuse a
  cached or compact slot.
- `ANONYMOUS_RING_SHAPES` holds fourteen shapes, 1 through 6 inputs with 2 or
  4 outputs, 8×2 and 12×2. The size gate in
  `custom-rings/sdk/tests/instruction_builders.rs` asserts that each fits a
  transaction with a lean and with a full account set. The full set adds a
  co-signer, an approval, a curator registry and a second policy tree. The
  gate also adds a SOL or an SPL withdrawal to each shape. Every shape keeps
  room for either withdrawal with the lean set, and every shape but 12×2 with
  the full set. The SDKs measure the actual transaction before they prove and
  refuse one past the limit, with `TransactionTooLarge` in Rust and
  `INTERFACE_TRANSACTION_TOO_LARGE` in TypeScript. TypeScript counts the
  withdrawal accounts only when they come in `transaction.withdrawal`.
- The build has no verifying keys for the anonymous merge circuits, and
  `proving-keys.lock` pins no proving key for them.
  `merge_anonymous_verifying_key` returns none for every width, so the ring
  program refuses every anonymous merge with `UnsupportedCircuit`.
- An outflow limit bounds each transfer alone, and the ring keeps no counter
  across transactions. A sender can move up to `cap` in every transfer.
- SPP cannot see the hidden key. It refuses an SPL token account at any
  keypair address, the hidden owner's included, but only the SDKs refuse the
  hidden owner's associated token account after a change of owner. No check
  sees a SOL recipient address derived from the hidden key, such as an
  unfunded associated token account.
- The TypeScript SDK builds no anonymous ring deposit.
  `buildRingDepositTransaction` refuses an anonymous ring with
  `RING_BUILD_DEPOSIT`, cause `RING_CONFIG_INVALID`.
- The TypeScript `auditRing` stops with `RING_AUDIT_OUTPUT_MISMATCH` at the
  first transfer whose scheme-9 body does not open. The Rust auditor reports
  that slot in `payload_errors`.
- Fast-path cost grows with issued addresses, known counterparties and owned
  spends. Recovery cost grows with ring history.
