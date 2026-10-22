# Anonymous rings

An anonymous ring is a custom ring whose config holds `RingMode::Anonymous`. A
transfer of ring notes inside it hides the sender and the recipient, amount
and asset of each ring output from a chain observer. The ring auditor reads all
of them. Each ring
output carries a tag and an encrypted body. The audit proof shows that
each body encrypts the note's asset and amount to its recipient. It also shows
that each payment's tag derives from its recipient's inbox stream or from a
first contact to that recipient.

The byte layouts and derivations this guide names are in
[Ring Address](../../docs/spec.md#ring-address),
[Ring outputs](../../docs/spec.md#ring-outputs) and the
[Ring Program Interface](../../docs/spec.md#ring-program-interface).

## Roles

A **sender** spends ring notes, and a **recipient** holds the keys behind an
address. The **hidden owner** is the sender of an anonymous spend. Its Ed25519
key signs the spend inside the SPP proof.

A recipient learns the asset, the amount and the blinding of each note it
receives. A payment on a pair stream also tells the recipient that it comes
from the sender of an earlier first contact. Beyond what the chain shows, the
recipient learns no key of the sender.

The **auditor** opens every transfer. It reads the hidden owner's key, every
spent note, every recipient's owner key and address key, every amount and
every asset. See [What the auditor reads](auditing.md#what-the-auditor-reads).

The **payer** is the SPP payer account, and it signs the transaction. Among
the SPP accounts the ring program accepts no other signer. Nothing on chain
checks the transaction's Solana fee payer against the hidden owner. The
TypeScript builders make the SPP payer the Solana fee payer, and Rust's
`RingSubmission` refuses a fee payer that is the hidden owner.

The **indexer** serves outputs by exact tag, spends by nullifier and Merkle
paths by leaf. It sees which tags, nullifiers and leaves a wallet asks for, and
a wallet trusts it to return every match. A paged read fails when the indexer
repeats a cursor. A wallet that needs unlinkability runs its own indexer.

A **chain observer** sees the ring, the shape, the payer, the Solana fee payer
and the co-signer. It sees the Solana slot, every tag and every public deposit
and withdrawal. It also sees whether a transfer pays on a pair stream and which
state tree holds the first contact the pair stream anchors on. A transfer that
spends default-ring notes publishes the hidden owner's key. An exit publishes
its owner. No other output names its recipient to the observer.

## Creating an anonymous ring

Anonymity is fixed when the config is created. With the CLI, set
`mode = "anonymous"` in `ring.toml`, or select it in `zolana-ring new`, before
the first `init`. An anonymous ring can be a policy ring or audit-only. It
refuses key registration and so key escrow, because its auditor already holds
every opening. It refuses a delegate, because a delegate signs for an owner
the ring hides.

## Addresses

A **ring address** names one recipient inside one ring. Its viewing key is the
wallet's **address key** for that ring and index. See
[Ring Address](../../docs/spec.md#ring-address). Anyone who holds the address
derives its inbox tags, so a wallet gives each sender its own address and
never publishes one. Two addresses of one wallet share the signing and nullifier
keys, so anyone who compares them sees one recipient.

A wallet issues indexes in order from 0. It records each index and its pairing
in its `AnonymousRingState` and stores the state before a sender receives the
address. A scan also reads the `ADDRESS_GAP` indexes past the highest issued
one, and a payment found there adds its address to the state. A state holds at
most `MAX_ISSUED_ADDRESSES` addresses, because every scan reads the inbox stream
of each one.

The checksum of a payment request does not cover its query of amount, mint and
label, so a sender treats the query as a suggestion. `zolana-ring address`
issues the next index of the CLI's sender keypair and prints its payment
request.

## Tags and epochs

Solana slots are grouped in tag epochs of `EPOCH_SLOTS` slots. Every proven tag
is one index of one stream in one epoch. An inbox stream holds `J_INBOX` indexes
per epoch, and a pair stream holds `J_PAIR`. A wallet finds its payments by
asking the indexer for the exact tags it derives, and its change through its own
spends. It decrypts no output outside its own tags and spends.

The **inbox stream** of an address carries every payment that takes no pair
stream. Its key derives from the ring id and the address key, so every holder
of the address can derive it.

A **first contact** is an inbox payment that anchors a pair stream. The secret
of its slot keys a **pair stream** between that sender and that address. A
first contact stays live until `K_PAIR_EPOCHS` epochs pass from its own epoch
or `PAIR_IDLE_EPOCHS` epochs pass with no pair payment. Later payments of that
sender can take its pair stream while it is live. A pair that is not live is
dead at both ends, and its recipient stops scanning it. A pair tag reveals
nothing to a holder of the address. Repeat payments therefore stay unlinkable
to everyone but the two parties, the indexers they query, the auditor and its
readers.

A **change** slot pays the sender itself, under a random tag and to the
sender's ring change key. A **padding** slot carries a random tag and random
body bytes. Both random tags follow the distribution of proven tags.

## Sending

Each payment names its recipient by a ring address. In Rust `with_payment`
takes an `AnonymousPayment`, and the builder places each payment at its own
output slot. A ring output to another owner without a payment fails before
proving.

The sender selects a stream and an index for each payment by the rules of
[View Tag Selection](../../docs/spec.md#view-tag-selection). Outputs that
others publish under an inbox tag never stop a payment. After an inbox payment
confirms, the sender records it as the address's newest first contact.

A pair-tagged slot proves its first contact under a root the program reads from
the root history of an SPP state tree. Both SDKs fetch the first contact's path
in one request beside the paths of its decoys. The decoys are outputs of the
same ring and tree in the [anonymous form](../../docs/spec.md#ring-outputs)
that the wallet's scans saw and pinned under those rules. Every read names the
same leaves in the same order and does not mark the first contact.

The transfer fails when the indexer refuses the read or does not prove every
pinned leaf under one root. The error is `FirstContactLeavesRefused` in Rust
and `RING_ANCHOR_INVALID`, reason `leaves`, in TypeScript. The wallet then
retires the first contact with `retire_first_contact` or `retireFirstContact`,
and the next payment to that address takes the inbox stream. The CLI retires it
itself.

A proof binds its epoch. A transaction lands in the proof's epoch, or in the
next one when its instruction sets the previous-epoch flag. `instruction_at`
in Rust and `instructionAt` in TypeScript set the flag from the slot they
build at. Any other landing fails, and the submission of either SDK then
proves again under a fresh salt. See
[How a transfer settles](../README.md#how-a-transfer-settles).

## What the proof covers

For every ring output the audit proof shows that

1. the body encrypts the note's asset address and amount to a canonical X25519
   recipient key,
2. the body key derives from the transaction key, the recipient key, the salt,
   the slot and the first nullifier,
3. the note's asset is the hash of that asset address, and the note carries no
   data,
4. an inbox tag derives from the recipient key's inbox stream,
5. a pair tag derives from a first contact to the same owner in the same ring,
6. the blinding binds the slot secret and the published tag, and
7. a change slot pays the hidden owner.

An anchor accepts only the blinding form of an anonymous ring output. A
deposit, a merge output, a confidential output, an exit and a padding slot
never open as a first contact. The anchor also proves that the first contact
took an inbox tag of the same address. A pair stream therefore starts from an
output on its recipient's inbox stream.

The proof does not show that anyone holds the keys of an address or that the
address's pairing rows admit the first contact.
[Threat](../README.md#threat) names the other choices no proof checks.

## Uniform slots

Every output slot of an anonymous transfer is published, so the slot count
shows only the shape. The ring program refuses a transfer with fewer slots
than its shape. A payment, a change slot and a padding slot have the same
form, a tag and a body. An exit is a default-ring output under its owner's tag.

## The anonymous SPP rail

An anonymous ring settles a member transfer on SPP's `AnonymousRingEddsa`
rail. The hidden owner signs the
[ring spend message](../../docs/spec.md#ring-spend-message). The circuit
verifies the signature and checks that the ring program id the owner signs is
the transfer's ring.

Three parties are public, and the circuit proves each one distinct from the
hidden owner:

1. The SPP payer.
2. The ring's co-signer, or the zero address when the ring has none.
3. The key every withdrawal names, or zero without a withdrawal.

A transfer can spend the hidden owner's default-ring notes in place of ring
notes. It then publishes the owner's key as its default owner tag, and one
transfer cannot spend both kinds. Such a transfer proves under the anonymous
entry audit key and opens every spent note to the auditor. The SDKs select ring
notes alone unless the sender allows default-ring notes. Rust's `AnonymousMove`
allows them with `EntrySpend::Allow`, and the CLI with
`transfer --funding held --entry-spend allow`. A TypeScript transfer allows
them with `inputs` of `"ring-or-default"` or `"default"`, and
`buildRingEntryTransaction` spends them alone.

`AnonymousSpendSigner` produces the signature, so the hidden owner's key can
stay outside the process that proves. In Rust `zolana_keypair::SigningKey` and
`ed25519_dalek::SigningKey` implement it, and a hardware or remote signer
implements it itself.

The SDKs refuse a payer or a co-signer equal to the hidden owner before they
prove. They also refuse a withdrawal destination that names the hidden owner
or its associated token account. The sender names the owner of a token account
the transaction creates, with `with_exit_token_owner` in Rust or
`exitTokenOwner` in TypeScript. The SDK accepts that account only as the named
owner's associated token account.

## Deposits and merges

A deposit into an anonymous ring discloses its owner key to the auditor. See
[Deposits](auditing.md#deposits). Both SDKs credit the depositor's own keys,
because the deposit tag derives from the credited wallet's viewing secret.
The tag comes from the stored `deposit_next` of the wallet's ring state,
`depositNext` in TypeScript, and the indexer does not choose it. Two deposits a
wallet makes between two scans share one tag.

A merge consolidates notes of one owner without the owner's signature. See
[Merges](auditing.md#merges).

## Policies

An anonymous policy ring runs the same rule table as a confidential one. The
sender is the hidden owner. The audit proof and the policy proof both bind one
blinded hash of the hidden owner's key, so the policy screens the owner who
spends. Every spent note belongs to that owner, and the rules read the
records of the owner, of every output owner and of every output asset.

## Wallet sync

A wallet keeps one `AnonymousRingState` per ring and stores it between scans.
[First Time Sync Wallet](../../docs/spec.md#first-time-sync-wallet) lists its
fields, and the state is key material. `AnonymousRingSync` runs the
anonymous-ring steps of that section, and those steps set the epochs each sync
reads. A malformed body under a wallet's tag is skipped and never fails the
sync.

A restore from seed starts a fresh state at `CustomRingConfig::creation_epoch`,
the epoch of the slot the config records at creation. Both SDKs refuse a stored
state of another version. A rescan from the creation epoch builds a new state
without sent first contacts. Each address the rescan finds takes a pairing row
that admits every payment.

A wallet whose viewing secret is kept in a remote key holder syncs the same way.
`ShieldedKeys::ring_address_keys` returns the address keys.
`ring_delivery_secrets` returns the slot secret of each output paid to one of
the wallet's addresses, and `ring_change_key` returns the change key. The
viewing secret never leaves the key holder.

## Integration

### Rust wallet

1. Start each ring's `AnonymousRingState` from `zolana-client` with
   `AnonymousRingState::new(ring, config.creation_epoch())`, and store it with
   `to_json` after every change.
2. To receive, `issue` the next index with its pairing and store the state.
   `address` then builds the `RingAddress`, and its `RingPaymentRequest` text
   goes to the sender.
3. To sync, build `AnonymousRingSync::new(keys, assets)`. Pass the wallet's
   notes to `with_held_utxos`, and the change scan asks for the nullifiers of
   this ring's notes among them. Pass the spends the default-ring sync read to
   `with_default_ring_spends`. Call `fetch(indexer, state, slot)` and store
   the state it returns.
4. To pay, build a `CustomRingTransfer`, call `with_anonymous_signer` with the
   hidden owner's signer and the state, and add one `with_payment` per
   recipient. Submit it through `RingSubmission`.
5. A confirmed submission returns the transfer's first contacts. Pass each
   one's leaf index to `PendingFirstContact::confirm` and the result to
   `record_first_contact`, then store the state.

### TypeScript wallet

1. `issueRingAddress` from `@heliuslabs/zolana/wallet` records the next address
   in the wallet and takes the config's `creationEpoch` the first time. The app
   persists the wallet before it shares the address. `RingAddress`, `Pairing`
   and `RingPaymentRequest` come from `@heliuslabs/zolana/keypair`.
2. `syncWallet` scans anonymous rings when it gets `anonymousRings` with the
   current slot. `start` names each ring with its config's `creationEpoch`
   the first time. The keys implement `RingKeys`, and `LocalKeys` does.
3. `createRingTransferSubmission` pays a `RingAddress` when it gets
   `anonymous` with the spend signer and `wallet.anonymousRing(ring)`.
   `signingKeySpendSigner` wraps an in-process key, and
   `messageSignerSpendSigner` wraps a wallet adapter's message signer.
   `buildRingTransferTransaction` builds the same transaction without the
   first contacts.
4. Its confirmed result carries `firstContacts`. Pass each one with its
   landed leaf index to `recordFirstContacts`, then persist the wallet.
5. The wallet snapshot stores every anonymous ring's state.

## Limits

Owners are Ed25519 keys. A ring output carries no data. An anonymous transfer
carries no SPP [address slot](../../docs/spec.md#input-slots), because its audit
proof rebuilds `private_tx_hash` with an empty address chain. The Rust SDK
refuses such a slot before signing. The anonymous rail serves fewer shapes than
the confidential rail, and a transfer that spends a default-ring note fewer
still. See [the shapes](../README.md#shapes).

Inbox tags are public to every holder of an address, so a holder counts the
inbox payments the address receives per epoch. A first contact pairs only after
the wallet's scans saw `ANCHOR_DECOYS` other anonymous outputs of its ring and
tree. A sender on a quiet tree therefore keeps paying the inbox stream.

Scan cost grows with the epochs since the last scan, the issued addresses, the
live pair streams and the wallet's own spends. Ring traffic does not add to it.
A restore from seed reads every epoch since the ring's creation epoch.

An anonymous merge spends fewer notes than a confidential one. See
[the limits](../README.md#limits).

A pairing row cannot name SOL alone, because SOL's mint is the zero address
and a zero mint admits every asset.
