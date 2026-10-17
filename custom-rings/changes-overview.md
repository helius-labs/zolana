A custom ring adds rules and auditor access to notes tagged with its program ID. SPP still settles transfers and checks commitments and nullifiers. Users keep their spending keys.

Originally, each transfer encrypted its viewing secret to the auditor using P-256 ECDH and a fresh ephemeral key. A proof checked that this secret matched the transfer's published viewing key. SPP bound the ciphertext to the transfer. The auditor recovered the key and decrypted output data.

VE already existed. The gap was in what the key unlocked. The original proof did not check that decrypted output data matched the committed notes. A valid transfer could leave the auditor with misleading or unreadable data.

Dedicated output disclosure closed that gap before this merge. The circuit encrypts note fields and computes their commitments from the same fields. Anonymous mode now extends disclosure to the sender, spent notes and recipients. The auditor sees the hidden transaction that the policy proof checks.

```text
Originally: proven encrypted key → auditor → output data from the wallet

Now: committed notes → proof checks policy and disclosure → settlement
                                          ↓
                              auditor decrypts checked data
```

This guarantee covers the dedicated audit disclosure. It does not certify every recipient ciphertext. Audited deposits also bind disclosure to the deposit that settled. Deposit amounts remain public.

Policy rules screen senders, recipients and assets. For example, a recipient must be approved and a sender must not be frozen. Amount thresholds can waive a check. Outflow thresholds can require a co-signer.

Previously, each list entry was a versioned SPP data note. Updates created new versions and revoked old ones. Transfers needed membership and revocation evidence for the entries their rules used. Escrowed keys lived in a separate registry.

```text
Before: member + list → versioned note + revocation evidence
        member       → separate escrow record

Now:    member       → one registry leaf [list bits | escrow commitment]
```

Membership now lives in a bitmap in an indexed Merkle tree. The ring stores accepted roots on chain. Photon stores the records and supplies authenticated paths. One opening supplies a member's status across rules. List updates preserve the escrow commitment. Key registration preserves the list bits.

Transfers no longer need list entry history or revocation proofs. They check a registry snapshot. Recent roots remain usable, so updates do not instantly invalidate older proofs. Membership records are public. Anonymous transfers hide which records they use.

A ring can read its own lists and lists from one other ring. That ring is the curator. Several rings can share its screening decisions without copying the entries.

The inline allowlist of eight mints is gone. Mints now use registry lists too. Changing an allowed mint updates its list bit instead of rewriting the policy. Lists can hold more than eight mints and can come from the curator. Owners and assets have one membership mechanism. Amount thresholds for each mint remain in the policy. They define amounts, not membership.

Rolling spend counters are gone. Limits cap a sender's outflow per mint in one transfer. Payments no longer update a spend counter. A 100-token cap allows two 60-token transfers. It is not a daily budget.

| Role | Before the curve migration | Now |
|---|---|---|
| Spending authority | P-256, Ed25519 or PDA | Ed25519 or PDA |
| Viewing and auditor encryption | P-256 ECDH | X25519 |
| Audit reader authentication | Solana keys or P-256 passkeys | Both remain supported |

VE uses the new X25519 viewing keys. Removing P-256 spending removes an ownership path and its proof machinery. Passkeys still authorize audit readers. Existing P-256 notes and viewing data need migration.

Registry mode keeps key escrow for recovery and a separately authorized delegate. Anonymous mode uses Ed25519 owners and discloses their identities to the auditor. It disallows delegation. The auditor key alone never grants spending authority.

Programs, proving keys, SDKs and indexer layouts must agree. Existing list notes need migration into the registry.
