A custom ring adds rules and auditor access to notes tagged with its program ID. SPP still settles transfers and checks commitments and nullifiers. Users keep their spending keys.

Originally, the sender encrypted the transaction viewing key to the auditor using P-256 ECDH. The proof checked that encrypted key against the transfer's published viewing key. The auditor could recover it and decrypt the wallet's output data.

That was verifiable encryption of a key, not verifiable disclosure of the payment. The proof did not check that the encrypted output data matched the notes. A sender could commit a note for 100 and encrypt data saying 10. The key proof would still pass.

Before this merge, the minimized branch already fixed that for the auditor. The proof creates an encrypted auditor copy from the same fields used to compute the output commitments. A note for 100 now requires an audit record for 100. Anonymous mode extends that checked record to the sender, spent notes and recipients.

```text
Original: proof checks the auditor's key
          payment data could still be wrong

Now:      committed notes → proof checks encrypted disclosure → auditor
          committed notes → wallet encrypts payment data     → recipient
```

Auditor disclosure is now verifiable against the committed notes. Settlement requires the proof. A sender cannot settle a transfer while substituting a false audit record.

Ordinary recipient encryption stays wallet-side. The proof does not guarantee that a recipient can recover the payment. A sender can already send their own funds to the wrong address or burn them. This does not bypass SPP's conservation or double-spend checks.

Swaps and other protocols that rely on delivery need a separate guarantee. That requires proving both the recipient ciphertext and its binding to the intended recipient's key. Ordinary self-funded transfers do not pay for that proof.

Audited deposits also prove that the auditor's record matches the deposit that settled. Deposit amounts remain public.

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

X25519 replaces P-256 for viewing and auditor encryption. The curve change alone does not prove that encrypted data matches a note. Removing P-256 spending removes an ownership path and its proof machinery. Passkeys still authorize audit readers. Existing P-256 notes and viewing data need migration.

Registry mode keeps key escrow for recovery and a separately authorized delegate. Anonymous mode uses Ed25519 owners and discloses their identities to the auditor. It disallows delegation. The auditor key alone never grants spending authority.

Programs, proving keys, SDKs and indexer layouts must agree. Existing list notes need migration into the registry.

For an ordinary transfer with one input and two outputs:

| Proof | Constraints | Proving time |
|---|---:|---:|
| Default ring | 30,922 | 61.4 ms |
| Custom ring settlement | 30,987 | 62.4 ms |
| Custom ring auditor disclosure | 62,345 | 158.6 ms |
| Custom ring total, without policy rules | 93,332 | 221.1 ms |

Measured on an Apple M5 Pro. Times are medians of three batches of five proofs. Compilation, setup and verification are excluded. Each proof was verified. The total adds the two proof times. It is not transaction latency. Policy enforcement uses a separate combined policy-and-audit circuit and is not included here.

The auditor path uses optimized X25519 and AES with a Poseidon key schedule. Ordinary rings now use a smaller audit circuit that excludes anonymous disclosure work. Settlement selects the key from the ring's configured mode. The complete ordinary transfer falls from 126,597 to 93,332 constraints. The auditor still receives the same checked data.

Anonymous audit proofs also shrink from 95,610 to 80,833 constraints. Canonical byte encoding uses bounded limbs instead of individual bits. Output commitments are computed once. Neither change removes a disclosure check. [Optimization details](proof-costs.md) explain the bounds and validation.

Reproduce with `go test ./circuits/spp_transaction/shared -run '^$' -bench '^BenchmarkPaymentProofs$' -benchtime=5x -count=3` from `prover/server`.
