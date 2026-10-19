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

Auditor disclosure is now verifiable against the committed notes. Settlement requires the proof. A sender cannot settle a transfer while substituting a false audit record. Auditor recovery reads that proved record directly. Broken or misleading recipient data cannot hide it. Audit scans and recovery compare indexed transfer, deposit and merge data with the exact confirmed SPP event. A fabricated indexer row cannot invent an audited payment or mark a note spent.

Exits to the default ring must publish the recipient owner through the confidential marker. SDKs reject a missing or wrong marker before proving. Otherwise a zero-identity output can burn the funds. Dummy padding is exempt.

Ordinary recipient encryption stays wallet-side. The proof does not guarantee that a recipient can recover the payment. A sender can already send their own funds to the wrong address or burn them. This does not bypass SPP's conservation or double-spend checks.

Swaps and other protocols that rely on delivery need a separate guarantee. That requires proving both the recipient ciphertext and its binding to the intended recipient's key. Ordinary self-funded transfers do not pay for that proof.

Every ring deposit now proves that the auditor's record matches the deposit that settled. The old optional audit switch remains on the wire. New false settings are rejected, and old false accounts cannot permit a proofless ring deposit. Deposit amounts remain public.

Merges now prove an encrypted copy of the merged amount and mint too. Every nonanonymous ring merge also proves that its owner's nullifier key has a registered auditor ciphertext. The auditor can recover that key, decrypt the merge output and check its commitment. The signed merge-audit RPC pages the ring's confirmed history and reports any output it cannot open. Its key search has a work limit and fails without a partial result if it runs out. A direct Rust audit can scan the full registry. The owner can rebuild the output even if a merger includes an input they never received. This is separate from ordinary recipient delivery. Merge proofs have 52 slots. A custom-ring merge fits at most 50 published inputs without an extra signer. Extra accounts or a co-signer can lower that cap. SDKs check the serialized transaction before proving. All real inputs must have the same committed ring data hash. The output inherits it. Merging cannot clear or replace that commitment.

Paying fees no longer adds a signer to the ownership proof. An owner who also pays still appears explicitly among owner signers. Anonymous transfers have an empty public signer vector and prove the hidden owner's signature instead. Before adding its PDA signature, the ring checks the payer, every deposit source and every public owner signer. A caller cannot use the ring PDA as a substitute signature.

Policy rules screen senders, recipients and assets. For example, a recipient must be approved and a sender must not be frozen. Amount thresholds can waive a check. Outflow thresholds can require a co-signer.

Previously, each list entry was a versioned SPP data note. Updates created new versions and revoked old ones. Transfers needed membership and revocation evidence for the entries their rules used. Escrowed keys lived in a separate registry.

```text
Before: member + list → versioned note + revocation evidence
        member       → separate escrow record

Now:    member       → one registry leaf [list bits | escrow commitment]
```

The policy and its members live in different places.

| Data | Stored where | What it contains |
|---|---|---|
| Rules and thresholds | The ring's 1,596-byte `PolicyConfig` PDA | Sixteen packed rules, eight list sources, eight mint-specific amount thresholds and eight outflow rows. Also the policy hash, address-tree binding and update generation. |
| Accepted registry snapshots | The ring's 1,035-byte `MemberRegistryRoot` PDA | Thirty-two recent Merkle roots, the current root position and the next free leaf index. |
| Members and mint memberships | Registry leaves reconstructed by Photon | An owner or asset identifier, its next identifier in sorted order, a 64-bit list bitmap and an escrow commitment. Current policies address eight list IDs. |
| Recovery ciphertext | The registration instruction, indexed with the member record | The encrypted nullifier key. Its hash is bound into that member's escrow commitment. |

A rule names a subject, required or forbidden list bits, an optional alternative list set and an amount guard. It occupies one 32-byte field in the policy account. Each list source stores its list ID and a registry address. Zero means this ring's registry. A nonzero address names the curator's registry.

A member does not get a separate account for every list. One leaf holds all its list bits. The `next` identifier lets a proof show that a missing member falls between two entries. Photon supplies the record and Merkle path. The proof checks that path against an accepted on-chain root.

```text
PolicyConfig PDA                 MemberRegistryRoot PDA
  rules + list source map          accepted roots
             ↓                          ↑
  own registry or curator        proof checks a path
                                        ↑
                              Photon record
                     [member | next | list bits | escrow]
```

List updates change bits and preserve the escrow commitment. The program rejects any attempt to change escrow through a list update. Only key registration can set an empty escrow commitment. Its proof binds the recovery ciphertext to the member's nullifier key. A registered key is final. Registration preserves the list bits. Photon keeps those authenticated bits instead of trusting redundant registration fields. Transfers no longer need list entry history or revocation proofs. They read a registry snapshot without changing it.

A policy edit validates the new table, replaces its hash and increments its generation. A membership edit publishes a new registry root. These have different effects. A proof for different rules no longer matches the current table. An older registry root can still be accepted until it leaves the 32-root history. Membership records are public. Anonymous transfers hide which records they use.

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

Programs, proving keys, SDKs and indexer layouts must agree. Existing list notes need migration into the registry. Deployment rejects legacy auditor configs before uploading. Photon indexes the member registry by default. Its migrations handle both old table names and databases already upgraded by main.

The full policy and auditor proof now fits below 100k constraints for two inputs and three outputs. All rule capacity, curator lists and escrow remain. The savings preserve the same policy and auditor checks.

| Optimization | Work saved |
|---|---|
| Shape and mode keys | Prove only the supported input and output capacity. Omit anonymous disclosure work from ordinary transfers. |
| Public policy binding | The verifier reads the stored table into 78 public fields. Each transfer no longer hashes the whole public table inside the circuit. Policy writes still validate and hash it. |
| Shared registry paths | Records in the same eight-leaf block share one upper Merkle path per registry. General proofs still accept scattered records. |
| Smaller integer checks | Bound limbs and carries instead of decomposing every value into bits. Absence proofs still enforce strict canonical ordering. |
| Less repeated policy work | Decode each packed rule once and reuse amount checks for the same asset. |
| Optimized auditor encryption | Use the existing X25519 and AES gadgets, the two-hash Poseidon key schedule and bounded canonical byte encoding. Reuse note commitments and omit unused disclosure work. |

The public table is read from the program-owned account. The prover cannot supply a replacement table. The proof stays 192 bytes. The new public fields do not add instruction payload.

```text
Before: each record gets a full path + policy is hashed again
Now:    records share a path + verifier reads the stored policy
```

| Proof for a 2-input, 3-output payment | Current constraints | Pre-427 proving time |
|---|---:|---:|
| Default-ring settlement | 57,558 | 146.6 ms |
| Custom-ring settlement | 57,684 | 159.7 ms |
| General policy and audit | 326,293 | 575.6 ms |
| New ordinary policy and audit | **95,943** | **237.8 ms** |
| New anonymous policy and audit | **98,809** | **267.9 ms** |
| New delegate policy and audit | **95,217** | **271.9 ms** |

The sub-100k figure covers policy and audit. Ordinary custom settlement adds another 57,684 constraints. Both proofs together total **153,627 constraints**. The previous build took 397.5 ms across both proofs. Default-ring settlement has no custom policy or auditor disclosure.

The shared-path proof requires queried records to share one aligned eight-leaf block within each registry. Absence checks use the predecessor's position. The registry itself can be much larger. Every supported shape also has a general proof for scattered records. Indexed requests use that general path because the client does not yet know the record positions. Both paths enforce the same policy.

The new keys cover the default ring's shapes that fit the current ring transaction format. These are proof capacities. Smaller live counts use the same padding rules as settlement. The dedicated 2×3 optimization remains available.

Exact 2×3 means two published inputs and three published outputs. Compact padding removes the trailing dummy slots and reveals those counts. It is opt-in. Delegate builders now support it in Rust and TypeScript. Anonymous transfers allow compact outputs while keeping their inputs padded. The settlement witness still fills every circuit slot.

| Transfer mode | New proof capacities |
|---|---|
| Ordinary | 1, 2, 3, 4, 5, 6, 8, 12 or 16 inputs, each with 2 or 4 outputs, plus 24×2 |
| Anonymous | 1, 2, 3, 4, 5 or 6 inputs with 2 or 4 outputs, plus 8×2 and 12×2 |
| Delegate | 2×2 and 4×4 |

Each capacity has a general key and a shared-path key. There are 19 ordinary, 14 anonymous and two delegate capacities. The exact 2×3 keys remain separate. Larger shapes cost more. For example, ordinary 1×2 uses 87,884 constraints with shared paths, while the 24×2 general proof uses 409,861. The sub-100k result is not a promise for every shape. A new 12-slot audit-only key covers anonymous transfers above four inputs.

Rust builds all three transfer modes. TypeScript builds ordinary and delegate transfers. Its audit reader supports anonymous transfers. The default ring remains nonanonymous.

Transaction size is the other limit. A V1 transaction has 4,096 bytes. With ordinary recipient ciphertexts, auditor disclosure, one owner who also pays and one policy tree, the Rust serializer measures:

| Shape | Serialized bytes | Result |
|---|---:|---|
| 12×4 | 3,788 | Fits |
| 16×2 | 3,674 | Fits |
| 16×4 | 4,052 | Fits only with little extra data |
| 24×2 | 3,626 minimum, 3,888 with the measured extras | Fits |
| 32×2 | 4,154 minimum | Excluded |
| 1×8 | 4,970 | Excluded |
| 1×16 | 8,786 | Excluded |

The 24×2 measurement uses a compact, proved auditor record of its two output openings. The other ordinary measurements predate this extension. They include the priority-fee header and inline output owner tags. A curator, co-signer and extra policy tree bring 16×4 to 4,314 bytes. That transaction is rejected. The SDK checks the core transfer size before proving. Final assembly checks the complete transaction again. No policy rule is waived to make it fit.

Anonymous disclosure includes the hidden sender and every spent note. With its current byte layout, the size model measures 6×4 at 3,835 bytes with lean accounts and 4,001 bytes with the measured extras. It measures 12×2 at 3,983 and 4,149 bytes, so that capacity only settles with a lean account set or fewer live slots. In the live validator, fully populated 6×4 and 12×2 transfers settled at 3,795 and 3,943 bytes. The model measures 8×4 at 4,159 bytes with lean accounts. The anonymous rail therefore cannot use every ordinary capacity. Its 14 keys cover every default-ring capacity whose measured lean anonymous transaction fits 4,096 bytes. Both proofs keep their full policy and audit checks.

Before PR #427, all 51 specialized policy keys passed full live settlement and auditor checks. This covers the 48 capacity keys and three exact 2×3 keys. Those fixtures consume 678k–757k CU across both verifiers and SPP settlement. [Proof costs](proof-costs.md) separates the rails and records the tested byte sizes.

After PR #427, all 29 anonymous and five delegate specialized cases have fresh valid-proof settlement coverage. The other 39 specialized cases still need the ordinary settlement keys from the new setup. All three ring-merge keys settle through the custom program and SPP. The tests use one real input in the 8-slot proof, 24 in the 24-slot proof and 50 in the 52-slot proof. The merge ciphertext uses the owner's nullifier key. The proof now binds that key to an authenticated registration even when the ring does not otherwise require escrow. It also bounds the encrypted mint chunks to the byte widths the auditor decodes. This keeps merge outputs recoverable by the auditor without adding a ciphertext to every input. Rust and TypeScript audit scans verify the registry root and the confirmed merge, then check the opened amount and mint against the settled commitment. Unopened outputs remain visible as unresolved. Registry keys are tried one at a time so a large registry does not require storing every decrypted key.

The 8-output and 16-output capacities are excluded. Ordinary transfers support 24×2 through a shorter proved disclosure. Anonymous transfers stop at 12×2 or 6×4 under the measured minimum layouts. More signers, extra data or extra instructions can also make a supported capacity too large. The 64-account limit still applies. Delegate shapes remain bounded by their settlement rail.

Constraint counts include PR #427. Its signer binding adds four constraints to ordinary settlement. The timing and size tables are the pre-427 baseline. The combined build needs fresh measurements because settlement authorization and keys changed. Measured on an Apple M5 Pro. Times are medians of three batches of five proofs. Compilation, setup and verification are excluded. Each proof was verified. The combined time adds the two proof times. It is not transaction latency.

The pre-427 one-input, two-output audit-only transfer used 89,632 constraints across both proofs. It has no policy rules. [Proof costs and security checks](proof-costs.md) give the bounds, fallback and reproduction commands. One catalog now drives all 82 ring keys in the CLI, release tools and TypeScript pins. Generation updates these together. Release loading rejects missing or mismatched keys. Deployment also checks the verifier markers embedded in the program, so stale binaries cannot be paired with current keys. New keys are generated locally. The matching program, keys and clients still need deployment together. The [audit map](audit-readiness.md) links guarantees to source and tests. The [code differential review](re-audit-checklist.md) assesses the custom-ring additions with PR #427 treated as merged.
