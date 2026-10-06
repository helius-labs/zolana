# Ring features

A custom ring lets you enforce your own compliance rules on private transfers
in the Solana Privacy Program: you define a policy that every transfer and
withdrawal must prove it satisfies, and ring settings such as co-signer
approval that your ring program checks directly. This document describes each
control you can configure and who can change it.

1. Co-signer
2. Allowlist
3. Blocklist
4. Curated lists
5. Frozen list
6. Asset allowlist
7. Amount thresholds
8. Velocity limits
9. Spend window
10. Permanent delegate and key escrow
11. Auditor
12. Deposit audit
13. Readers
14. Pause

## Policy

A ring's policy is the set of rules that transfers and withdrawals through the
ring must satisfy. The transaction proves it satisfies them without revealing
amounts, recipients or which list entries it used.

### Policy and ring settings

- **Policy:** allowlist, blocklist, frozen list, asset allowlist, amount
  thresholds and velocity limits. The proof checks these, and only the
  upgrade authority can change them.
- **Ring settings:** co-signer, spend window, deposit audit, readers and
  pause. The ring program checks these, and the ring authority changes them.

### Rules and entries

- The policy fixes the rules: which lists are checked, for which party, and
  above which threshold.
- The ring authority adds and removes list entries without changing the
  policy.

## 1. Co-signer

A co-signer is a key that the ring authority designates to approve selected
operations. The co-signer on its own cannot move funds.

### Operations that can require approval

- **Deposits:** every deposit into the ring.
- **Transfers:** every transaction through the ring, including withdrawals,
  transfers with a deposit leg and delegate moves. Plain deposits are
  excluded.
- **Withdrawals:** withdrawals whose public amount per token in one
  transaction exceeds a threshold. A token without a threshold needs
  approval for any amount.
- **Transfer/withdrawal threshold:** transfers or withdrawals whose total per
  token in one transaction exceeds a threshold, configured per token.
  Deposits have no threshold.

### Configuration

- The ring config holds one co-signer.
- The co-signer can be a smart account to allow multiple approvers.
- The ring authority sets, replaces or removes the co-signer. It also selects
  the operations that need approval and the withdrawal thresholds per token.
- The transfer/withdrawal threshold is part of the policy, and only the
  upgrade authority can change it.

## 2. Allowlist

An allowlist is a list of approved identities that the ring authority
maintains, and the ring can require parties to a transfer to be on it. List
entries are public: anyone can see which identifiers are on the list and
when entries were added or removed. A transfer proves its checks without revealing which
entries it used.

### What can be checked

- **Sender:** the sender must be on the allowlist.
- **Recipients:** every recipient must be on the allowlist.
- **Recipients above a threshold:** a recipient must be on the allowlist only
  when it receives more than a threshold per token in one transaction.
- **Combined with other lists:** for example, on the allowlist and not frozen,
  or on the allowlist or on the approval list.

### Configuration

- The ring authority adds and removes entries.
- The list is the ring's own, or one shared by a curator ring.
- Sender and recipient checks are configured independently, each with its own
  list, and a transfer must pass all configured checks.
- Which checks apply is part of the policy, and only the upgrade authority can
  change it.

## 3. Blocklist

A blocklist is a list of identities or tokens the ring refuses transfers to
or from. A block takes effect as soon as the entry is added. Block lists can be shared.
Entries are public, and a transfer doesn't reveal which entries it checked.

### What can be checked

- **Sender:** the sender is not on the blocklist.
- **Recipients:** no recipient is on the blocklist.
- **Tokens:** no token moved is on the blocklist.
- **Approval list exception:** a blocked party passes if it is on the ring's
  approval list. A ring that uses a curator's shared blocklist can't remove
  entries from it, so the approval list lets it clear individual parties
  locally.

### Configuration

- The ring authority adds and removes entries on its own blocklist and
  approval list.
- The blocklist is the ring's own, or one shared by a curator ring, such as a
  sanctions list.
