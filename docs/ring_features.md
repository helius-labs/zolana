# Ring features

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

## 1. Co-signer

A co-signer is a key that the ring authority designates to approve deposits,
transfers, withdrawals, or transfers and withdrawals above a threshold. The
co-signer on its own cannot move funds.

### Operations that can be gated by co-signer approval

- **Deposits:** every deposit into the ring.
- **Transfers:** every transaction through the ring, including withdrawals,
  transfers with a deposit leg and delegate moves. Only plain deposits are
  not covered.
- **Withdrawals:** withdrawals whose public amount per token in one
  transaction exceeds a threshold. A token with no threshold always needs
  approval.
- **Transfer/Withdrawal Threshold:** transfers or withdrawals whose total per
  token in one transaction exceeds a threshold. Configured for every token. Thresholds for deposits
  are unimplemented.

### Configuration

- The ring config holds one co-signer.
- The co-signer can be a smart account to allow multiple approvers.
- The ring authority sets, replaces or removes the co-signer, and selects any
  combination of deposits, transfers and withdrawals plus the withdrawal
  thresholds per token.
- The transfer/withdrawal threshold is part of the policy, and only the
  upgrade authority can change it.
