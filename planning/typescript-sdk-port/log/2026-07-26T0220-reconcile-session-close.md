# 2026-07-26 02:20 UTC | reconciliation session close: the backlog is folded and the baseline is recounted | queue-wide

- Baseline: HEAD `5691096b` on `port/reconcile`
- Worker: reconciler, second holder of the role
- Explanation: closes the session that folded the four unreconciled row-update files. This entry exists to record the verdicts in the form `review-checklist-check.mjs` reads, one verdict per field line, and to record the recount. The two entries before it packed several verdicts onto one `Verdicts:` line, which that check deliberately refuses to attribute, so it read the rows as still carrying their old adverse verdicts. Entries are not edited once committed, so the correction is made here, where it supersedes.
- Evidence: six commands run at this HEAD, `pkp-entry-gate.mjs --skip-ci`, `review-checklist-check.mjs`, `check:packaging`, `typecheck`, `test:unit`, and `fixtures:check`

## The recount

Counted from the tables rather than from the block that described them, because the block disagreed with itself: one line read 45 adverse and another read 61 including 4 `BLOCKED`. The tables and the entry gate agree with each other.

| | Before | After |
| --- | --- | --- |
| `PARITY` | 90 | 95 |
| `PARTIAL` | 27 | 22 |
| `DIVERGENT` | 17 | 17 |
| `STALE` | 1 | 1 |
| `NOT_APPLICABLE` | 10 | 10 |
| adverse | 45 | 40 |

`DIVERGENT` holding at 17 hides two moves in opposite directions: `C08` closed and `C18` reopened.

## What the next dispatch should be

The largest adverse cluster is the transaction package, 15 of the 40, and it is one kind of problem rather than fifteen. Eleven of the fifteen are held open by the public surface: a Rust type with no TypeScript counterpart and no root export (`DecodeCx`, `OwnerCx`, `UtxoSerialization` on `T10`, `ApprovalRequest` and `Balances` on `T17`, `decryptTransactionsWorkerEquivalent` on `T16`), or an aggregate export omission on `T26`, `T30` and `T31`. The fifteen sit at `needs_fix` with a named symbol, and none at `needs_re_review`, so the cluster wants a fix worker with the transaction package's export surface as its brief, not a reviewer.

- Verdict: `PARITY` for `C07`, `C08`, `C15`, `C19`, `C20`, and `M02`
- Verdict: `DIVERGENT` for `C18`, reopened, and for `T23`, unchanged
- Verdict: `NOT_APPLICABLE` accepted for `H08`
- Verdict: `PARTIAL` unchanged for `K13` and `K14`, whose recorded causes were corrected without moving the verdict
- Gap and smallest fix: `C18` owes a four-shape restriction on the zone-authority rail in both languages with a named error and a shared vector; `T23` owes the BN254 range check in `spp_proof_inputs.rs` and a boundary vector
- Row transitions: seven rows to `done`, one row out of it
- Progress: `95/145`
- Exact next file: `I07`, first at `needs_re_review` in queue order; `C18` needs a fix worker in parallel
- Full SDK parity claim: unsupported
