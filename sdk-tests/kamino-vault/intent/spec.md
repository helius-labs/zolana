# kVault Intents

- Private deposits into and exits from a fixed set of Kamino kVaults. An order hides which vault it targets, its direction (deposit or exit), and its amount.
- Users submit orders during a period and can go offline. After the period ends, the maker executes one net kVault operation per supported vault and fills each order at the rate that operation realized, minus a public `fee_bps`.
- The program performs the net operation itself, by CPI into kVault `deposit` or `withdraw_from_available` from the maker's token accounts, and records the realized rate from the token balance deltas. The maker does not set or report rates, holds no inventory, and carries no price risk.
- Every supported vault is executed in every period, with a minimum deposit when its orders net to zero, so the set of executed vaults is the same whether or not a vault had orders.
- `create_escrow`, `settle`, and `cancel` reference only the market and period accounts. The vault and direction are private proof inputs, checked against the period root.
- Each order settles only against the period it was created in. The taker's private `min_out` refunds the order if the realized rate is worse, for example after a loss in a vault's reserves. Fill and refund have the same shape, verifying key, and public effect.
- There is no bond. A maker that does not execute costs the taker the time until `expiry`, then anyone holding the order data cancels it. Cancels are public, so a maker's non-execution rate is observable.
- The payout destination is the taker: the proof checks that the recipient owner-hash equals the source UTXO's owner, and the order UTXO's data hash includes it. Settlement and cancel blindings follow [dynamic swap settlement recovery](../../dynamic-swap/swap_program.md#settlement-recovery). The `escrow_authority` nullifier secret is 0, as in dynamic swap.

## Actors

| Actor | Role | Trust |
|-------|------|-------|
| Taker | Locks a base-token or share UTXO into an order with a private `min_out`, holds its opening, and cancels it after expiry if unsettled. | None. The proofs fix the payouts. |
| Maker | Decrypts orders, executes the net operation per vault, and settles. Learns each order's vault, direction, and amount. Fronts the net operation until the fills return the escrowed funds. | Liveness and privacy. In a TEE, attestation shows the code that handles the orders. |
| Anyone | Cancels an expired order. | None. Only a holder of the order data can build the proof. |

## Periods

A market has `period_slots` and `settle_slots`. Period `p` covers slots `[p * period_slots, (p + 1) * period_slots)`.

1. **Collect** (during `p`): takers `create_escrow`; each escrow stores `p`.
2. **Execute** (after `p` ends): the maker runs `execute` once per supported vault.
3. **Finalize**: `finalize_period` commits the recorded rates under the period root.
4. **Settle** (until `expiry = (p + 1) * period_slots + settle_slots`): the maker fills or refunds each order of `p`.
5. **Cancel** (after `expiry`): unsettled orders return to their takers.

## Instructions

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | create_market | 1 | Creates a market at `[b"market", authority, market_id]` with the authority, the handoff encryption key, `fee_bps`, `period_slots`, `settle_slots`, and up to `MAX_VAULTS` kVault addresses with their base and share mints, each at a fixed index. | — | market account (created) | Maker signs (fee payer) |
| 2 | execute | 2 | After period `p` ends, for vault index `i` not yet recorded in `p`: CPIs kVault `deposit` (net deposit, at least the vault's minimum) or `withdraw_from_available` (net exit) from the maker's token accounts, measures the base and share balance deltas, and stores the leaf `(i, base_amount, share_amount)` in the period account `[b"period", market, p]`, creating it on first use. | market account, kVault accounts | period account | Maker signs |
| 3 | finalize_period | 3 | Requires a leaf for every supported vault. Computes the period root over the leaves. | market account | period account | Maker signs |
| 4 | create_escrow | 4 | During period `p`, one IN1_OUT2 `order_open` proof spends the taker's source UTXO into the order UTXO (owned by `escrow_authority`) and change. The proof checks that the source asset is the base or share mint of vault `i` of the market. The order data hash includes `Poseidon(i, direction, min_out, recipient_owner_hash)`. The handoff encrypts the order opening to the market's key. Stores the escrow UTXO hash (the PDA seed), `owner`, and `p`. | market account | escrow account (created) | Taker signs (fee payer) |
| 5 | settle | 5 | Resolves one escrow of `p` before `expiry`, against the finalized period account of `p`. One IN2_OUT3 `order_settle` proof spends the order UTXO and the maker's UTXO of the output mint. The proof checks leaf `i` under the period root and computes `out = floor(amount_in * share_amount / base_amount)` for a deposit or `floor(amount_in * base_amount / share_amount)` for an exit, times `(10000 - fee_bps) / 10000`, and `fills = out >= min_out`. On fill the recipient gets `out` of the output mint and the maker gets `amount_in` of the input mint; on refund the recipient gets `amount_in` back and the maker gets a zero-amount UTXO of the input mint. Output 2 is the maker's change in both cases. Closes the escrow. | market account, period account | escrow account (closed) | Maker signs; destinations are fixed by the proof |
| 6 | cancel | 6 | Refunds one escrow after `expiry`. One IN1_OUT1 `order_cancel` proof spends the order UTXO back to the committed recipient. `rent_recipient` must be the escrow's `owner`. Closes the escrow. | escrow account | escrow account (closed) | Permissionless; only a holder of the order data can build the proof |

## Visibility

| Field | Visibility | Reason |
|-------|------------|--------|
| Market, maker, taker address | Public | Instruction accounts; default-ring owners are public |
| Supported vaults | Public | Market account |
| Net operation and rate per vault per period | Public | The `execute` CPIs and the period leaves |
| Vault, direction | Private | Private proof inputs, checked against the period root |
| `amount_in`, `out`, `min_out` | Private | Inside UTXO commitments and the order data hash |
| Fill or refund | Private | Same shape, verifying key, and public effect |
| Escrow period, settle or cancel | Public | Escrow account lifecycle |

## Risks

1. Exit liquidity: `withdraw_from_available` pays only from a vault's idle funds. If the net exit exceeds them, `execute` withdraws what is available and the rate leaf reflects it; exits whose `min_out` the rate misses refund.
2. Anonymity is weighted by flow: an order hides among the vaults with orders in its period, and a vault with one order shows that taker's net amount, though not which taker.
3. Timing: settles that follow closely after a single vault's `execute` point to that vault; the maker settles a period's orders after finalizing, in random order.

## Future Work

1. Batched settlement in two phases: pay (one maker input, about 45 payout outputs without ciphertext, the most that fits beside this program's instruction in 4,096 bytes) and collect (up to 48 escrow inputs into one maker output), with escrow records kept in the period account. Needs a new wide-output SPP shape.
2. Reserve-backed kVault exits through `withdraw`, which redeems from klend when idle funds run short.
3. Closing finalized period accounts after their last escrow resolves.
