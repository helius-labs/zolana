# Dynamic Swap

- Price updates are cheap: `update_price` touches only the pair account, and `create_escrow` prices the order at creation by reading that price.
- Unidirectional trading pairs (e.g. SOL -> USDC), each with its own authority (the maker) who sets the price.
- Committed liquidity: the pool is every UTXO owned by the pair's `pool_authority` PDA (destination asset). Each pool note's confidential data contains `booked`: the portion of its amount that the public accounting already counts. The pair account tracks a public `available_liquidity` and `open_reservations`. Invariants: per note `0 <= booked <= amount`, and globally `sum(booked) >= available_liquidity + open_reservations * max_order_size`. Each open escrow holds a `max_order_size` reservation, covered by funds the maker cannot withdraw.
- Order amounts are confidential, so the accounting is conservative: `create_escrow` reserves the worst case (`max_order_size`), and settle publicly changes nothing except closing the reservation. The unspent part of the reservation (`max_order_size - owed`) stays inside the pool change note as surplus (`amount - booked`).
- Rebalancing is the only place surplus becomes public liquidity again: `rebalance_liquidity` restructures pool notes (many in, many out) and lets the maker declare a public `credit`, adding exactly that much of the spent notes' surplus to `available_liquidity`. Timing and granularity are maker-chosen; a zero credit restructures the pool (merge, split, re-blind) with no public effect.
- `max_order_size` is immutable per pair: cancel must release exactly what create_escrow reserved. It is denominated in the destination asset. `escrow_open` proves the reservation covers the order at the public window's highest price.
- Each pair also fixes an absolute `price_tolerance = X` and a private-proof-enforced `min_order_amount`. For public instruction floor `F`, escrow creation accepts the live price in `[F, F + 2X]`; the taker's private `min_price` must be in `[F, F + X]`.
- Only the maker fills: settle requires the pair authority's signature. The taker's paths are settle-by-maker before expiry or unilateral cancel after; the taker's worst case is funds reserved for `expiry_slots`, then cancel.
- Deposit notes are public (amount, owner, blinding, and `booked = amount` are instruction data; the program computes the commitment itself, no proof). Pool confidentiality comes from settle, withdraw, and rebalance output notes with maker-held private blindings and confidential `booked` values. The only encrypted handoff is the order UTXO data at `create_escrow`.
- `execution_price` is public and snapshotted in the escrow account. The coarse `public_price_floor` is instruction data and gates escrow creation; the exact `min_price` is encrypted to the maker and evaluated only in settlement. Settlement privately fills when `execution_price >= min_price`, otherwise it refunds the fixed source amount.
- The payout destination stays confidential: the proof checks that the recipient owner-hash equals the taker's source UTXO owner. It appears only in the order UTXO's composite data hash and encrypted maker handoff.
- The `escrow_authority` and `pool_authority` nullifier secrets are hardcoded to 0: escrow- and pool-note spend linkage is already public (`escrow_utxo_hash` lives in the escrow account, deposit notes are public), and spends are gated by the proofs, the signer checks, and the liquidity accounting.

## Instructions

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | create_pair | 1 | Creates a unidirectional trading pair. Alongside the existing authority, assets, expiry, handoff key, receipt owner, and destination-denominated `max_order_size`, it stores immutable nonzero `price_tolerance` and `min_order_amount`. `price` must be at least the tolerance. | — | pair account (created) | Pair authority signs (fee payer) |
| 2 | update_price | 2 | Updates `price`; it must remain nonzero and at least `price_tolerance`. | — | pair account | Pair authority signs |
| 3 | deposit_liquidity | 3 | Shields a public `amount` of the destination asset from the depositor's SPL token account into a new pool UTXO owned by the pair's `pool_authority` PDA, with `booked = amount` in its note data. Amount, owner, blinding, and booked are public instruction data, so the program computes the UTXO commitment itself; no proof. `available_liquidity += amount`. A zero amount is rejected. | — | pair account | Permissionless: the depositor signs its own SPL transfer (fee payer) |
| 4 | withdraw_liquidity | 4 | One IN1_OUT1 `pool_withdraw` proof spends one pool UTXO into a pool change UTXO (back to `pool_authority`, with a maker-held private blinding and `booked_out = booked_in - amount`; the proof rejects a negative result) and a public `amount` unshielded to the authority's SPL token account. Rejects `amount = 0` and `amount > available_liquidity`; `available_liquidity -= amount`. | — | pair account | Pair authority signs |
| 5 | rebalance_liquidity | 5 | One `pool_rebalance` proof restructures the pool: it spends one to five pool UTXOs into one to four pool UTXOs (back to `pool_authority`, maker-held private blindings). The proof checks `sum(amount_out) = sum(amount_in)`, per output `booked <= amount`, and, for the public input `credit`, `sum(booked_out) = sum(booked_in) + credit`. The program applies `available_liquidity += credit`. `credit = 0` restructures with no public effect (merge, split, re-blind). The circuit is compiled once at the largest supported shape (IN5_OUT4); unused slots hold dummy notes. | — | pair account | Pair authority signs |
| 6 | create_escrow | 6 | Creates and prices an exact-input sell escrow. Instruction data carries `public_price_floor = F`; the program rejects unless `F <= pair.price <= F + 2 * price_tolerance` and the fixed reservation is available. The IN1_OUT2 proof privately enforces `order_amount >= min_order_amount`, `F <= min_price <= F + price_tolerance`, and `order_amount * (F + 2 * price_tolerance) <= max_order_size`; it does not bind the live price. The order data hash commits `Poseidon(recipient_owner_hash, min_price)`, and the encrypted handoff includes both values. | — | pair account, user escrow account (created) | Taker signs (fee payer) |
| 7 | settle | 7 | Resolves one escrow before expiry with IN2_OUT3. The circuit derives `fills = execution_price >= min_price`. On fill, the recipient gets `order_amount * execution_price` destination tokens and the maker gets the fixed source amount. On refund, the recipient gets the fixed source amount, the pool amount is unchanged, and the maker gets a real zero-amount source UTXO. Both outcomes return pool change, reduce `booked` by `max_order_size`, apply the same public state delta, and expose the same transaction shape. | — | pair account, user escrow account (closed) | Pair authority signs; the destinations are fixed by the proof |
| 8 | cancel | 8 | Refunds one escrow after expiry and closes it. One IN1_OUT1 `escrow_cancel` proof spends the order UTXO back to the confidential recipient committed in its data hash: the full `order_amount` in the source asset, with the refund blinding derived from the order blinding. Applies `available_liquidity += max_order_size` and `open_reservations -= 1`. `rent_recipient` must be the escrow's `owner`. | — | pair account, user escrow account (closed) | Permissionless: only a holder of the order UTXO data (the taker, or the maker via the handoff) can build the proof, and the destination is fixed by the proof |

## Liquidity Accounting

Per-note invariant: `0 <= booked <= amount`. Global invariant:
`sum(booked) >= available_liquidity + open_reservations * max_order_size`, which
together give `sum(pool UTXO amounts) >= available_liquidity + open_reservations *
max_order_size`.

| Instruction | available_liquidity | open_reservations | actual pool total |
|-------------|-----------------|-------------------|-------------------|
| deposit_liquidity | += amount | — | += amount |
| withdraw_liquidity | -= amount (reject if amount > bound) | — | -= amount |
| rebalance_liquidity | += credit | — | — |
| create_escrow | -= max_order_size (reject if bound < max_order_size) | += 1 | — |
| settle | — | -= 1 | -= owed on fill; unchanged on refund |
| cancel | += max_order_size | -= 1 | — |

The notes record the `booked` bookkeeping and the proofs maintain it: a
deposit starts with `booked = amount`, a withdrawal consumes booked value, a
settle moves up to `max_order_size` out of booked (clamped at zero) while only
`owed` leaves the note, and a rebalance raises booked by the declared public
`credit`, capped by the spent notes' surplus (`sum(amount) - sum(booked)`).
The credit is bounded by surplus that is provably present and not yet counted,
so no value is counted twice; the other transitions only lower booked or match
a public delta, so the bound stays a lower bound on the pool total. Settle does
not change the bound, so the public record of the maker's liquidity is
deposits, withdrawals, and the credits the maker publishes.

## State Machine

```
                          +==================+
                          |   (no escrow)    |
                          +==================+
                                   |
                                   |  create_escrow (taker signs, pays rent)
                                   |  rejected unless public_floor <= price
                                   |    <= public_floor + 2 * tolerance
                                   |  rejected if available_liquidity < max_order_size
                                   |  available_liquidity -= max_order_size
                                   |  open_reservations += 1
                                   |  order UTXO locked under escrow_authority
                                   v
                          +==================+
                          |       Open       |
                          +==================+
                             |            |
    slot <= expiry           |            |           slot > expiry
                             |            |
    settle                   |            |           cancel
    (pair authority signs;   |            |           (holder of order UTXO
     pool-funded from the    |            |            data: the taker, or
     pool_authority UTXOs)   |            |            the maker via handoff)
                             v            v
                +==================+    +==================+
                |     Resolved     |    |    Cancelled     |
                +==================+    +==================+
                | fill: recipient  |    | recipient: full  |
                |  gets owed, maker|    |  order_amount    |
                |  gets source     |    |  (source asset)  |
                | refund: recipient|    | bound += max     |
                |  gets source,    |    | reservations -= 1|
                |  pool unchanged  |    | escrow closed,   |
                | reservations -= 1|    |  rent -> owner   |
                | escrow closed,   |    +==================+
                |  rent -> owner   |
                +==================+
```

`expiry = created_at + pair.expiry_slots`; `owed = order_amount * execution_price`;
`max = pair.max_order_size`. Settled and Cancelled are terminal: both close the
escrow account and nullify the order UTXO, so exactly one of the two branches
can execute.

## Future Work

1. allow more taker input utxos in create_escrow
2. batch settlement by the maker (one proof spending the pool UTXO and N order UTXOs)
3. withdrawal of multiple UTXOs
