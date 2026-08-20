# Dynamic Swap

- Price updates are cheap: `update_price` touches only the pair account, and `create_escrow` prices the order at creation by reading that price.
- Unidirectional trading pairs (e.g. SOL -> USDC), each with its own authority (the maker) who sets the price.
- Committed liquidity: the pool is every UTXO owned by the pair's `pool_authority` PDA (destination asset). Each pool note's confidential data contains `booked`: the portion of its amount that the public accounting already counts. The pair account tracks a public `available_liquidity` and `open_reservations`. Invariants: per note `0 <= booked <= amount`, and globally `sum(booked) >= available_liquidity + open_reservations * max_order_size`. Each open escrow holds a `max_order_size` reservation, covered by funds the maker cannot withdraw.
- Order amounts are confidential, so the accounting is conservative: `create_escrow` reserves the worst case (`max_order_size`), and settle publicly changes nothing except closing the reservation. The unspent part of the reservation (`max_order_size - owed`) stays inside the pool change note as surplus (`amount - booked`).
- Rebalancing is the only place surplus becomes public liquidity again: `rebalance_liquidity` restructures pool notes (many in, many out) and lets the maker declare a public `credit`, adding exactly that much of the spent notes' surplus to `available_liquidity`. Timing and granularity are maker-chosen; a zero credit restructures the pool (merge, split, re-blind) with no public effect.
- `max_order_size` is immutable per pair: cancel must release exactly what create_escrow reserved. It is denominated in the destination asset and caps `owed = order_amount * execution_price` in the `escrow_open` circuit.
- Only the maker fills: settle requires the pair authority's signature. The taker's paths are settle-by-maker before expiry or unilateral cancel after; the taker's worst case is funds reserved for `expiry_slots`, then cancel.
- Deposit notes are public (amount, owner, blinding, and `booked = amount` are instruction data; the program computes the commitment itself, no proof). Pool confidentiality comes from settle, withdraw, and rebalance output notes with maker-held private blindings and confidential `booked` values. The only encrypted handoff is the order UTXO data at `create_escrow`.
- `execution_price` is public (stored in the escrow account). `max_price` is checked once at creation against the pair price and then discarded; it rejects an `update_price` that lands between the taker building the transaction and the escrow's creation. An escrow can only exist at an acceptable price, so the outcomes are settle (before expiry) and cancel (after).
- The payout destination stays confidential: the proof checks that the recipient owner-hash equals the taker's source UTXO owner, and its only appearance is inside the order UTXO's data hash.
- The `escrow_authority` and `pool_authority` nullifier secrets are hardcoded to 0: escrow- and pool-note spend linkage is already public (`escrow_utxo_hash` lives in the escrow account, deposit notes are public), and spends are gated by the proofs, the signer checks, and the liquidity accounting.

## Instructions

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | create_pair | 1 | Creates a unidirectional trading pair. The pair account holds `price`, the authority (the maker), the source/destination asset commitments, `expiry_slots` (the maker's settle window, and the taker's worst-case wait for a cancel), the maker's encryption key for order UTXO data handoffs, the maker's receipt owner-hash (the settle receipt destination), and `max_order_size` (immutable, destination asset). `available_liquidity` and `open_reservations` start at 0. A zero price or zero `max_order_size` is rejected. | — | pair account (created) | Pair authority signs (fee payer) |
| 2 | update_price | 2 | Updates `price` on the pair account. A zero price is rejected. | — | pair account | Pair authority signs |
| 3 | deposit_liquidity | 3 | Shields a public `amount` of the destination asset from the depositor's SPL token account into a new pool UTXO owned by the pair's `pool_authority` PDA, with `booked = amount` in its note data. Amount, owner, blinding, and booked are public instruction data, so the program computes the UTXO commitment itself; no proof. `available_liquidity += amount`. A zero amount is rejected. | — | pair account | Permissionless: the depositor signs its own SPL transfer (fee payer) |
| 4 | withdraw_liquidity | 4 | One IN1_OUT1 `pool_withdraw` proof spends one pool UTXO into a pool change UTXO (back to `pool_authority`, with a maker-held private blinding and `booked_out = booked_in - amount`; the proof rejects a negative result) and a public `amount` unshielded to the authority's SPL token account. Rejects `amount > available_liquidity`; `available_liquidity -= amount`. `amount = 0` is allowed: it re-blinds a public deposit note into a confidential one. | — | pair account | Pair authority signs |
| 5 | rebalance_liquidity | 5 | One `pool_rebalance` proof restructures the pool: it spends one to five pool UTXOs into one to four pool UTXOs (back to `pool_authority`, maker-held private blindings). The proof checks `sum(amount_out) = sum(amount_in)`, per output `booked <= amount`, and, for the public input `credit`, `sum(booked_out) = sum(booked_in) + credit`. The program applies `available_liquidity += credit`. `credit = 0` restructures with no public effect (merge, split, re-blind). The circuit is compiled once at the largest supported shape (IN5_OUT4); unused slots hold dummy notes. | — | pair account | Pair authority signs |
| 6 | create_escrow | 6 | Creates a user escrow account for a swap order and prices it at creation. One IN1_OUT2 `escrow_open` proof spends the taker's source UTXO (its asset must equal the pair's source asset) into the order UTXO and the taker's change, and enforces `order_amount * execution_price <= max_order_size`. The instruction rejects `execution_price > max_price` (`max_price` is instruction data) and `available_liquidity < max_order_size`, then applies `available_liquidity -= max_order_size` and `open_reservations += 1`. Stores the order UTXO hash (the PDA seed, so a taker can hold concurrent orders), `owner` (the taker, who pays rent), `created_at` (the current slot), and `execution_price` (the pair `price`; a zero price is rejected). The order UTXO is owned by the pair's `escrow_authority` PDA, and the proof checks that its data hash commits the recipient owner-hash, equal to the source UTXO's owner. The order UTXO data (`order_amount`, blinding, recipient owner-hash) is encrypted with the pair's maker encryption key, so the maker can settle on its own. | — | pair account, user escrow account (created) | Taker signs (fee payer) |
| 7 | settle | 7 | Fills one escrow before expiry and closes it. One IN2_OUT3 `pool_settle` proof spends the order UTXO and one pool UTXO (owned by `pool_authority`, destination asset), producing the recipient payout (`order_amount * execution_price` of the destination asset, to the confidential recipient), the pool change (back to `pool_authority`; the proof sets `booked_out = max(booked_in - max_order_size, 0)`), and the maker receipt (`order_amount` of the source asset, to the pair's receipt owner-hash). The recipient blinding derives from the order blinding (the taker precomputes its payout note at creation); pool change and receipt blindings are maker-chosen private witnesses. The program applies `open_reservations -= 1` and leaves `available_liquidity` unchanged; the unspent reservation stays in the change note as surplus. `rent_recipient` must be the escrow's `owner`. | — | pair account, user escrow account (closed) | Pair authority signs; the destinations are fixed by the proof |
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
| settle | — | -= 1 | -= owed |
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
                                   |  rejected if execution_price > max_price
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
                |     Settled      |    |    Cancelled     |
                +==================+    +==================+
                | recipient: owed  |    | recipient: full  |
                |  (dest asset)    |    |  order_amount    |
                | pool: -owed,     |    |  (source asset)  |
                |  change re-locked|    | bound += max     |
                | maker: source    |    | reservations -= 1|
                |  receipt         |    | escrow closed,   |
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
