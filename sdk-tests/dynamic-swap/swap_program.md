# Dynamic Swap

- Price updates are cheap: `update_price` touches only the pair account, and `create_escrow` prices the order at creation by reading that price.
- Unidirectional trading pairs (e.g. SOL -> USDC), each with its own authority (the maker) who sets the price.
- The taker escrows alone and the maker settles later. No shared liquidity pool: the maker's liquidity sits in its own shielded UTXOs between fills and enters only at settle time.
- `execution_price` is public (stored in the escrow account). `max_price` is checked once at creation against the pair price and then discarded; it rejects an `update_price` that lands between the taker building the transaction and the escrow's creation. An escrow can only exist at an acceptable price, so the outcomes are settle (before expiry) and cancel (after).
- The payout destination stays confidential: the proof checks that the recipient owner-hash equals the taker's source UTXO owner, and its only appearance is inside the order UTXO's data hash.
- The escrow_authority nullifier secret is hardcoded to 0: escrow-note spend linkage is already public (`escrow_utxo_hash` lives in the escrow account), and a public key lets both the maker (settle) and the taker (cancel) build the order spend.

## Instructions

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | create_pair | 1 | Creates a unidirectional trading pair. The pair account holds `price`, the authority, the source/destination asset commitments, `expiry_slots` (the maker's settle window, and the taker's worst-case wait for a cancel), and the maker's encryption key for order UTXO data handoffs. A zero price is rejected. | — | pair account (created) | Pair authority signs (fee payer) |
| 2 | update_price | 2 | Updates `price` on the pair account. A zero price is rejected. | — | pair account | Pair authority signs |
| 3 | create_escrow | 5 | Creates a user escrow account for a swap order and prices it at creation. One IN1_OUT2 `escrow_open` proof spends the taker's source UTXO (its asset must equal the pair's source asset) into the order UTXO and the taker's change. The instruction rejects `execution_price > max_price` (`max_price` is instruction data). Stores the order UTXO hash (the PDA seed, so a taker can hold concurrent orders), `owner` (the taker, who pays rent), `created_at` (the current slot), and `execution_price` (the pair `price`; a zero price is rejected). The order UTXO is owned by the pair's `escrow_authority` PDA, and the proof checks that its data hash commits the recipient owner-hash, equal to the source UTXO's owner. The order UTXO data (`order_amount`, blinding, recipient owner-hash) is encrypted with the pair's maker encryption key, so the maker can settle on its own. | pair account | user escrow account (created) | Taker signs (fee payer) |
| 4 | settle | 8 | Fills one escrow before expiry and closes it. One IN2_OUT3 `escrow_settle` proof spends the order UTXO and the funder's funding UTXO (its asset must equal the pair's destination asset), producing the recipient payout (`order_amount * execution_price` of the destination asset, to the confidential recipient), the funder's change, and the funder's source-asset receipt (`order_amount`). Change and receipt go to the funding UTXO's owner, so whoever holds the order UTXO data and funds the payout fills the order: the maker in practice (it holds the encrypted order UTXO data), though the taker can self-fill to exit early. The proof fixes the output blindings: the recipient's derives from the order blinding (the taker precomputes its payout note at creation), the funder's from the funding blinding. `rent_recipient` must be the escrow's `owner`. | pair account, user escrow account | user escrow account (closed) | Permissionless: the funding UTXO's owner signs its own input, and the destinations are fixed by the proof |
| 5 | cancel | 6 | Refunds one escrow after expiry and closes it. One IN1_OUT1 `escrow_cancel` proof spends the order UTXO back to the confidential recipient committed in its data hash: the full `order_amount` in the source asset, with the refund blinding derived from the order blinding. `rent_recipient` must be the escrow's `owner`. | pair account, user escrow account | user escrow account (closed) | Permissionless: only a holder of the order UTXO data (the taker, or the maker via the handoff) can build the proof, and the destination is fixed by the proof |

## State Machine

```
                          +==================+
                          |   (no escrow)    |
                          +==================+
                                   |
                                   |  create_escrow (taker signs, pays rent)
                                   |  rejected if execution_price > max_price
                                   |  order UTXO locked under escrow_authority
                                   v
                          +==================+
                          |       Open       |
                          +==================+
                             |            |
    slot <= expiry           |            |           slot > expiry
                             |            |
    settle                   |            |           cancel
    (funding UTXO owner      |            |           (holder of order UTXO
     signs: the maker, or    |            |            data: the taker, or
     the taker self-fills)   |            |            the maker via handoff)
                             v            v
                +==================+    +==================+
                |     Settled      |    |    Cancelled     |
                +==================+    +==================+
                | recipient: owed  |    | recipient: full  |
                |  (dest asset)    |    |  order_amount    |
                | funder: change + |    |  (source asset)  |
                |  source receipt  |    | escrow closed,   |
                | escrow closed,   |    |  rent -> owner   |
                |  rent -> owner   |    +==================+
                +==================+
```

`expiry = created_at + pair.expiry_slots`; `owed = order_amount * execution_price`.
Settled and Cancelled are terminal: both close the escrow account and nullify the
order UTXO, so exactly one of the two branches can execute.

## Future Work

1. allow more taker input utxos in create_escrow
2. batch settlement by the maker
