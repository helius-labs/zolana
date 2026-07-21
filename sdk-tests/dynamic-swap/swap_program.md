# Dynamic Swap

- Price updates are cheap: `update_price` touches only the pair account, never a per-order proof, and `create_escrow` prices the order at creation by reading that price.
- Unidirectional trading pairs (e.g. SOL -> USDC), each with its own authority (the maker) who sets the price.
- No shared liquidity pool: the maker funds each escrow directly from its own shielded UTXO. Every order is a self-contained bilateral escrow -- the taker's source funds and the maker's worst-case destination funds, both locked at creation.
- An order's `max_price` is never stored or transmitted in the clear; it lives only inside the order UTXO's commitment. Every order is priced at creation, and a single `settle` instruction covers both outcomes (settle and price-refund) with an identical shape and verifying key, so an observer cannot tell whether an order executed or refunded. Each escrow resolves independently: no shared resource, no ordering between orders.

## Instructions

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | create_pair | 1 | Creates a unidirectional trading pair. The pair account holds `price`, the authority, and the source/destination asset commitments. A zero price is rejected. | — | pair account (created) | Pair authority signs (fee payer) |
| 2 | update_price | 2 | Updates `price` on the pair account. A zero price is rejected. | — | pair account | Pair authority signs |
| 3 | create_escrow | 5 | Creates a user escrow account for a swap order and prices it at creation. One IN2_OUT3 `escrow_open` proof spends the taker's source UTXO and the maker's funding UTXO (bound to the pair's destination asset), producing the order UTXO, the reservation UTXO (`order_amount * max_price` of the destination asset), and the maker's change. Stores the escrow UTXO hash (the PDA seed), the reservation hash, `owner`, `created_at`, and `execution_price` (the pair `price`; a zero price is rejected). `max_price` is a private witness committed in the order UTXO's data hash, not stored. The payout destination is not stored or caller-supplied either: it is the taker itself, bound in-circuit to the source UTXO's owner and committed into the order UTXO's data hash, so it stays confidential. The order and reservation UTXOs are owned by the pair's `escrow_authority` PDA, and the escrowed asset is bound to the pair's source asset. | pair account | user escrow account (created) | Both the maker (pair authority, funds and signs its own funding UTXO) and the owner (taker, signs its own source UTXO) sign |
| 4 | settle | 8 | Resolves one escrow and closes it -- settle or price-refund -- in a single permissionless instruction with an identical account list, IN2_OUT3 shape, and verifying key for both outcomes. If `execution_price <= max_price` (private) it settles: the taker receives `order_amount * execution_price` of the destination asset, the maker receives the escrowed source asset and the unspent reservation. Otherwise it refunds: the taker receives the full order amount back in the source asset, the maker receives the whole reservation. The payout destination (the taker) is not stored on-chain; it is the private in-circuit recipient bound to the order UTXO's data hash. The proof derives the outcome from the public `execution_price` and the private `max_price`, so the outcome is not observable. `rent_recipient` must be the escrow's `owner`. | pair account, user escrow account | user escrow account (closed) | Permissionless: only whoever holds the order/reservation witnesses can build a valid proof, and all destinations are fixed by the proof |

## Future Work

1. allow more input utxos to create escrow
2. allow change utxo for both maker and taker in create escrow
3. encrypt both escrow utxos to both maker and taker so that each can execute the settlement tx
4. allow batch settlement by the taker
