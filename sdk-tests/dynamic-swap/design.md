# Dynamic Swap

Users swap tokens between private balances through a market maker with committed liquidity. The program reserves the payout funds when an order opens and checks the swap terms with zero-knowledge proofs.

Flow:

1. Users swap one token for another between private balances at a market maker's quoted price, with a private minimum acceptable price.
2. The market maker deposits payout tokens into a pool. When a user opens an order, the program locks their input tokens and reserves enough pool liquidity to cover the swap.
3. The market maker settles at the price recorded when the order opened. If that price meets the user's minimum, both parties receive their tokens. Otherwise, the user receives a full refund.
4. If the market maker does not settle before expiry, the user can recover their tokens without its approval.
5. The market maker replenishes and reorganizes liquidity on its own schedule. Individual swap amounts stay private. Pool deposits, withdrawals, and published liquidity credits are public.

The market maker supports a set of directional swap pairs. Each pair has two tokens:

1. Source: the token the user sells, for example USDC.
2. Destination: the token the user receives, for example kVault shares.

Swapping in reverse uses a separate pair with the tokens reversed. The market maker sets each pair's price; this program does not read a vault exchange rate or perform vault deposits and withdrawals.

Opening an order and settling it are separate Solana transactions. Settlement exchanges the locked input tokens and the pool's payout tokens atomically: both transfers land or neither does.

## Actors

| Actor | Role | Trust |
|-------|------|-------|
| User | Holds private source tokens, chooses an amount and minimum price, opens an order, cancels after expiry if needed | Relies on the market maker for timely settlement; the proofs enforce payout or refund terms |
| Market maker | Sets prices, commits destination-token liquidity, settles orders, manages pool inventory | Sees the order amount and private minimum through the encrypted order handoff; cannot withdraw liquidity reserved for open orders |
| Dynamic swap program | Reserves liquidity, records the execution price and expiry, verifies swap proofs, authorizes pool and escrow spends | Enforces the pair's policy and each order's lifecycle |
| Shielded pool program | Verifies private transfers, checks ownership and value conservation, records created and spent notes | Provides the private balance protocol |

## Swap

1. Market maker: publish a price. The maker updates the pair's public price. The pair also fixes a price tolerance, minimum order amount, maximum payout per order, and settlement window.

2. User: prepare an order. The user chooses the source-token amount and a private minimum price. The order includes a public price floor that defines an accepted price window using the pair's tolerance. The private minimum must lie within the permitted range.

3. User: open the order. The user proves that the order meets the pair's minimum amount and that its largest possible payout within the accepted window fits the maximum payout. The transaction locks the source tokens, returns the user's change, and encrypts the order opening to the maker. The program records the live pair price as the execution price and reserves the pair's maximum payout. Later price updates do not change this order's execution price.

4. Market maker: recover the order. The maker decrypts the order opening and selects a pool note large enough to fund the payout. It constructs a proof for the committed order terms and the recorded execution price.

5. Market maker: settle before expiry. If the execution price meets the private minimum, the user receives destination tokens and the maker receives the locked source tokens. Otherwise, the user receives all the source tokens back. The same transaction returns any pool change, releases the reservation, closes the order, and returns its account rent to the user.

6. User: cancel after expiry if settlement did not happen. The user proves a full source-token refund to the order's committed recipient. Cancellation releases the reservation and closes the order without requiring the maker's signature. A holder of the order opening can also submit this proof, but cannot change the refund destination.

The user can derive the settlement payout or cancellation refund note from the order opening and the published order nullifier. Recovery does not depend on the maker supplying a payout ciphertext.

### Privacy

| Field | Visible to | Reason |
|-------|------------|--------|
| User and market maker Solana addresses | Public | They sign the order-opening and settlement transactions |
| Pair and swap direction | Public | Instructions reference the directional pair account |
| Quoted and execution prices | Public | The pair stores the live price and the order records its execution price |
| Public price floor, tolerance, and order policy | Public | The program checks the price window and reserves the configured maximum payout |
| Order amount and exact minimum price | User and market maker | The user creates the order; its opening is encrypted to the maker |
| User's other notes and remaining balance | User | The maker receives the order opening, not the user's source-note preimage or change-note opening |
| Fill or price-based refund | Hidden by the proof and transaction shape | Both settlement outcomes use the same input and output layout and public accounting delta |
| Pool deposits and withdrawals | Public | These move public SPL amounts into or out of the pool |
| Published liquidity credits | Public | The maker declares how much confidential surplus becomes available for new reservations |
| Escrow and pool spend linkage | Public | Their nullifier keys are public; proofs and program signatures authorize spends |

The market maker learns individual order terms. Published policy bounds constrain possible amounts and prices, and public liquidity operations can reveal aggregate information. Scheduling those operations separately from individual swaps reduces direct timing correlation.

## Market Maker

1. Setup prepares each directional pair and its settlement policy.
2. Inventory management keeps destination-token liquidity available and splits it across notes for concurrent settlements.
3. Rebalancing restructures notes and publishes accumulated surplus when the maker chooses.

### Setup

1. Create the pair with its source and destination tokens, initial price, price tolerance, minimum order amount, maximum payout, and settlement window.
2. Configure the maker's private receipt destination and publish its escrow viewing key for encrypted order handoffs.
3. Deposit destination tokens into the pair's pool. Each deposit creates a pool note and increases available liquidity by the deposited amount.

### Inventory

1. Reservations: every open order reserves the configured maximum payout, even when its actual payout is smaller. The program rejects new orders when available liquidity cannot cover another reservation.
2. Concurrency: one settlement spends one pool note. Splitting inventory into several notes lets the maker settle independent orders concurrently without spending the same note twice.
3. Note sizing: keep notes large enough to fund intended orders. Aggregate pool liquidity can cover an order while individual notes still need consolidation before settlement.
4. Recovery: retain the preimages of rebalance outputs, which are published without ciphertexts. Confidential pool outputs that carry encrypted payloads use the pool viewing key, separately from the escrow handoff key.

### Rebalance

1. Restructure notes. The maker can merge, split, or re-blind pool notes without moving tokens out of the pool. The proof conserves the token amount.
2. Publish surplus. Opening an order reserves the maximum payout, but settlement only spends the actual payout. Unused reserved value remains in the pool as surplus. A rebalance can publish a chosen portion of that surplus as available liquidity for new orders.
3. Replenish liquidity. The maker can deposit more destination tokens whenever it needs additional payout capacity.
4. Withdraw free liquidity. The maker can withdraw destination tokens to its own token account, up to the publicly available liquidity. Open-order reservations remain covered.

For every pool note, the counted value must not exceed its token amount. Across the pool, counted value covers available liquidity plus all open-order reservations. Deposits, withdrawals, rebalances, settlements, and cancellations preserve this guarantee.
