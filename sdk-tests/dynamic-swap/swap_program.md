# Dynamic Swap

- A taker opens an order without a maker signature or liquidity witness.
- Each unidirectional pair (e.g. SOL -> USDC) has a maker, public price, maximum
  order size, and private shielded liquidity pool.
- Maker liquidity is deposited up front into one program-controlled liquidity
  UTXO. The liquidity account stores its UTXO hash; the amount remains private. A
  maker-supplied proof sets the public number of fixed-capacity order slots.
- `create_escrow` is a taker-only transaction. It escrows the taker's private
  source funds, snapshots the price and slippage constraint, consumes one
  capacity slot, and logs an order note encrypted to the maker. The taker keeps
  the transaction viewing secret and can decrypt the same note.
- `settle` is deferred execution. The maker decrypts the order and spends the
  order UTXO together with the current private liquidity UTXO. It pays the
  taker's committed fresh recipient, credits the maker with the source asset,
  and creates the next private liquidity UTXO. When advertised capacity is below
  the configured refresh threshold, settlement also publishes the updated
  number of collateralized order slots.
- Orders resolve independently. Settlements are sequential because each one
  consumes the liquidity UTXO produced by the previous settlement.

## Requirements

1. The maker publishes the quote and does not participate in order opening.
2. The liquidity balance is private; conservative order capacity is public.
3. Order amount and slippage are private. Default-zone owner pubkeys are public.
4. Orders are fully collateralized, settle at their committed price, and can be
   refunded after expiry without maker participation.

## Flow

```text
Maker: deposit private liquidity + publish price/capacity
                              |
                              v
Taker: create_escrow -> lock funds + price + slippage + capacity slot
                              |
                              v  encrypted order note
                    Maker decrypts order
                              |
                              v
Maker: settle -> taker payout + maker proceeds + next private liquidity UTXO
                 + refresh capacity when below threshold

After 10 minutes -> permissionless refund + liability release
```

## Instructions

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | create_pair | 1 | Creates the quote account and a separate liquidity account initialized to a program-owned bootstrap UTXO with zero advertised slots. Stores the maximum order size, refresh threshold, quote version, and maker viewing pubkey. | — | pair and liquidity accounts (created) | Pair authority signs |
| 2 | update_price | 2 | Updates the price and quote version. Because existing slots were denominated at the old price, it sets advertised slots to zero until the next proved capacity refresh. | — | pair and liquidity accounts | Pair authority signs |
| 3 | deposit_liquidity | 3 | Adds destination-asset funds to the private liquidity UTXO and stores its new hash. The initial deposit publishes capacity; later deposits may leave advertised capacity unchanged. | pair and liquidity accounts | liquidity account, SPP trees (CPI) | Pair authority signs |
| 4 | withdraw_liquidity | 4 | Creates a smaller liquidity UTXO and a maker withdrawal. The proof checks outstanding reserved liability and advertised capacity against the new private amount. | pair and liquidity accounts | liquidity account, SPP trees (CPI) | Pair authority signs |
| 5 | create_escrow | 5 | Spends the taker's exact-sized source UTXO into a program-owned order UTXO, snapshots the quote, checks the private limit and maximum order size, reserves one slot, sets expiry to 600 seconds after creation, and includes an order note encrypted to the maker. | pair and liquidity accounts | liquidity account, order account (created), SPP trees (CPI) | Taker signs |
| 6 | refund_expired | 6 | After the 600-second settlement window, returns the escrowed source funds to the committed recipient and removes its aggregate liability. It does not touch the private liquidity UTXO. | pair, liquidity, and order accounts | liquidity account, order account (closed), SPP trees (CPI) | Permissionless submission; proof fixes the recipient |
| 7 | settle | 8 | Spends the order and current liquidity UTXOs, pays the committed recipient, credits the maker, stores the next liquidity hash, conditionally refreshes advertised capacity, removes the liability, and closes the order. | pair, liquidity, and order accounts | liquidity account, order account (closed), SPP trees (CPI) | Permissionless submission; maker or settlement service holds the witnesses |

The order account omits the taker pubkey. Its PDA is derived from the pair and a
fresh random order commitment. The committed recipient is independent of the
funding owner. Use a fresh recipient for each order.

The order output uses the existing default-zone transaction encryption. The
taker encrypts it using the maker's viewing pubkey and the transaction viewing
key. The maker decrypts with its viewing secret. The taker retains
`tx_viewing_sk` and uses it to decrypt the same ciphertext for settlement
tracking or refund.
The ciphertext contains the private order terms and the order UTXO data needed
by both paths.

The lifecycle test decrypts the logged ciphertext through both paths. It uses
the maker viewing key with `decrypt_utxo` and the taker's transaction viewing
key with `decrypt_slot_ephemeral`, then checks that both plaintexts equal the
order note constructed by `create_escrow`.

`create_escrow` sets `expires_at_unix_ts = created_at_unix_ts + 600`. The
program tolerance-checks the client-supplied creation time against
`Clock::unix_timestamp`. Settlement is allowed while
`Clock::unix_timestamp <= expires_at_unix_ts`; refund is allowed afterward.

The order proof privately checks:

- `0 < order_amount <= max_order_size`;
- the pair's current price and quote version were used;
- the current price satisfies the taker's slippage or limit price;
- the source input uses the pair's source asset;
- the order output is owned by the pair's order-authority PDA;
- the order UTXO commits to the amount, recipient, price, quote version, and
  `created_at_unix_ts + 600`; and
- the SPP `private_tx_hash` includes the order output and encrypted-note hash.

The settlement proof checks:

- the order input hash equals the hash stored in the order account;
- the liquidity input hash equals the current hash stored in the pair;
- `payout = order_amount * execution_price`, with the pair's fixed-point and
  rounding rules;
- the payout uses the destination asset and the committed recipient;
- the maker receives the source asset;
- the liquidity output uses the destination asset and contains the input
  liquidity minus the payout;
- a capacity refresh, when required, matches the private liquidity output after
  covering the remaining reserved liability; and
- the SPP `private_tx_hash` includes the order and liquidity input hashes and
  the settlement output hashes.

Capacity slots conservatively reserve the worst-case payout for one maximum-size
order. A successful `create_escrow` moves one slot from available to reserved.
Public state stores the aggregate reserved liability `R` and available-slot
count; the liquidity balance remains private. The pair stores
`capacity_refresh_threshold` in destination-token base units.

Settlement removes its aggregate liability. It normally leaves the available-slot
count unchanged because the slot was already removed by `create_escrow`. A
refresh is required when:

```text
available_slots * slot_value < capacity_refresh_threshold
```

The refreshing settlement includes private top-ups and unused capacity in the
new slot count. For slot value `S`, remaining reserved liability `R`, private
liquidity output `L`, and refreshed available slots `X`, the proof checks:

```text
R + X*S <= L < R + (X+1)*S
```

The upper bound makes `X` exact. Refund removes its reserved liability; the
released capacity remains unadvertised until the next refresh. The public slot
count reveals a one-slot range only when capacity is initialized or refreshed;
the balance and later top-ups stay private between refreshes.

For example, with maximum order size `1`, price `1`, `S = 1`, `L = 1,000`, and
`capacity_refresh_threshold = 100`, capacity is refreshed by the first
settlement for which advertised available liquidity is below `100`. The refresh
publishes the slots supported by the latest private liquidity UTXO.

The default-zone SPP input signer and output owner tags are public. The order
lifecycle links the funding owner to a fresh recipient. Amounts, slippage, order
UTXO data, and the private liquidity balance remain hidden.

## Future Work

1. Allow more input UTXOs and a taker change UTXO in `create_escrow`.
2. Update capacity once per settlement batch while keeping the shared liquidity
   balance private.
3. Encrypt order notes for a backup settlement service so settlement does not
   depend on the maker.
4. Use aggregate quote accounts when maker identity must remain hidden until
   trade commitment.
